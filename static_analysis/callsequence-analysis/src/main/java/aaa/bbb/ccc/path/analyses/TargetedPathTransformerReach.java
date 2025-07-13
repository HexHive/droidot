package aaa.bbb.ccc.path.analyses;

import com.google.common.base.Joiner;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import aaa.bbb.ccc.android.model.*;
import aaa.bbb.ccc.path.analyses.getnatives.SrcToSinksReach;
import aaa.bbb.ccc.path.analyses.getnatives.nativeFuncInfo;
import org.javatuples.Pair;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.options.Options;
import soot.tagkit.BytecodeOffsetTag;
import soot.tagkit.Tag;
import soot.toolkits.graph.BriefBlockGraph;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;
import soot.util.Chain;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

public class TargetedPathTransformerReach {

	protected static String DROZER_TARGETED_INTENT_CMDS = "drozer_targeted_intent_cmds_";
	private static String ADB_TARGETED_INTENT_CMDS = "adb_targeted_intent_cmds_";

	static Logger logger = LoggerFactory.getLogger(TargetedPathTransformerReach.class);
	private final String Z3_RUNTIME_SPECS_DIR = "z3_runtime_specs";
	private Set<SootClass> dynRegReceivers;

	/**
	 * to track intents that are passed to native function call
	 */
	//Set<intentToNative> intents2native = new LinkedHashSet<intentToNative>();

	/**
	 * sinks for unitNeedsAnalysis
	 */
	Set<String> sinksMethodSignatures = new LinkedHashSet<String>();
	Set<String> sourcesMethodSignatures = new LinkedHashSet<String>();

	/**
	 * object that performs application-independent path operations
	 */
	//private DefaultPathAnalysis pathAnalyses = new DefaultPathAnalysis();
	static final Object ctxLock = new Object();

	/**
	 * key: the z3 expression for a Unit, value: the corresponding Unit
	 */
	private Map<String, Unit> exprUnitMap = new ConcurrentHashMap<String, Unit>();

	/**
	 * key: a symbol used to represent a Local, value: the Local represented by the symbol
	 */
	private Map<String, Local> symbolLocalMap = new ConcurrentHashMap<String, Local>();

	/**
	 * key: a Local that is treated symbolically, value: the symbol used to represent the Local
	 */
	private Map<Local, String> localSymbolMap = new ConcurrentHashMap<Local, String>();

	/**
	 * key: a Value corresponding to an Intent extra, value: the string representing the key of the extra data
	 */
	private Map<Value, String> valueKeyMap = new ConcurrentHashMap<Value, String>();

	/**
	 * key: a symbol representing a string constant, value: the actual string constant value for the symbol
	 */
	private Map<String, StringConstant> stringConstantMap = new ConcurrentHashMap<String, StringConstant>();

	/**
	 * symbols that represent Intent actions
	 */
	private Set<String> actionSymbols = new LinkedHashSet<String>();

	/**
	 * key: action symbol, value: string constant symbols
	 */
	private Map<String, Set<String>> actionStrings = new ConcurrentHashMap<String, Set<String>>();

	protected JimpleBasedInterproceduralCFG icfg;

	private AndroidProcessor androidProcessor = new AndroidProcessor();

	BufferedWriter activityCmdsDrozerFileWriter = null;
	BufferedWriter serviceCmdsDrozerFileWriter = null;
	BufferedWriter receiverCmdsDrozerFileWriter = null;

	/**
	 * key: type of component, value: the generated commands for the type of component matching the key
	 */
	Map<String, String> generatedCmdsMap = new ConcurrentHashMap<String, String>();

	private ExecutorService executor;

	Set<Pair<String, Set<Triplet<String, String, Type>>>> writableGenData = new LinkedHashSet<Pair<String, Set<Triplet<String, String, Type>>>>();

	Set<Intent> prevWrittenIntents = new LinkedHashSet<Intent>();

	Set<Pair<Unit, SootMethod>> unitsWithGenData = new LinkedHashSet<Pair<Unit, SootMethod>>();
	Set<Pair<Unit, SootMethod>> unitsWithoutGenData = new LinkedHashSet<Pair<Unit, SootMethod>>();
	Set<Pair<Unit, SootMethod>> targetedUnits = new LinkedHashSet<Pair<Unit, SootMethod>>();
	Set<Pair<Unit, SootMethod>> infeasibleTargets = new LinkedHashSet<Pair<Unit, SootMethod>>();
	Set<Pair<Unit, SootMethod>> possiblyFeasibleNoGenTargets = new LinkedHashSet<Pair<Unit, SootMethod>>();

	// Map<Unit,List<UnitPath>>: given an unit, return all paths in method that can lead to that unit
	Map<SootMethod, Map<Unit, List<UnitPathSink>>> methodSummaries = new ConcurrentHashMap<SootMethod, Map<Unit, List<UnitPathSink>>>();
	Map<SootMethod, Map<Unit, List<UnitPathSink>>> srcMethodSummaries = new ConcurrentHashMap<SootMethod, Map<Unit, List<UnitPathSink>>>();
	Map<SootMethod, List<Unit>> methodFinalPaths = new ConcurrentHashMap<SootMethod, List<Unit>>();

	// track source-sink pairs
	Set<Pair<List<String>,List<String>>> srcSinkPairs = new LinkedHashSet<Pair<List<String>,List<String>>>();

	public Map<List<Unit>, Intent> getPathIntents() {
		return pathIntents;
	}

	Map<List<Unit>, Intent> pathIntents = new ConcurrentHashMap<List<Unit>, Intent>();

	public class UnitPathSink {
		List<String> pathSink;  // list of JNI call units
		List<Unit> path;
		String sinkSignature;

		public UnitPathSink(List<String> currPathSink, List<Unit> currPath, String sinkSignature) {
			this.pathSink = currPathSink;
			this.path = currPath;
			this.sinkSignature = sinkSignature;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			UnitPathSink unitPath = (UnitPathSink) o;

			if (!path.equals(unitPath.path)) return false;
			if (!sinkSignature.equals(unitPath.sinkSignature)) return false;
			return pathSink.equals(unitPath.pathSink);
		}

		@Override
		public int hashCode() {
			int result = pathSink.hashCode();
			result = 31 * result + path.hashCode();
			result = 31 * result + sinkSignature.hashCode();
			return result;
		}

		public List<String> getPathSink() {
			return pathSink;
		}

		public List<Unit> getPath() {
			return path;
		}

	}

	protected int pathsAnalyzedCount = 0;

	public int getPathsAnalyzedCount() {
		return pathsAnalyzedCount;
	}

	public boolean parallelEnabled = false;
	public boolean pathLimitEnabled = true;

	public int timeout = 180;
	public int basicBlockSize = Integer.MAX_VALUE;

	public int finalPathsLimit = 100;

	public long mainAnalysisRuntime = -1;

	public String apkFilePath;

	public TargetedPathTransformerReach(String apkFilePath) {
		HashMap<String, String> config = new HashMap<String, String>();
		config.put("model", "true"); // turn on model generation for z3
		pathsAnalyzedCount = 0;
		this.apkFilePath = apkFilePath;
	}

	public static boolean isApplicationMethod(SootMethod method) {
		/*
		if (method.getName().startsWith("<init>")) {
            // constructor
            return false;
        }
        if (method.getName().startsWith("<clinit>")) {
            // static initializer
            return false;
        }
		 */
		Chain<SootClass> applicationClasses = Scene.v().getApplicationClasses();
		for (SootClass appClass : applicationClasses) {
			if (appClass.getMethods().contains(method)) {
				return true;
			}
		}
		return false;
	}

	protected Set<SrcToSinksReach> main(SootMethod method) {
		Set<SrcToSinksReach> srcSinkSummaries = new LinkedHashSet<SrcToSinksReach>();

		final BriefBlockGraph bug = new BriefBlockGraph(method.retrieveActiveBody());
		if (bug.getBlocks().size() > basicBlockSize) {
			logger.debug("method " + method.getName() + " has block size that is too big: " + String.valueOf(bug.getBlocks().size()));
			return srcSinkSummaries;
		}

		int currMethodCount = 1;

		executor = null;
		if (parallelEnabled)
			executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
		else
			executor = Executors.newSingleThreadExecutor();

		// by default (unfortunately) the ThreadPoolExecutor will throw an
		// exception
		// when you submit the job that fills the queue, to have it block you
		// do:
		if (executor instanceof ThreadPoolExecutor) {
			((ThreadPoolExecutor) executor).setRejectedExecutionHandler(new RejectedExecutionHandler() {
				public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
					// this will block if the queue is full as opposed to
					// throwing
					try {
						executor.getQueue().put(r);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			});
		}

		long mainAnalysisStartTime = System.currentTimeMillis();
		// fill out methodSummaries
		if (isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
			if (method.hasActiveBody()) {
				doPathAnalysis(method, true, true);
			} else {
				logger.debug("method " + method + " has no active body, so it won't be analyzed.");
			}
		}
		logger.debug("Finished path analysis on method: " + method);
		logger.debug("Number of methods analyzed: " + currMethodCount);

		// identify source-to-sink connection
		if (isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
			if (method.hasActiveBody()) {
				doPathAnalysis(method, false, true);
			} else {
				logger.debug("method " + method + " has no active body, so it won't be analyzed.");
			}
		}

		// paused executor since we need executor to finish for each method after doPathAnalysis
		System.out.println("Finishing executor...");
		executor.shutdown();
		System.out.println("Executor shutdown...");
		try {
			executor.awaitTermination(timeout, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			// Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Executor terminated...");
		long mainAnalysisEndTime = System.currentTimeMillis();
		mainAnalysisRuntime = mainAnalysisEndTime - mainAnalysisStartTime;

		for (Pair<List<String>,List<String>> p : srcSinkPairs) {
			srcSinkSummaries.add(new SrcToSinksReach(p.getValue0(),p.getValue1()));
		}
		return srcSinkSummaries;
	}

	protected Set<SrcToSinksReach> main(List<SootMethod> rtoMethods, boolean isODCG) {

		try {
			final String baseDrozerIntentCmdsPath = "data" + File.separator + DROZER_TARGETED_INTENT_CMDS + androidProcessor.mainPackageName;

			activityCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_activities.sh");
			serviceCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_services.sh");
			receiverCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_receivers.sh");

			int currMethodCount = 1;
			logger.debug("total number of possible methods to analyze: " + rtoMethods.size());

			executor = null;
			if (parallelEnabled)
				executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
			else
				executor = Executors.newSingleThreadExecutor();

			// by default (unfortunately) the ThreadPoolExecutor will throw an
			// exception
			// when you submit the job that fills the queue, to have it block you
			// do:
			if (executor instanceof ThreadPoolExecutor) {
				((ThreadPoolExecutor) executor).setRejectedExecutionHandler(new RejectedExecutionHandler() {
					public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
						// this will block if the queue is full as opposed to
						// throwing
						try {
							executor.getQueue().put(r);
						} catch (InterruptedException e) {
							e.printStackTrace();
						}
					}
				});
			}

			long mainAnalysisStartTime = System.currentTimeMillis();
			//CallGraph cg = Scene.v().getCallGraph();
			//icfg = new JimpleBasedInterproceduralCFG();
			//SootClass clsk = Scene.v().getSootClass("e.c.d.d0");
            //SootMethod ka = clsk.getMethod("void E(java.io.InputStream)");
			//SootClass parCls = Scene.v().getSootClass("com.ubikey.stock.UbikeyLibrary");
            //SootMethod parMtd = parCls.getMethod("boolean ubikeyConnect(android.content.Context)");
			// fill out methodSummaries
			for (SootMethod method : rtoMethods) {
				if (isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
					logger.debug("METHOD: " + method.getSignature());
					//if (method.hasActiveBody()) {
					Collection<Future<?>> futures = new LinkedList<Future<?>>();
					doPathAnalysis(method, true, false, futures);
					for (Future<?> future:futures) {
						future.get();
					}
					//} else {
					//	logger.debug("method " + method + " has no active body, so it won't be analyzed.");
					//}
				}
				logger.debug("Finished path analysis on method: " + method);
				logger.debug("Number of methods analyzed: " + currMethodCount);
				currMethodCount++;
			}

			// identify source-to-sink connection
			for (SootMethod method : rtoMethods) {
				if (isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
					//if (method.hasActiveBody()) {
						//System.out.println("doPathAnalysis");
					doPathAnalysis(method, false, false);
					//} else {
					//	logger.debug("method " + method + " has no active body, so it won't be analyzed.");
					//}
				}
			}

			// paused executor since we need executor to finish for each method after doPathAnalysis
			System.out.println("Finishing executor...");
			executor.shutdown();
			System.out.println("Executor shutdown...");
			try {
				executor.awaitTermination(timeout, TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				// Auto-generated catch block
				e.printStackTrace();
			}
			System.out.println("Executor terminated...");
			long mainAnalysisEndTime = System.currentTimeMillis();
			mainAnalysisRuntime = mainAnalysisEndTime - mainAnalysisStartTime;

			// Done writing so close them
			flushIntentCmdsWriters(activityCmdsDrozerFileWriter, serviceCmdsDrozerFileWriter, receiverCmdsDrozerFileWriter);
			//flushIntentCmdsWriters(activityCmdsAdbFileWriter,serviceCmdsAdbFileWriter,receiverCmdsAdbFileWriter);

			int numOtherNonGeneratedTargets = unitsWithoutGenData.size() - infeasibleTargets.size();
			logger.debug("Number of units with generated data: " + unitsWithGenData.size());
			logger.debug("Number of units without generated data: " + unitsWithoutGenData.size());
			logger.debug("Number of infeasible targets: " + infeasibleTargets.size());
			logger.debug("Number of other non-generated targets: " + numOtherNonGeneratedTargets);
			logger.debug("Total number of targeted units: " + targetedUnits.size());

			if (numOtherNonGeneratedTargets != possiblyFeasibleNoGenTargets.size()) {
				throw new RuntimeException("numOtherNonGeneratedTargets != otherNoGenTargets.size()");
			}

			logger.debug("Targets with generated data: ");
			printUnitMethods(unitsWithGenData);

			logger.debug("Targets withOUT generated data: ");
			printUnitMethods(unitsWithoutGenData);

		} catch (IOException e) {
			e.printStackTrace();
		} catch (ExecutionException e) {
			throw new RuntimeException(e);
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}

		Set<SrcToSinksReach> srcSinkSummaries = new LinkedHashSet<SrcToSinksReach>();
		for (Pair<List<String>,List<String>> p : srcSinkPairs) {
			srcSinkSummaries.add(new SrcToSinksReach(p.getValue0(),p.getValue1()));
		}
		// write methodSummaries as JSON to disk
		if (!isODCG) {
			Path p = Paths.get(apkFilePath);
			String apkName = p.getFileName().toString();
			apkName = apkName.substring(0, apkName.lastIndexOf('.')) + ".json";
			try {
				Writer writer = new FileWriter("nativesAnalysis" + File.separator + "R_" + apkName);
				Gson gson = new GsonBuilder().disableHtmlEscaping().create();
				String json = gson.toJson(srcSinkSummaries);
				writer.write(json);
				writer.flush();
				writer.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
		return srcSinkSummaries;
	}

	public void printUnitMethods(Set<Pair<Unit, SootMethod>> unitMethods) {
		for (Pair<Unit, SootMethod> unitMethod : unitMethods) {
			Unit unit = unitMethod.getValue0();
			SootMethod method = unitMethod.getValue1();
			logger.debug(unit + " of method " + method);
		}
	}

	public void flushIntentCmdsWriters(BufferedWriter activityWriter, BufferedWriter serviceWriter, BufferedWriter receiverWriter) throws IOException {
		synchronized (activityWriter) {
			activityWriter.flush();
		}
		synchronized (serviceWriter) {
			serviceWriter.flush();
		}
		synchronized (receiverWriter) {
			receiverWriter.flush();
		}
	}

	public static BufferedWriter setupIntentCmdsWriter(final String baseIntentCmdsPath, String suffix) throws IOException {
		String intentCmdsPathName = baseIntentCmdsPath + suffix;
		Path intentCmdsPath = Paths.get(intentCmdsPathName);

		Utils.deletePathIfExists(intentCmdsPath);
		return Files.newBufferedWriter(intentCmdsPath, Charset.defaultCharset(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
	}

	private void doPathAnalysis(final SootMethod method, boolean backward, boolean isIntra) {
		Body b = method.retrieveActiveBody();
		PatchingChain<Unit> units = b.getUnits();
		final BriefUnitGraph ug = new BriefUnitGraph(b);
		final String currClassName = method.getDeclaringClass().getName();
		int totalUnitsToAnalyzeCount = 0;

		int currUnitToAnalyzeCount = 0;
		for (final Unit unit : units) {
			boolean performPathAnalysis = false;

			synchronized (method) {
				if (backward) {
					performPathAnalysis = unitNeedsAnalysisSink(method, currClassName, unit, methodSummaries, sinksMethodSignatures);
				} else {
					performPathAnalysis = unitNeedsAnalysisSource(method, currClassName, unit, srcMethodSummaries, sourcesMethodSignatures);
				}
			}

			if (performPathAnalysis) {
				logger.debug("Performing path analysis for unit: " + unit);
				logger.debug("Currently analyzing unit " + currUnitToAnalyzeCount + " of " + totalUnitsToAnalyzeCount);
				StopWatch stopWatch = new StopWatch();
				stopWatch.start();

				// unit becomes startingUnit in callees
				if (backward) {
					doPathAnalysisOnUnitUsingExecutor(method, ug, currClassName, unit, true, isIntra);
					//doPathAnalysisOnUnit(0, method, ug, currClassName, unit, true, isIntra);
				} else {
					doPathAnalysisOnUnitUsingExecutor(method, ug, currClassName, unit, false, isIntra);
					//doPathAnalysisOnUnit(0, method, ug, currClassName, unit, false, isIntra);
				}
				totalUnitsToAnalyzeCount++;
				stopWatch.stop();
				logger.debug("Time to compute unit " + currUnitToAnalyzeCount + ": " + stopWatch.getElapsedTime());

				Pair<Unit, SootMethod> unitMethod = new Pair<Unit, SootMethod>(unit, method);
				targetedUnits.add(unitMethod);

				currUnitToAnalyzeCount++;
			}
		}
	}

	private void doPathAnalysis(final SootMethod method, boolean backward, boolean isIntra, Collection<Future<?>> futures) {
		Body b = method.retrieveActiveBody();
		PatchingChain<Unit> units = b.getUnits();
		final BriefUnitGraph ug = new BriefUnitGraph(b);
		final String currClassName = method.getDeclaringClass().getName();
		int totalUnitsToAnalyzeCount = 0;

		int currUnitToAnalyzeCount = 0;
		for (final Unit unit : units) {
			boolean performPathAnalysis = false;

			synchronized (method) {
				if (backward) {
					performPathAnalysis = unitNeedsAnalysisSink(method, currClassName, unit, methodSummaries, sinksMethodSignatures);
				} else {
					performPathAnalysis = unitNeedsAnalysisSource(method, currClassName, unit, srcMethodSummaries, sourcesMethodSignatures);
				}
			}

			if (performPathAnalysis) {
				logger.debug("Performing path analysis for unit: " + unit);
				logger.debug("Currently analyzing unit " + currUnitToAnalyzeCount + " of " + totalUnitsToAnalyzeCount);
				StopWatch stopWatch = new StopWatch();
				stopWatch.start();

				// unit becomes startingUnit in callees
				if (backward) {
					doPathAnalysisOnUnitUsingExecutor(method, ug, currClassName, unit, true, isIntra, futures);
					//doPathAnalysisOnUnit(0, method, ug, currClassName, unit, true, isIntra);
				} else {
					doPathAnalysisOnUnitUsingExecutor(method, ug, currClassName, unit, false, isIntra, futures);
					//doPathAnalysisOnUnit(0, method, ug, currClassName, unit, false, isIntra);
				}
				totalUnitsToAnalyzeCount++;
				stopWatch.stop();
				logger.debug("Time to compute unit " + currUnitToAnalyzeCount + ": " + stopWatch.getElapsedTime());

				Pair<Unit, SootMethod> unitMethod = new Pair<Unit, SootMethod>(unit, method);
				targetedUnits.add(unitMethod);

				currUnitToAnalyzeCount++;
			}
		}
	}

	public void doPathAnalysisOnUnitUsingExecutor(final SootMethod method,
												  final BriefUnitGraph ug,
												  final String currClassName,
												  final Unit unit,
												  final boolean backward,
												  final boolean isIntra) {
		executor.execute(new Runnable() {
			@Override
			public void run() {
				Options.v().set_time(false);

				logger.debug("begin path analysis on unit " + unit + " of method " + method);
				doPathAnalysisOnUnit(0, method, ug, currClassName, unit, backward, isIntra);
				//doPathAnalysisOnUnit(0, method, ug, currClassName, unit);
				logger.debug("end path analysis on unit " + unit + " of method " + method);

			}
		});
	}

	public void doPathAnalysisOnUnitUsingExecutor(final SootMethod method,
												  final BriefUnitGraph ug,
												  final String currClassName,
												  final Unit unit,
												  final boolean backward,
												  final boolean isIntra,
												  Collection<Future<?>> futures) {
		futures.add(executor.submit(new Runnable() {
			@Override
			public void run() {
				Options.v().set_time(false);

				logger.debug("begin path analysis on unit " + unit + " of method " + method);
				doPathAnalysisOnUnit(0, method, ug, currClassName, unit, backward, isIntra);
				//doPathAnalysisOnUnit(0, method, ug, currClassName, unit);
				logger.debug("end path analysis on unit " + unit + " of method " + method);

			}
		}));
	}

	public Set<List<Unit>> extractPath(BriefUnitGraph ug, Unit startingUnit, Boolean backward, int limit) {
		Set<List<Unit>> finalPaths = new LinkedHashSet<List<Unit>>();

		// set up worklists
		Stack<Unit> workUnits = new Stack<Unit>(); // working stack for units to start or continue path analysis from
		workUnits.push(startingUnit);
		Stack<List<Unit>> workPaths = new Stack<List<Unit>>(); // working stack for paths under analysis
		List<Unit> initialPath = new ArrayList<Unit>();
		initialPath.add(startingUnit);
		workPaths.push(initialPath);

		// set limits
		int finalPathsLimit = limit;
		if (!pathLimitEnabled) {
			finalPathsLimit = Integer.MAX_VALUE;
		}
		while (!workUnits.isEmpty()) {
			if (workPaths.size() != workUnits.size()) {
				throw new RuntimeException("workUnits size is different from workPaths size");
			}

			Unit startUnitOfCurrPath = workUnits.pop(); // starting unit in current path
			List<Unit> currPath = workPaths.pop(); // current path to work on

			boolean reachEnd;
			if (backward) {
				reachEnd = ug.getPredsOf(startUnitOfCurrPath).isEmpty();
			} else {
				reachEnd = ug.getSuccsOf(startUnitOfCurrPath).isEmpty();
			}

			if (reachEnd) { // if there are no more predecessors than we reached the end of the path
				if (logger.isTraceEnabled()) {
					logger.trace("A final path:");
					logger.trace("\n" + Joiner.on("\n").join(currPath));
				}

				if (finalPaths.size() < finalPathsLimit) {
					// add currPath to path to analyze if it reaches the beginning and is less than a pre-set limit
					finalPaths.add(currPath);
				} else {
					break;
				}
			}

			List<Unit> nextUnits;
			if (backward) {
				nextUnits = ug.getPredsOf(startUnitOfCurrPath);
			} else {
				nextUnits = ug.getSuccsOf(startUnitOfCurrPath);
			}
			for (Unit u : nextUnits) { // update paths based on predecessors
				if (currPath.contains(u)) {
					continue;
				}

				if (logger.isTraceEnabled()) {
					logger.trace("Forking the following path on predecessor unit " + u);
					logger.trace(Joiner.on("\n").join(currPath) + "\n");
				}

				List<Unit> newPath = new ArrayList<Unit>(currPath);
				newPath.add(u); // add to end of list, so path is reverse

				// if there are two preds, two new paths will be created
				workPaths.push(newPath);
				workUnits.push(u);
			}
		}
		return finalPaths;
	}

	public void doPathAnalysisOnUnit(int tabs, SootMethod method, BriefUnitGraph ug, String currClassName, Unit startingUnit, boolean backward, boolean isIntra) {

		Set<Unit> discoveredUnits = new LinkedHashSet<Unit>(); // units for which paths have begun enumeration
		discoveredUnits.add(startingUnit);

		Stack<Unit> workUnits = new Stack<Unit>(); // working stack for units to start or continue path analysis from
		workUnits.push(startingUnit);

		Stack<List<Unit>> workPaths = new Stack<List<Unit>>(); // working stack for paths under analysis
		List<Unit> initialPath = new ArrayList<Unit>();
		initialPath.add(startingUnit);
		workPaths.push(initialPath);


		Set<List<Unit>> finalPaths;
		if (backward) {
			finalPaths = extractPath(ug, startingUnit, true, finalPathsLimit);
		} else {
			// forward paths extraction
			finalPaths = extractPath(ug, startingUnit, false, finalPathsLimit);
		}

		// finalPaths contain all possible paths in the function
		// each element of finalPaths is a possible path in the function based on CFG
		// each path is in reverse
		for (List<Unit> currPath : finalPaths) { // analyzed fully-determined relevant program paths
			//this.pathsAnalyzedCount++;
			//List<Unit> currPathJNI = new ArrayList<Unit>();
			Set<List<String>> currPathJNIs = new HashSet<List<String>>();

			// perform intra-procedural analysis
			// updates currPathJNI with JNI call sequence
			// create methodIntraSummaries that only track intraprocedural JNI call sequences.
			// what about a method that contains two methods that eventually call JNI methods

			// if currPath has a method call in methodSummaries, multiple
			// curPathJNIs may be generated
			if (backward) {
				analyzeProgramPathSink(tabs, method, currPath, currPathJNIs, isIntra);
			} else {
				analyzeProgramPathSource(tabs, method, currPath, currPathJNIs, isIntra);
			}
		}
	}

	private boolean isDefInPathAndLatest(List<Unit> path, Unit inDef, Local usedLocal, Unit usedUnit, SimpleLocalDefs defs) {
		if (path.contains(inDef)) { // does the path contain the definition
			for (Unit otherDef : defs.getDefsOfAt(usedLocal, usedUnit)) { // check other defs of usedLocal at usedUnit to determine if inDef is the latestDef in path
				if (inDef.equals(otherDef)) { // continue if inDef equals otherDef
					continue;
				}
				if (!path.contains(otherDef)) { // if the otherDef is not in path, then continue
					continue;
				}
				List<Unit> cipList = new ArrayList<Unit>(path);
				int inDefPos = cipList.indexOf(inDef);
				int argDef2Pos = cipList.indexOf(otherDef);
				if (inDefPos < argDef2Pos) { // if inDef's position in the path is earlier then otherDef's position, then inDef is not the latest definition in the path, so return false
					return false;
				}
			}
			return true; // inDef is in the path and is the latest definition along that path
		} else { // inDef is not in the path, so return false
			return false;
		}
	}

	private boolean isSrcMethod(SootMethod method) {
		for (String source : sourcesMethodSignatures) {
			if (method.getSignature().equals(source)) {
				return true;
			}
		}
		return false;
	}

	private void analyzeProgramPathSource(int tabs, SootMethod method, List<Unit> currPath, Set<List<String>> currPathJNIs, boolean isIntra) {
		Set<List<String>> wipCurrPathJNIs = new HashSet<List<String>>();
		List<Unit> currPathAsList = new ArrayList<Unit>(currPath);
		Unit startingUnit = currPathAsList.get(0); // source invocation
		Stmt startingStmt = (Stmt) startingUnit;
		SootMethod startingCalledMethod = startingStmt.getInvokeExpr().getMethod();
		InvokeExpr startingExpr = startingStmt.getInvokeExpr();
		String srcSignature = startingExpr.getMethod().getSignature();
//		SootClass clsk = Scene.v().getSootClass("com.mitake.network.k");
//		SootClass clsi = Scene.v().getSootClass("com.mitake.network.i");
//		SootMethod ka = clsk.getMethod("void a(java.io.InputStream)");
//		SootMethod ia = clsi.getMethod("byte[] a(java.io.InputStream,int)");
		for (int i = 0; i < currPathAsList.size(); i++) {
			// iterating each instruction in path currPath
			Unit currUnitInPath = currPathAsList.get(i); // current unit under analysis for current path
			if (!method.hasActiveBody()) {
				throw new RuntimeException("method has no active body, which shouldn't happen: " + method.getName());
			}

			Stmt currStmtInPath = (Stmt) currUnitInPath;
			if (currStmtInPath.containsInvokeExpr()) {
				InvokeExpr ie = currStmtInPath.getInvokeExpr();
				SootMethod calledMethod = ie.getMethod();
				// check if unit is a JNI call
				if (Utils.isAndroidMethod(calledMethod) && !isSrcMethod(calledMethod)) {
					continue;
				}
				if (sinksMethodSignatures.contains(calledMethod.getSignature())) {
					// intra-procedural src-sink pair
					if (isSrcMethod(startingCalledMethod)) {
						// the unit where unitNeedsAnalysis returns true and is a sink invocation (not a transitive call)
						List<String> rootPair = new ArrayList<String>();
						//rootPair.add(method.getSignature() + " : " + startingUnit.toString());
						String src = method.getSignature() + " : " + startingUnit.toString();
						rootPair.add(method.getSignature() + " : " + currUnitInPath.toString());
						srcSinkPairs.add(new Pair<List<String>, List<String>>(Collections.singletonList(src), rootPair));
						logger.debug("SRC-SINK: "+src+" -> "+rootPair);
					} else {
						if (srcMethodSummaries.containsKey(startingCalledMethod)) {
							// create a new unitPathJNI that is current unitPathJNI + current iteration of unitPathJNI
							Map<Unit, List<UnitPathSink>> unitSumSrc = srcMethodSummaries.get(startingCalledMethod);
							for (Map.Entry<Unit, List<UnitPathSink>> ues : unitSumSrc.entrySet()) {
								List<UnitPathSink> pathsSrc = ues.getValue();
								for (UnitPathSink ps : pathsSrc) {
									List<String> rootPair = new ArrayList<String>();
									rootPair.add(method.getSignature() + " : " + currUnitInPath.toString());
									List<String> srcPair = new ArrayList<String>(ps.getPathSink());
									srcPair.add(method.getSignature());
									srcSinkPairs.add(new Pair<List<String>, List<String>>(srcPair, rootPair));
									logger.debug("SRC-SINK: "+srcPair+" -> "+rootPair);
								}
							}
						}
					}
				}
				if (i == 0) {
					// track source methods for transitivity
					if (isSrcMethod(calledMethod)) {
						// unit is a source
						List<String> rootPathJNI = new ArrayList<String>();
						rootPathJNI.add(method.getSignature() + " : " + currUnitInPath.toString());
						UnitPathSink up = new UnitPathSink(rootPathJNI, currPath, calledMethod.getSignature());
						storeToMethodSummaries(srcMethodSummaries, method, startingUnit, up);
						// sink can reach
						if (methodSummaries.containsKey(method)) {
							Map<Unit, List<UnitPathSink>> unitSumSrc = srcMethodSummaries.get(method);
							for (Map.Entry<Unit, List<UnitPathSink>> ues : unitSumSrc.entrySet()) {
								List<UnitPathSink> pathsSrc = ues.getValue();
								for (UnitPathSink ps : pathsSrc) {
									srcSinkPairs.add(new Pair<List<String>, List<String>>(rootPathJNI, ps.getPathSink()));
									logger.debug("SRC-SINK: "+rootPathJNI+" -> "+ps.getPathSink());
								}
							}
						}
					} else {
						// unit is a function call that can reach a source
						if (srcMethodSummaries.containsKey(calledMethod)) {
							// create a new unitPathJNI that is current unitPathJNI + current iteration of unitPathJNI
							Map<Unit, List<UnitPathSink>> unitSum = srcMethodSummaries.get(calledMethod);
							for (Map.Entry<Unit, List<UnitPathSink>> ue : unitSum.entrySet()) {
								List<UnitPathSink> paths = ue.getValue();
								for (UnitPathSink p : paths) {
									List<String> interPathJNI = new ArrayList<String>(p.getPathSink());
									interPathJNI.add(method.getSignature());
									UnitPathSink up = new UnitPathSink(interPathJNI, currPath, p.sinkSignature);
									storeToMethodSummaries(srcMethodSummaries, method, startingUnit, up);
									// sink can reach
									if (methodSummaries.containsKey(method)) {
										Map<Unit, List<UnitPathSink>> unitSumSrc = methodSummaries.get(method);
										for (Map.Entry<Unit, List<UnitPathSink>> ues : unitSumSrc.entrySet()) {
											List<UnitPathSink> pathsSrc = ues.getValue();
											for (UnitPathSink ps : pathsSrc) {
												srcSinkPairs.add(new Pair<List<String>, List<String>>(p.getPathSink(), ps.getPathSink()));
												logger.debug("SRC-SINK: "+p.getPathSink()+" -> "+ps.getPathSink());
											}
										}
									}
								}
							}
						} /*else {
							// new src
							List<String> rootPathJNI = new ArrayList<String>();
							rootPathJNI.add(method.getSignature() + " : " + currUnitInPath.toString());
							UnitPathSink up = new UnitPathSink(rootPathJNI, currPath, calledMethod.getSignature());
							storeToMethodSummaries(srcMethodSummaries, method, startingUnit, up);
						}*/
					}
				}

				// also add to currPathJNI if it's to a method call that transitively calls a JNI method
				// this may result in multiple currPathJNIs
				if (!isIntra) {
					if (methodSummaries.containsKey(calledMethod) && (i!=0)) {
						// create a new unitPathJNI that is current unitPathJNI + current iteration of unitPathJNI
						Map<Unit, List<UnitPathSink>> unitSum = methodSummaries.get(calledMethod);
						for (Map.Entry<Unit, List<UnitPathSink>> ue : unitSum.entrySet()) {
							Unit u = ue.getKey();
							List<UnitPathSink> paths = ue.getValue();
							for (UnitPathSink p : paths) {
								if (isSrcMethod(calledMethod)) {
									List<String> interPathJNI = new ArrayList<String>();
									//interPathJNI.add(method.getSignature() + " : " + startingUnit.toString());
									String src = method.getSignature() + " : " + startingUnit.toString();
									interPathJNI.addAll(p.getPathSink());
									srcSinkPairs.add(new Pair<List<String>, List<String>>(Collections.singletonList(src), interPathJNI));
									logger.debug("SRC-SINK: "+Collections.singletonList(src)+" -> "+interPathJNI);
								} else {
									if (srcMethodSummaries.containsKey(startingCalledMethod)) {
										// create a new unitPathJNI that is current unitPathJNI + current iteration of unitPathJNI
										Map<Unit, List<UnitPathSink>> unitSumSrc = srcMethodSummaries.get(startingCalledMethod);
										for (Map.Entry<Unit, List<UnitPathSink>> ues : unitSumSrc.entrySet()) {
											List<UnitPathSink> pathsSrc = ues.getValue();
											for (UnitPathSink ps : pathsSrc) {
												List<String> interPathJNI = new ArrayList<String>();
												interPathJNI.addAll(p.getPathSink()); // paths to sinks
												srcSinkPairs.add(new Pair<List<String>, List<String>>(ps.getPathSink(), interPathJNI));
												logger.debug("SRC-SINK: "+ps.getPathSink()+" -> "+interPathJNI);
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if (!wipCurrPathJNIs.isEmpty()) {
			currPathJNIs.addAll(wipCurrPathJNIs);
		}
	}

	private void analyzeProgramPathSink(int tabs, SootMethod method, List<Unit> currPath, Set<List<String>> currPathJNIs, boolean isIntra) {
		Set<List<String>> wipCurrPathJNIs = new HashSet<List<String>>();
		List<Unit> currPathAsList = new ArrayList<Unit>(currPath);
		Unit startingUnit = currPathAsList.get(0);
		for (int i = 0; i < currPathAsList.size(); i++) {
			// iterating each instruction in path currPath
			Unit currUnitInPath = currPathAsList.get(i); // current unit under analysis for current path
			if (!method.hasActiveBody()) {
				throw new RuntimeException("method has no active body, which shouldn't happen: " + method.getName());
			}

			Stmt currStmtInPath = (Stmt) currUnitInPath;
			if (currStmtInPath.containsInvokeExpr()) {
				InvokeExpr ie = currStmtInPath.getInvokeExpr();
				SootMethod calledMethod = ie.getMethod();
				// check if unit is a JNI call
				if (Utils.isAndroidMethod(calledMethod)) {
					continue;
				}
				if (sinksMethodSignatures.contains(calledMethod.getSignature()) && i==0) {
					// the unit where unitNeedsAnalysis returns true and is a sink invocation (not a transitive call)
					List<String> rootPathJNI = new ArrayList<String>();
					rootPathJNI.add(method.getSignature() + " : " + currUnitInPath.toString());
					UnitPathSink up = new UnitPathSink(rootPathJNI, currPath, calledMethod.getSignature());
					storeToMethodSummaries(methodSummaries, method, startingUnit, up);
				}

				// also add to currPathJNI if it's to a method call that transitively calls a JNI method
				// this may result in multiple currPathJNIs
				if (!isIntra) {
					if (methodSummaries.containsKey(calledMethod)) {
						// create a new unitPathJNI that is current unitPathJNI + current iteration of unitPathJNI
						Map<Unit, List<UnitPathSink>> unitSum = methodSummaries.get(calledMethod);
						for (Map.Entry<Unit, List<UnitPathSink>> ue : unitSum.entrySet()) {
							Unit u = ue.getKey();
							List<UnitPathSink> paths = ue.getValue();
							for (UnitPathSink p : paths) {
								List<String> interPathJNI = new ArrayList<String>(p.getPathSink());
								interPathJNI.add(method.getSignature());
								UnitPathSink up = new UnitPathSink(interPathJNI, currPath, p.sinkSignature);
								storeToMethodSummaries(methodSummaries, method, startingUnit, up);
							}
						}
					}
				}
			}
		}
		if (!wipCurrPathJNIs.isEmpty()) {
			currPathJNIs.addAll(wipCurrPathJNIs);
		}
	}

	public void storeToMethodSummaries(Map<SootMethod, Map<Unit, List<UnitPathSink>>> summaries, SootMethod method, Unit unitKey, UnitPathSink up) {
		Map<Unit, List<UnitPathSink>> unitSum = null;
		// store to methodSummaries
		// unitSum is a map of unit to list of unitpathJNI that leads to it
		if (summaries.containsKey(method)) {
			unitSum = summaries.get(method);
		} else {
			unitSum = new ConcurrentHashMap<Unit, List<UnitPathSink>>();
		}
		List<UnitPathSink> unitPathJNIs = null;
		if (unitSum.containsKey(unitKey)) {
			// there are paths found previously for startingUnit
			unitPathJNIs = unitSum.get(unitKey);
		} else {
			// first path found for startingUnit
			unitPathJNIs = new ArrayList<UnitPathSink>();
		}
		unitPathJNIs.add(up);
		unitSum.put(unitKey, unitPathJNIs);
		summaries.put(method, unitSum);
	}

	public synchronized void storeGeneratedDataToWriter(String currClassName, Intent genIntent) {
		Component comp = androidProcessor.findComponent(currClassName);

		if (comp == null) {
			for (SootClass dynReceiver : dynRegReceivers) {
				if (dynReceiver.getName().equals(currClassName)) {
					comp = new Receiver(currClassName);
					comp.setExported(true);
				}
			}
		}

		BufferedWriter drozerWriter = null;
		//BufferedWriter adbWriter = null;
		if (comp instanceof Activity) {
			//writer = activityCmdsWrappedStringWriter;
			drozerWriter = activityCmdsDrozerFileWriter;
			//adbWriter = activityCmdsAdbFileWriter;
		} else if (comp instanceof Service) {
			//writer = serviceCmdsWrappedStringWriter;
			drozerWriter = serviceCmdsDrozerFileWriter;
			//adbWriter = serviceCmdsAdbFileWriter;
		} else if (comp instanceof Receiver) {
			drozerWriter = receiverCmdsDrozerFileWriter;
			//adbWriter = receiverCmdsAdbFileWriter;
		} else {
			logger.error("Unsupported component type: " + comp);
			logger.error("Won't write new intent command files for this component");
			return;
		}
		try {
			androidProcessor.writeIntentCmdsForDrozer(currClassName, comp, genIntent, drozerWriter);
			//androidProcessor.writeIntentCmdsForADB(currClassName,comp, genIntent, adbWriter);
			drozerWriter.flush();
			//adbWriter.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	public Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> findLeftAndRightValuesOfByteVal(SootMethod method, SimpleLocalDefs defs, Unit inUnit, Value value, List<Unit> currPath) {
		Quartet<Value, String, String, Unit> leftVal = null;
		Quartet<Value, String, String, Unit> rightVal = null;
		if (value instanceof Local) {
			Local local = (Local) value;
			if (local.getType() instanceof ByteType) {
				List<Unit> potentialCmpUnits = defs.getDefsOfAt(local, inUnit);
				for (Unit potentialCmpUnit : potentialCmpUnits) {
					/*if (!currPath.contains(potentialCmpUnit)) {
						continue;
					}*/
					if (!isDefInPathAndLatest(currPath, potentialCmpUnit, local, inUnit, defs)) {
						continue;
					}
					if (potentialCmpUnit.toString().contains("cmp")) {
						logger.debug("Found potential cmp* statement: " + potentialCmpUnit);
						if (potentialCmpUnit instanceof DefinitionStmt) {
							DefinitionStmt defStmt = (DefinitionStmt) potentialCmpUnit;
							Value rightOp = defStmt.getRightOp();
							if (rightOp instanceof AbstractJimpleIntBinopExpr) {
								AbstractJimpleIntBinopExpr cmpExpr = (AbstractJimpleIntBinopExpr) rightOp;
								leftVal = findOriginalVal(method, defs, potentialCmpUnit, cmpExpr.getOp1(), currPath);
								rightVal = findOriginalVal(method, defs, potentialCmpUnit, cmpExpr.getOp2(), currPath);
							}
						}
					}
				}
			}
		}
		return new Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>>(leftVal, rightVal);
	}

	public Quartet<Value, String, String, Unit> findOriginalVal(SootMethod method, SimpleLocalDefs defs, Unit potentialCmpUnit, Value cmpOp, List<Unit> currPath) {
		Value origVal = null;
		String newDecl = null;
		String newAssert = null;
		Unit defUnit = null;
		if (cmpOp instanceof Local) {
			Value cmpVal = cmpOp;
			Quartet<Value, String, String, Unit> r = findOriginalValFromCmpVal(method, defs, potentialCmpUnit, cmpVal, currPath);
			origVal = r.getValue0();
			newDecl = r.getValue1();
			newAssert = r.getValue2();
			defUnit = r.getValue3();
		} else if (cmpOp instanceof Constant) {
			origVal = cmpOp;
			if (cmpOp instanceof StringConstant) {

			}
		} else {
			throw new RuntimeException("Unhandled cmpOp for: " + potentialCmpUnit);
		}
		return new Quartet<Value, String, String, Unit>(origVal, newDecl, newAssert, defUnit);
	}

	public Quartet<Value, String, String, Unit> findOriginalValFromCmpVal(SootMethod method, SimpleLocalDefs defs, Unit potentialCmpUnit, Value cmpVal, List<Unit> currPath) {
		Value origVal = null;
		String key = null;
		Local cmpOp1 = (Local) cmpVal;
		List<Unit> castOrInvokeUnits = defs.getDefsOfAt(cmpOp1, potentialCmpUnit);
		String newDecl = null;
		String newAssert = null;
		Unit defUnit = null;
		for (Unit coiUnit : castOrInvokeUnits) {
			/*if (!currPath.contains(coiUnit)) {
				continue;
			}*/
			if (!isDefInPathAndLatest(currPath, coiUnit, cmpOp1, potentialCmpUnit, defs)) {
				continue;
			}
			logger.debug("Found potential cast or invoke stmt: " + coiUnit);
			if (coiUnit instanceof DefinitionStmt) {
				DefinitionStmt coiStmt = (DefinitionStmt) coiUnit;
				origVal = coiStmt.getLeftOp();
				defUnit = coiUnit;
				if (!currPath.contains(defUnit)) {
					continue;
				}
				if (coiStmt.getRightOp() instanceof JCastExpr) {
					logger.debug("Handling cast expression from potential API invocation assigned to local");
					JCastExpr expr = (JCastExpr) coiStmt.getRightOp();
					if (expr.getOp() instanceof Local) {
						Local localFromCast = (Local) expr.getOp();
						List<Unit> defsOfLocalFromCast = defs.getDefsOfAt(localFromCast, coiUnit);
						for (Unit defLocalAssignFromCastUnit : defsOfLocalFromCast) {
							/*if (!currPath.contains(defLocalAssignFromCastUnit)) {
								continue;
							}*/
							if (!isDefInPathAndLatest(currPath, defLocalAssignFromCastUnit, localFromCast, coiUnit, defs)) {
								continue;
							}
							if (defLocalAssignFromCastUnit instanceof DefinitionStmt) {
								DefinitionStmt defLocalAssignFromCastStmt = (DefinitionStmt) defLocalAssignFromCastUnit;
								origVal = defLocalAssignFromCastStmt.getLeftOp();
								defUnit = defLocalAssignFromCastUnit;
								key = extractKeyFromIntentExtra(defLocalAssignFromCastStmt, defs, currPath);
							}
						}
					}
				} else {
					key = extractKeyFromIntentExtra(coiStmt, defs, currPath);
				}

				if (coiStmt.getRightOp() instanceof StringConstant) {
					Local local = (Local) coiStmt.getLeftOp();
					String symbol = createSymbol(local, method, coiStmt);
					symbolLocalMap.put(symbol, local);
					StringConstant stringConst = (StringConstant) coiStmt.getRightOp();
					newDecl = "(declare-const " + symbol + " String )";
					newAssert = "(assert (= " + symbol + " " + stringConst + " ))";
				}

				if (coiStmt.getRightOp() instanceof ParameterRef) {
					logger.debug("Found parameter ref when searching for original value");
					if (coiStmt.getLeftOp() instanceof Local) {
						Local prLocal = (Local) coiStmt.getLeftOp();
						String localSymbol = createSymbol(prLocal, method, coiStmt);

						origVal = coiStmt.getLeftOp();
						ParameterRef pr = (ParameterRef) coiStmt.getRightOp();
						String prSymbol = createParamRefSymbol(prLocal, pr.getIndex(), method, coiStmt);

						newDecl = "(declare-const " + prSymbol + " ParamRef)";
						newAssert = "(assert ( = (index " + prSymbol + ") " + pr.getIndex() + "))\n";
						newAssert += "(assert ( = (type " + prSymbol + ") \"" + pr.getType() + "\"))\n";
						newAssert += "(assert ( = (method " + prSymbol + ") \"" + method.getDeclaringClass().getName() + "." + method.getName() + "\"))\n";
						// TODO: HASPARAMREF LOC
						newAssert += "(assert (= (hasParamRef " + localSymbol + " " + prSymbol + ") true))";
						defUnit = coiStmt;
					}
				}
			}
		}
		valueKeyMap.put(origVal, key);
		return new Quartet<Value, String, String, Unit>(origVal, newDecl, newAssert, defUnit);
	}

	public String extractKeyFromIntentExtra(DefinitionStmt defStmt, SimpleLocalDefs defs, List<Unit> currPath) {

		String key = null;
		if (defStmt.getRightOp() instanceof JVirtualInvokeExpr) {
			JVirtualInvokeExpr expr = (JVirtualInvokeExpr) defStmt.getRightOp();
			boolean keyExtractionEnabled = false;
			if (Pattern.matches("get.*Extra", expr.getMethod().getName())) {
				if (expr.getMethod().getDeclaringClass().toString().equals("android.content.Intent")) {
					keyExtractionEnabled = true;
				}
			}
			if (Pattern.matches("has.*Extra", expr.getMethod().getName())) {
				if (expr.getMethod().getDeclaringClass().toString().equals("android.content.Intent")) {
					keyExtractionEnabled = true;
				}
			}
			if (Globals.bundleExtraDataMethodsSet.contains(expr.getMethod().getName())) {
				if (expr.getMethod().getDeclaringClass().getName().equals("android.os.Bundle")) {
					keyExtractionEnabled = true;
				}
				if (expr.getMethod().getDeclaringClass().getName().equals("android.os.BaseBundle")) {
					keyExtractionEnabled = true;
				}
			}

			if (keyExtractionEnabled) {
				logger.debug("We can extract the key from this expression");
				if (!(expr.getArg(0) instanceof StringConstant)) {
					if (expr.getArg(0) instanceof Local) {
						Local keyLocal = (Local) expr.getArg(0);
						List<Unit> defUnits = defs.getDefsOfAt(keyLocal, defStmt);
						for (Unit defUnit : defUnits) {
							/*if (!currPath.contains(defUnit)) {
								continue;
							}*/
							if (!isDefInPathAndLatest(currPath, defUnit, keyLocal, defStmt, defs)) {
								continue;
							}
							if (defUnit instanceof DefinitionStmt) {
								DefinitionStmt keyLocalDefStmt = (DefinitionStmt) defUnit;
								if (keyLocalDefStmt.getRightOp() instanceof VirtualInvokeExpr) {
									VirtualInvokeExpr invokeExpr = (VirtualInvokeExpr) keyLocalDefStmt.getRightOp();
									if (invokeExpr.getBase() instanceof Local) {
										if (invokeExpr.getMethod().getDeclaringClass().getType().toString().equals("java.lang.Enum")) {
											Local base = (Local) invokeExpr.getBase();
											List<Unit> baseDefs = defs.getDefsOfAt(base, keyLocalDefStmt);
											for (Unit baseDef : baseDefs) {
												/*if (!currPath.contains(baseDef)) {
													continue;
												}*/
												if (!isDefInPathAndLatest(currPath, baseDef, base, keyLocalDefStmt, defs)) {
													continue;
												}
												if (baseDef instanceof DefinitionStmt) {
													DefinitionStmt baseDefStmt = (DefinitionStmt) baseDef;
													if (baseDefStmt.getRightOp() instanceof FieldRef) {
														FieldRef fieldRef = (FieldRef) baseDefStmt.getRightOp();
														if (fieldRef.getField().getDeclaringClass().toString().equals(invokeExpr.getBase().getType().toString())) {
															key = fieldRef.getField().getName();
														}
													}
												}
											}
										}

									}
									continue;
								} else if (keyLocalDefStmt.getRightOp() instanceof StaticFieldRef) {
									SootField keyField = ((StaticFieldRef) keyLocalDefStmt.getRightOp()).getField();
									SootMethod clinitMethod = keyField.getDeclaringClass().getMethodByName("<clinit>");
									if (clinitMethod.hasActiveBody()) {
										Body clinitBody = clinitMethod.getActiveBody();
										for (Unit clinitUnit : clinitBody.getUnits()) {
											if (clinitUnit instanceof DefinitionStmt) {
												DefinitionStmt clinitDefStmt = (DefinitionStmt) clinitUnit;
												if (clinitDefStmt.getLeftOp() instanceof StaticFieldRef) {
													SootField clinitField = ((StaticFieldRef) clinitDefStmt.getLeftOp()).getField();
													if (clinitField.equals(keyField)) {
														if (clinitDefStmt.getRightOp() instanceof StringConstant) {
															StringConstant clinitStringConst = (StringConstant) clinitDefStmt.getRightOp();
															key = clinitStringConst.value;
														}
													}
												}
											}
										}
									}
								} else {
									throw new RuntimeException("Unhandled case for: " + keyLocalDefStmt.getRightOp());
								}

							}
						}
					}
				} else {
					key = expr.getArg(0).toString();
				}
			}
		}
		return key;
	}

	public boolean unitNeedsAnalysisSink(SootMethod method, String currClassName, Unit unit, Map<SootMethod, Map<Unit, List<UnitPathSink>>> methodSummaries, Set<String> methodSignatures) {
		if (unit instanceof InvokeStmt) {
			InvokeStmt stmt = (InvokeStmt) unit;
			if (stmt.getInvokeExpr().getMethod().getName().equals("d")) {
				return true;
			}
		}
		return false;
	}

	public boolean unitNeedsAnalysisSource(SootMethod method, String currClassName, Unit unit, Map<SootMethod, Map<Unit, List<UnitPathSink>>> srcMethodSummaries, Set<String> methodSignatures) {
		if (unit instanceof InvokeStmt) {
			InvokeStmt stmt = (InvokeStmt) unit;
			if (stmt.getInvokeExpr().getMethod().getName().equals("d")) {
				return true;
			}
		}
		return false;
	}

	public Set<SrcToSinksReach> run(String srcsnsinksFilePath, SootMethod method) {
		// fill in sources and sinks
		try(BufferedReader br = new BufferedReader(new FileReader(srcsnsinksFilePath))) {
			String sMethodSig = br.readLine();
			while (sMethodSig != null) {
				String[] sig = sMethodSig.split(" -> ");
				if (sig[1].equals("_SOURCE_")) {
					sourcesMethodSignatures.add(sig[0]);
				} else if (sig[1].equals("_SINK_")) {
					sinksMethodSignatures.add(sig[0]);
				} else {
					// NOT source or sink signature!
					throw new RuntimeException();
				}
				sMethodSig = br.readLine();
			}
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return main(method);
	}

	public Set<SrcToSinksReach> run(String srcsnsinksFilePath, List<SootMethod> rtoMethods, boolean isODCG) {
		// fill in sources and sinks
		try(BufferedReader br = new BufferedReader(new FileReader(srcsnsinksFilePath))) {
			String sMethodSig = br.readLine();
			while (sMethodSig != null) {
				String[] sig = sMethodSig.split(" -> ");
				if (sig[1].equals("_SOURCE_")) {
					sourcesMethodSignatures.add(sig[0]);
				} else if (sig[1].equals("_SINK_")) {
					sinksMethodSignatures.add(sig[0]);
				} else {
					// NOT source or sink signature!
					throw new RuntimeException();
				}
				sMethodSig = br.readLine();
			}
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return main(rtoMethods,isODCG);
	}

	// JA: Add separate run for native-based reachability pass
	public Set<SrcToSinksReach> run(List<nativeFuncInfo> nativeMethods, List<SootMethod> rtoMethods, boolean isODCG) {
		// JA: assume root directory is `phenomenon`
		String srcsnsinksFilePath = "SourcesAndSinks.txt";
		try(BufferedReader br = new BufferedReader(new FileReader(srcsnsinksFilePath))) {
			String sMethodSig = br.readLine();
			while (sMethodSig != null) {
				String[] sig = sMethodSig.split(" -> ");
				// JA: previous exception when line is empty or something else other than
				//     METHOD -> SOURCE_OR_SINK structure, just skip over for now
				if (sig.length < 2) {
					sMethodSig = br.readLine();
					continue;
				}
				if (sig[1].equals("_SOURCE_")) {
					sourcesMethodSignatures.add(sig[0]);
				}
				// JA: we can just ignore others for now, throwing an exception would
				//     terminate the program even though there are other methods still
			/* else {
				// NOT source or sink signature!
				throw new RuntimeException();
			} */
				sMethodSig = br.readLine();
			}
			// JA: populate sinks with native method signatures found by idNative
			for (nativeFuncInfo nFunc : nativeMethods) {
				sinksMethodSignatures.add(nFunc.signature);
			}
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		return main(rtoMethods,isODCG);
	}

	// JA: Add separate run for native-based reachability pass
	public Set<SrcToSinksReach> run(List<nativeFuncInfo> nativeMethods, SootMethod method) {
		// JA: assume root directory is `phenomenon`
		String srcsnsinksFilePath = "SourcesAndSinks.txt";
		try(BufferedReader br = new BufferedReader(new FileReader(srcsnsinksFilePath))) {
			String sMethodSig = br.readLine();
			while (sMethodSig != null) {
				String[] sig = sMethodSig.split(" -> ");
				// JA: previous exception when line is empty or something else other than
				//     METHOD -> SOURCE_OR_SINK structure, just skip over for now
				if (sig.length < 2) {
					sMethodSig = br.readLine();
					continue;
				}
				if (sig[1].equals("_SOURCE_")) {
					sourcesMethodSignatures.add(sig[0]);
				}
				// JA: we can just ignore others for now, throwing an exception would
				//     terminate the program even though there are other methods still
			/* else {
				// NOT source or sink signature!
				throw new RuntimeException();
			} */
				sMethodSig = br.readLine();
			}
			// JA: populate sinks with native method signatures found by idNative
			for (nativeFuncInfo nFunc : nativeMethods) {
				sinksMethodSignatures.add(nFunc.signature);
			}
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return main(method);
	}

	private static String convertTypeNameForZ3(Type type) {
		String returnStr = type.toString();
		returnStr = returnStr.replace("[]","-Arr");
		return returnStr;
	}

	private static String createParamRefSymbol(Value opVal, int index, SootMethod method, Unit unit) {
		String valNameNoDollar = opVal.toString();
		BytecodeOffsetTag bcoTag = null;
		for (Tag tag : unit.getTags()) {
			if (tag instanceof BytecodeOffsetTag) {
				bcoTag = (BytecodeOffsetTag)tag;
			}
		}
		String symbol = null;
		if (bcoTag != null)
			symbol = "pr" + index + "_" + convertTypeNameForZ3(opVal.getType()) + "_" + method.getName() + "_" + method.getDeclaringClass().getName() + "_" + bcoTag.toString();
		else
			symbol = "pr" + index + "_" + convertTypeNameForZ3(opVal.getType()) + "_" + method.getName() + "_" + method.getDeclaringClass().getName();
		return symbol;
	}
	
	private static String createSymbol(Value opVal, SootMethod method, Unit unit) {
		String valNameNoDollar = opVal.toString();
		String symbol = null;
		if (unit.getJavaSourceStartLineNumber() > -1)
			symbol = valNameNoDollar + "_" + convertTypeNameForZ3(opVal.getType()) + "_" + method.getName() + "_" + method.getDeclaringClass().getName() + "_" + String.valueOf(unit.getJavaSourceStartLineNumber());
		else
			symbol = valNameNoDollar + "_" + convertTypeNameForZ3(opVal.getType()) + "_" + method.getName() + "_" + method.getDeclaringClass().getName();
		return symbol;
	}
}
