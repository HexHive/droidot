package aaa.bbb.ccc.path.analyses;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.microsoft.z3.Z3Exception;
import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import aaa.bbb.ccc.android.model.*;
import org.javatuples.Pair;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.options.Options;
import soot.tagkit.StringConstantValueTag;
import soot.tagkit.StringTag;
import soot.tagkit.Tag;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class TargetedPathTransformerAnn {

	public Boolean reducedFlag = false;

	protected static final String DROZER_TARGETED_INTENT_CMDS = "drozer_targeted_intent_cmds_";
	private static String ADB_TARGETED_INTENT_CMDS = "adb_targeted_intent_cmds_";

//	static Logger logger = LoggerFactory.getLogger(TargetedPathTransformerSp.class);
	private final String Z3_RUNTIME_SPECS_DIR = "z3_runtime_specs";
	private Set<SootClass> dynRegReceivers;

	/**
	 * to track total number of intents generated
	 */
	public Set<Intent> totalIntents = ConcurrentHashMap.newKeySet();;

	/**
	 * key: a symbol used to represent a Local, value: the Local represented by the symbol
	 */
	//private Map<String, Local> symbolLocalMap = new ConcurrentHashMap<String, Local>();

	/**
	 * key: a Local that is treated symbolically, value: the symbol used to represent the Local
	 */
	//private Map<Local, String> localSymbolMap = new ConcurrentHashMap<Local, String>();

	/**
	 * key: a Value corresponding to an Intent extra, value: the string representing the key of the extra data
	 */
	//private Map<Value, String> valueKeyMap = new ConcurrentHashMap<Value, String>();

	//protected JimpleBasedInterproceduralCFG icfg;

	private AndroidProcessor androidProcessor = new AndroidProcessor();

	BufferedWriter activityCmdsDrozerFileWriter = null;
	BufferedWriter serviceCmdsDrozerFileWriter = null;
	BufferedWriter receiverCmdsDrozerFileWriter = null;

	BufferedWriter activityCmdsAdbFileWriter = null;
	BufferedWriter serviceCmdsAdbFileWriter = null;
	BufferedWriter receiverCmdsAdbFileWriter = null;

	private ExecutorService executor;

	private int basicBlockSize = Integer.MAX_VALUE;

	private static boolean outInitialization = false;

	Set<Pair<String, Set<Triplet<String, String, Type>>>> writableGenData = new LinkedHashSet<Pair<String, Set<Triplet<String, String, Type>>>>();

	Set<Intent> prevWrittenIntents = new LinkedHashSet<Intent>();
	Set<Pair<Unit, SootMethod>> unitsWithoutGenData = new LinkedHashSet<Pair<Unit, SootMethod>>();
	Set<Pair<Unit, SootMethod>> possiblyFeasibleNoGenTargets = new LinkedHashSet<Pair<Unit, SootMethod>>();
	Map<SootMethod, Map<Unit, Set<UnitPath>>> methodSummaries = new ConcurrentHashMap<SootMethod, Map<Unit, Set<UnitPath>>>();

	class UnitPath {
		List<String> locations;  // where each element is of this form: <line number>:<method sig>:<attr>
		List<String> constraintLocations;  // where each element is of this form: <line number>:<method sig>:<attr>
		List<String> locationsWithoutAttrs; // where each element is of this form: <line number>:<method sig>
		Map<String, List<Pair<String,String>>> attrConstraintsMap;

		public UnitPath(List<String> locations, List<String> constraintLocations, List<String> locationsWithoutAttrs, Map<String, List<Pair<String,String>>> attrConstraintsMap) {
			this.locations = locations;
			this.constraintLocations = constraintLocations;
			this.locationsWithoutAttrs = locationsWithoutAttrs;
			this.attrConstraintsMap = attrConstraintsMap;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			UnitPath unitPath = (UnitPath) o;

			if (!locations.equals(unitPath.locations)) return false;
			if (!constraintLocations.equals(unitPath.constraintLocations)) return false;
			if (!attrConstraintsMap.equals(unitPath.attrConstraintsMap)) return false;
			return locationsWithoutAttrs.equals(unitPath.locationsWithoutAttrs);
		}

		@Override
		public int hashCode() {
			int result = locations.hashCode();
			result = 31 * result + constraintLocations.hashCode();
			result = 31 * result + locationsWithoutAttrs.hashCode();
			result = 31 * result + attrConstraintsMap.hashCode();
			return result;
		}

	}

	protected int pathsAnalyzedCount = 0;

	public int getPathsAnalyzedCount() {
		return pathsAnalyzedCount;
	}

	public boolean parallelEnabled = false;
	public boolean pathLimitEnabled = true;

	public boolean debugFlag = false;

	public long mainAnalysisRuntime = -1;

	public Boolean isODCG = false;
	public Boolean demandFilterFlag = false;
	public Boolean payloadAsArgFlag = false;
	public Boolean intentDependentExtractionFlag = false;
	public Boolean wholeProgramCgFlag = false;
	public Boolean handleOnActivityResultFlag = false;
	public Boolean justLineNumber = false;

	public JSONObject annotatedJson = null;

	TargetedPathTransformerAnn() {
		HashMap<String, String> config = new HashMap<String, String>();
		config.put("model", "true"); // turn on model generation for z3
		pathsAnalyzedCount = 0;
		this.annotatedJson = new JSONObject();
	}

	public String apkFilePath;
	public String apkName;

	public TargetedPathTransformerAnn(String apkFilePath) {
		this();
		G.reset();
		this.apkFilePath = apkFilePath;
		Config.apkFilePath = apkFilePath;
		Path p = Paths.get(apkFilePath);
		this.apkName = p.getFileName().toString();
		this.annotatedJson = new JSONObject();
	}

	// Inter-procedural analysis
	public void main(boolean isODCG) throws IOException {
		Runtime.getRuntime().addShutdownHook(new Thread() {
				@Override
				public void run() {
					// write intents as JSON to disk
					Path p = Paths.get(apkFilePath);
					String apkName = p.getFileName().toString();
					if (isODCG) {
						apkName = apkName.substring(0, apkName.lastIndexOf('.')) + "_O_.json";
					}else {
						apkName = apkName.substring(0, apkName.lastIndexOf('.')) + "_P_.json";
					}
					try {
						Writer iWriter = new FileWriter("intents"+File.separator+"intents_"+apkName);
						Gson gsson = new GsonBuilder().create();
						gsson.toJson(totalIntents, iWriter);
						iWriter.flush();
						iWriter.close();
						//System.exit(0);
					} catch (IOException e) {
						throw new RuntimeException(e);
					}
				}

		});

		// turn off extracting Intent info from manifest
		//androidProcessor.extractApkFilters(apkFilePath, totalIntents, annotatedJson);
		this.isODCG = isODCG;

		List<SootMethod> rtoMethods = null;
		List<List<SootMethod>> callgraphs = null;
		// analysis-specific callgraphs
		// inter-procedural (analysis-specific callgraphs)
		// retrieve callgraphs
		AnalysisSpecificCallGraphsGranular ascg = new AnalysisSpecificCallGraphsGranular(apkFilePath);
		ascg.intentDependentExtractionOn = false;
		ascg.handleOnActivityResult = true;
		// each callgraph from callgraphs is in RTO
		callgraphs = ascg.main(true);

		System.out.println(java.time.LocalDateTime.now() + "- Analysis Specific Callgraphs completed.");

		try {
			final String baseDrozerIntentCmdsPath = "data" + File.separator + DROZER_TARGETED_INTENT_CMDS + androidProcessor.mainPackageName;
			//final String baseAdbIntentCmdsPath = "data" + File.separator + ADB_TARGETED_INTENT_CMDS + androidProcessor.mainPackageName;

			executor = null;
			if (parallelEnabled) {
				executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
			}else{
				executor = Executors.newSingleThreadExecutor();
			}
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
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
				});
			}

			//threadPool2.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
			long mainAnalysisStartTime = System.currentTimeMillis();
			// using analysis-specific callgraphs
			assert callgraphs != null;
			Collection<Future<?>> futures = new LinkedList<Future<?>>();
			for (List<SootMethod> cg : callgraphs) {
				// each cg is in reverse topological order
				System.out.println(java.time.LocalDateTime.now() + "- Begin analyzing callgraph of size: " + cg.size());
				processCallgraphUsingExecutor(cg, futures);
			}
			for (Future<?> future : futures) {
				future.get();
			}
			System.out.println("Finishing executor...");
			executor.shutdown();  // stop allowing new task to be added
			System.out.println("Executor shutdown...");
			executor.shutdownNow();  // stop all tasks. Analysis is done
			System.out.println("Executor shutdownNow() finished...");

			FileWriter file = new FileWriter(apkName+".json");
			file.write(annotatedJson.toJSONString());
			file.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ExecutionException|InterruptedException e) {
			throw new RuntimeException(e);
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

	// for inter-procedural (analysis-specific callgraphs)
	private void doPathAnalysis(final SootMethod method, Integer analysisMode, Boolean isRootMethod, Map<SootMethod,
			Map<Unit, Set<UnitPath>>> methodSum, JSONArray methodJson, JSONArray methodLinesJson) {
		Body b = method.getActiveBody();
		PatchingChain<Unit> units = b.getUnits();
		final BriefUnitGraph ug = new BriefUnitGraph(b);
		final String currClassName = method.getDeclaringClass().getName();
		int totalUnitsToAnalyzeCount = 0;

		int currUnitToAnalyzeCount = 0;
		Set<Unit> onDemandApproved = new HashSet<>();
		List<String> intentLocs = new ArrayList<>();  // locations of Intent-controlled if-statements
		for (final Unit unit : units) {
			boolean performPathAnalysis = false;
			synchronized (method) {
				performPathAnalysis = unitNeedsAnalysisTag(method, currClassName, unit, methodSum.keySet(), intentLocs);
				if (performPathAnalysis) {
					onDemandApproved.add(unit);
				}
			}
		}

		if (!justLineNumber) {
			NoPostDom npd = new NoPostDom(ug, onDemandApproved);
			for (Unit u : onDemandApproved) {
				FlowSet flows = (FlowSet) npd.getFlowAfter(u);
				if (flows.size() == 0) {
					// no post-dominator
					//System.out.println("Performing path analysis for unit: " + unit);
					//StopWatch stopWatch = new StopWatch();
					//stopWatch.start();
					// unit becomes startingUnit in callees
					//doPathAnalysisOnUnitUsingExecutor(method, ug, currClassName, u, futures, analysisMode, isRootMethod);
					doPathAnalysisOnUnit(0, method, ug, currClassName, u, analysisMode, isRootMethod, methodSum, methodJson);
					totalUnitsToAnalyzeCount++;
					//stopWatch.stop();
					//logger.debug("Time to compute unit " + currUnitToAnalyzeCount + ": " + stopWatch.getElapsedTime());

					//Pair<Unit, SootMethod> unitMethod = new Pair<Unit, SootMethod>(u, method);

					currUnitToAnalyzeCount++;
				}
			}
		} else {
			// just line numbers
			List<String> locationsFiltered = new ArrayList<>();
			String prev = null;
			for (String loc : intentLocs) {
				if (prev != null && prev.equals(loc)) {
					continue;
				}
				locationsFiltered.add(loc);
				prev = loc;
			}
			methodLinesJson.addAll(locationsFiltered);
		}
	}

	// for inter-procedural (analysis-specific callgraph)
	public void processCallgraphUsingExecutor(List<SootMethod> cg, Collection<Future<?>> futures) {
		futures.add(executor.submit(new Runnable() {
			@Override
			public void run() {
				Options.v().set_time(false);
				int methodIdx = 0;
				Map<SootMethod, Map<Unit, Set<UnitPath>>> methodSummaries = new ConcurrentHashMap<SootMethod, Map<Unit, Set<UnitPath>>>();
				for (SootMethod method : cg) {
					if (Utils.isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
						if (method.hasActiveBody()) {
							Boolean isRootMethod = false;
							if (methodIdx == cg.size()-1) {
								isRootMethod = true;
							}
							// analyze method
							// will update MethodSummaries (sub sub sub call..)
							// will write the ...z3_path_cond file
							// will generate intents to data/ if encountered
							System.out.println(java.time.LocalDateTime.now() + "- Analyzing method: " + method.getSignature());

							JSONArray methodJson = new JSONArray();
							JSONArray methodLinesJson = new JSONArray();
							doPathAnalysis(method,0, isRootMethod, methodSummaries, methodJson, methodLinesJson);  // inter-procedural

							//
							String methodDeclaringClass = method.getDeclaringClass().getName();
							JSONObject classJson = null;
							if (annotatedJson.containsKey(methodDeclaringClass)) {
								classJson = (JSONObject) annotatedJson.get(methodDeclaringClass);
							} else {
								classJson = new JSONObject();
							}

							/*
							if (isRootMethod) {
								// even if methodJson is empty, place it in JSON if it is an entrypoint method
								if (justLineNumber) {
									classJson.put("[R]" + method.getSignature(), methodLinesJson);
								} else {
									classJson.put("[R]" + method.getSignature(), methodJson);
								}
							}
							 */
							if (!justLineNumber) {
								if (methodJson.size() != 0) {
									if (!isRootMethod) {
										classJson.put(method.getSignature(), methodJson);
									} else {
										classJson.put("[R]" + method.getSignature(), methodJson);
									}
								}
							} else {
								// just line numbers
								if (methodLinesJson.size() != 0) {
									if (!isRootMethod) {
										classJson.put(method.getSignature(), methodLinesJson);
									} else {
										classJson.put("[R]" + method.getSignature(), methodLinesJson);
									}
								}
							}
							if (classJson.size() != 0) {
								annotatedJson.put(methodDeclaringClass, classJson);
							}
						}
					}
					methodIdx += 1;
				}

				System.out.println(java.time.LocalDateTime.now() + "- Finish analyzing callgraph of size: " + cg.size());
			}
		}));
	}

	// inter-procedural (analysis-specific callgraphs)
	public void doPathAnalysisOnUnit(int tabs, SootMethod method, BriefUnitGraph ug, String currClassName,
									 Unit startingUnit, Integer analysisMode, Boolean isRootMethod, Map<SootMethod, Map<Unit, Set<UnitPath>>> methodSum, JSONArray methodJson) {



		boolean isFeasible = false;

		Set<Unit> discoveredUnits = new LinkedHashSet<Unit>(); // units for which paths have begun enumeration
		discoveredUnits.add(startingUnit);

		Stack<Unit> workUnits = new Stack<Unit>(); // working stack for units to start or continue path analysis from
		workUnits.push(startingUnit);

		Stack<List<Unit>> workPaths = new Stack<List<Unit>>(); // working stack for paths under analysis
		List<Unit> initialPath = new ArrayList<Unit>();
		initialPath.add(startingUnit);
		workPaths.push(initialPath);

		Set<List<Unit>> finalPaths = new LinkedHashSet<List<Unit>>();

		int finalPathsLimit = 100000;
//		int finalPathsLimit = Integer.MAX_VALUE;
		boolean hitPathsLimit = false;
		if (!pathLimitEnabled) {
			finalPathsLimit = Integer.MAX_VALUE;
		}

		// Perform backward analysis to fill in finalPaths with all paths that can lead to unit
		// No "actual" analysis is performed yet, just paths extraction
		Map<Unit, Set<UnitPath>> unitSum = null;
		while (!workUnits.isEmpty()) {
			if(Thread.currentThread().isInterrupted()) {
				// time is up
				return;
			}
			if (workPaths.size() != workUnits.size()) {
				throw new RuntimeException(Utils.createTabsStr(tabs) + "workUnits size is different from workPaths size");
			}

			Unit startUnitOfCurrPath = workUnits.pop(); // starting unit in current path
			List<Unit> currPath = workPaths.pop(); // current path to work on
			discoveredUnits.add(startUnitOfCurrPath);

			if (ug.getPredsOf(startUnitOfCurrPath).isEmpty()) { // if there are no more predecessors than we reached the end of the path
				if (startUnitOfCurrPath instanceof IdentityStmt) {
					// Reach the beginning of the function
					IdentityStmt idStmt = (IdentityStmt) startUnitOfCurrPath;
					if (idStmt.getRightOp() instanceof CaughtExceptionRef) {
//						logger.trace("Exceptional path is not being analyzed for now");
					} else {
						// increase finalPathsLimit will get more paths?
						if (finalPaths.size() < finalPathsLimit) {
							// add currPath to path to analyze if it reaches the beginning and is less than a pre-set limit
							finalPaths.add(currPath);
						} else {
							hitPathsLimit = true;
							break;
						}
					}
				}
			}

			// traversing in reverse
			for (Unit pred : ug.getPredsOf(startUnitOfCurrPath)) { // update paths based on predecessors
				if (currPath.contains(pred)) {
					continue;
				}

				List<Unit> newPath = new ArrayList<Unit>(currPath);
				newPath.add(pred);

				// if there are two preds, two new paths will be created
				workPaths.push(newPath);
				workUnits.push(pred);

				if (Thread.interrupted()) {
					try {
						throw new InterruptedException();
					} catch (InterruptedException e) {
						return;
					}
				}
			}

			if (Thread.interrupted()) {
				try {
					throw new InterruptedException();
				} catch (InterruptedException e) {
					return;
				}
			}
		}

		if (hitPathsLimit) {
//			logger.debug("Path limit hit for unit " + startingUnit + " in method " + method);
		}

		System.out.println(java.time.LocalDateTime.now() + "- Finished path extractions for: " + method.getSignature());

		Set<UnitPath> unitPaths = new HashSet<>();
		for (List<Unit> currPath : finalPaths) { // analyzed fully-determined relevant program paths
			if(Thread.currentThread().isInterrupted()) {
				// time is up
				return;
			}


			Map<String, List<Pair<String,String>>> attrConstraintsMap = new ConcurrentHashMap<String, List<Pair<String,String>>>();

			Set<String> currPathCond = new LinkedHashSet<String>();
			Set<String> currDecls = new LinkedHashSet<String>();
			List<String> locations = new ArrayList<>();
			List<String> constraintLocations = new ArrayList<>();
			List<String> locationsWithoutAttrs = new ArrayList<>();

			// perform intra-procedural analysis
			// updates currPathCond and currDecls
			Boolean isInterrupted = analyzeProgramPath(tabs, method, currPath, locations, constraintLocations, locationsWithoutAttrs, attrConstraintsMap);
			if (isInterrupted) {
				return;
			}
			unitPaths.add(new UnitPath(locations, constraintLocations, locationsWithoutAttrs, attrConstraintsMap));
		}

		for (UnitPath up : unitPaths) {
			List<String> locations = up.locations;
			List<String> constraintLocations = up.constraintLocations;
			List<String> locationsWithoutAttrs = up.locationsWithoutAttrs;
			Map<String, List<Pair<String,String>>> attrConstraintsMap = up.attrConstraintsMap;
			JSONObject IntentJson = new JSONObject();
			JSONArray locationsJson = new JSONArray();
			JSONArray constraintLocationsJson = new JSONArray();
			JSONArray locationsWithoutAttrsJson = new JSONArray();

			List<String> locationsFiltered = new ArrayList<>();
			List<String> constraintLocationsFiltered = new ArrayList<>();
			List<String> locationsWithoutAttrsFiltered = new ArrayList<>();
			String prev = null;
			for (String loc : locations) {
				if (prev != null && prev.equals(loc)) {
					continue;
				}
				locationsFiltered.add(loc);
				prev = loc;
			}
			prev = null;
			for (String loc : constraintLocations) {
				if (prev != null && prev.equals(loc)) {
					continue;
				}
				constraintLocationsFiltered.add(loc);
				prev = loc;
			}
			prev = null;
			for (String loc : locationsWithoutAttrs) {
				if (prev != null && prev.equals(loc)) {
					continue;
				}
				locationsWithoutAttrsFiltered.add(loc);
				prev = loc;
			}
			locationsJson.addAll(locationsFiltered);
			constraintLocationsJson.addAll(constraintLocationsFiltered);
			locationsWithoutAttrsJson.addAll(locationsWithoutAttrsFiltered);

			Map<String, Map<String,String>> attrConstraintsMapNor = new ConcurrentHashMap<>();  // key: attr, value: constraintkey,constraintvalue
			for (Map.Entry<String,List<Pair<String,String>>> entry : attrConstraintsMap.entrySet()) {
				String attr = entry.getKey();
				List<Pair<String,String>> constraints = entry.getValue();
				Pair attrNormalized = getNormalizedAttr(attr);
				String attrVal1 = (String) attrNormalized.getValue0();  // normalized attribute name
				String attrVal2 = (String) attrNormalized.getValue1();  // scheme or host for uri

				if (attrVal1.endsWith("-nullness")) {
					attrConstraintsMapNor.put(attrVal1, new HashMap<>());
				} else {
					Map<String,String> attrConstraints;
					if (attrConstraintsMapNor.containsKey(attrVal1)) {
						attrConstraints = attrConstraintsMapNor.get(attrVal1);
					} else {
						attrConstraints = new HashMap<>();
					}
					for (Pair<String,String> con : constraints) {
						attrConstraints.put(con.getValue0(), con.getValue1());
					}
					if (!attrVal2.equals("")) {
						// scheme or host
						attrConstraints.put(attrVal2, "");
					}
					attrConstraintsMapNor.put(attrVal1, attrConstraints);
				}
			}

			for (Map.Entry<String,Map<String,String>> entry : attrConstraintsMapNor.entrySet()) {
				String attr = entry.getKey();
				Map<String,String> constraints = entry.getValue();
				IntentJson.put("lineNumber", locationsJson);
				if (locationsWithoutAttrsJson.size() != 0) {
					IntentJson.put("lineNumberIncomplete", locationsWithoutAttrsJson);
				}
				if (constraintLocationsJson.size() != 0) {
					IntentJson.put("constraintsLineNumber", constraintLocationsJson);
				}
				if (attr.endsWith("-nullness")) {
					IntentJson.put(attr, "NotNull");
				} else {
					JSONObject constraintsJson = new JSONObject();
					for (Map.Entry<String,String> cEntry : constraints.entrySet()) {
						String constraintKey = cEntry.getKey();
						String constraintValue = cEntry.getValue();
						constraintsJson.put(constraintKey, constraintValue);
					}
					IntentJson.put(attr, constraintsJson);
				}
			}
			methodJson.add(IntentJson);
		}
	}

	private void handleSwitchStmt(int tabs, Unit currUnit, JLookupSwitchStmt switchStmt, Set<String> currPathCond,
								  Set<String> currDecls, List<Unit> currPath, SootMethod method, SimpleLocalDefs defs,
								  Map<Value, String> localSymbolMap, Map<String, Value> symbolLocalMap) {
		int index = 0;
		Value key = switchStmt.getKey();

		Unit keyDefUnit = getDefOfValInPath(key, currUnit, currPath, defs);
		String opExpr1 = createZ3Expr(key, currUnit, keyDefUnit, method, currDecls, tabs, localSymbolMap, symbolLocalMap);

		List<Integer> seen = new ArrayList<Integer>();
		for (Unit unit : switchStmt.getTargets()) {
			int val = switchStmt.getLookupValue(index);
			seen.add(val);
			if (currUnit.toString().equals(unit.toString())) {
				// create Z3 constraint
				String returnExpr = buildZ3CondExpr(tabs, opExpr1, Integer.toString(val), "==", null, symbolLocalMap);
				currPathCond.add(returnExpr);
				return;
			}
			index += 1;
		}
		// default value
		for (Integer curSeen : seen) {
			String returnExpr = buildZ3CondExpr(tabs, opExpr1, Integer.toString(curSeen), "!=", null, symbolLocalMap);
			currPathCond.add(returnExpr);
		}
		return;
	}

	public Pair<String,String> getNormalizedAttr(String attr) {
		Boolean isNull = false;
		if (attr.endsWith("-nullness")) {
			attr = attr.substring(0, attr.lastIndexOf("-nullness"));
			isNull = true;
		}
		if (attr.startsWith("getScheme")) {
			if (isNull) {
				return new Pair("uri-nullness", "scheme");
			} else {
				return new Pair("uri", "scheme");
			}
		} else if (attr.startsWith("getHost")) {
			if (isNull) {
				return new Pair("uri-nullness", "host");
			} else {
				return new Pair("uri", "host");
			}
		} else if (attr.startsWith("URItoString")) {
			if (isNull) {
				return new Pair("uri-nullness", "");
			} else {
				return new Pair("uri", "");
			}
		} else if (attr.startsWith("getData")) {
			if (isNull) {
				return new Pair("uri-nullness", "");
			} else {
				return new Pair("uri", "");
			}
		} else if (attr.startsWith("getDataString")) {
			if (isNull) {
				return new Pair("uri-nullness", "");
			} else {
				return new Pair("uri", "");
			}
		} else if (attr.startsWith("hasExtra")) {
			if (isNull) {
				return new Pair("extras-key-nullness", "");
			} else {
				return new Pair("extras-key", "");
			}
		} else if (Globals.bundleExtraDataValuesSet.contains(attr)) {
			if (isNull) {
				return new Pair("bundleExtras-value-nullness", "");
			} else {
				return new Pair("bundleExtras-value", "");
			}
		} else if (Globals.bundleExtraDataKeysSet.contains(attr)) {
			if (isNull) {
				return new Pair("bundleExtras-key-nullness", "");
			} else {
				return new Pair("bundleExtras-key", "");
			}
		} else if (Globals.categoryMethodsSet.contains(attr)) {
			if (isNull) {
				return new Pair("category-nullness", "");
			} else {
				return new Pair("category", "");
			}
		} else if (attr.startsWith("getAction")) {
			if (isNull) {
				return new Pair("action-nullness", "");
			} else {
				return new Pair("action", "");
			}
		} else if (Pattern.matches("get.Parcelable*Extra", attr) || Pattern.matches("get.Parcelable*Extra-nullness", attr)) {
			if (isNull) {
				return new Pair("serial-nullness", "");
			} else {
				return new Pair("serial", "");
			}
		} else if (Pattern.matches("get.Serializable*Extra", attr) || Pattern.matches("get.Serializable*Extra-nullness", attr)) {
			if (isNull) {
				return new Pair("serial-nullness", "");
			} else {
				return new Pair("serial", "");
			}
		} else if (Pattern.matches("get.*Extra", attr) || Pattern.matches("get.*Extra-nullness", attr)) {
			if (isNull) {
				return new Pair("extra-values-nullness", "");
			} else {
				return new Pair("extra-values", "");
			}
		} else if (attr.startsWith("getExtras")) {
			if (isNull) {
				return new Pair("getExtras-nullness", "");
			} else {
				return new Pair("getExtras", "");
			}
		}
		return null;
	}

	private void updateInterWorkStacks(Stack<Set<String>> workDecls, Stack<Set<String>> workPathConds, Stack<Integer> workUnitsIdx, Stack<List<Unit>> workSumPaths, Set<String> currPathCond, Set<String> currDecls, List<Unit> currSumPath, int currUnitIdx) {
		workPathConds.add(currPathCond);
		workDecls.add(currDecls);
		workUnitsIdx.push(currUnitIdx + 1);
		workSumPaths.add(currSumPath);
	}

	private void generateIntentExprForSumMethod(SootMethod method, SimpleLocalDefs defs, List<Unit> currIntraPath, Unit currUnitInPath, InvokeExpr ie, String condsCombined, Set<String> newAsserts) {
		// condsCombined are the interprocedural unitpath constraints from callee
		// condsCombined at least contain "fromIntent" so usage of intent exists

		// pFromIntent: regular expression for FromIntent
		Pattern pFromIntent = Pattern.compile("\\(\\s*assert\\s*\\(\\s*=\\s*\\(\\s*fromIntent\\s+(\\S+)\\)\\s+(\\S+)\\)\\)");
		// TODO: HASPARAMREF LOC
		// first match: intent object
		// second match: ParamRef object
		// third match: boolean
		Pattern pHasParamRef = Pattern.compile("\\(\\s*assert\\s*\\(\\s*=\\s*\\(\\s*hasParamRef\\s+(\\S+)\\s+(\\S+)\\)\\s+(\\S+)\\)\\)");

		// ParamRef establishes which method, method's parameter position the Intent belongs to
		// index is the argument index
		Pattern pPrIndex = Pattern.compile("\\(\\s*assert\\s*\\(\\s*=\\s*\\(\\s*index\\s+(\\S+)\\)\\s+(\\S+)\\s*\\)\\)");
		Pattern pPrType = Pattern.compile("\\(\\s*assert\\s*\\(\\s*=\\s*\\(\\s*type\\s+(\\S+)\\)\\s+\"(\\S+)\"\\s*\\)\\)");
		Pattern pPrMethod = Pattern.compile("\\(\\s*assert\\s*\\(\\s*=\\s*\\(\\s*method\\s+(\\S+)\\)\\s+\"(\\S+)\"\\s*\\)\\)");

		Matcher mFromIntent = pFromIntent.matcher(condsCombined);
		while (mFromIntent.find()) {
			String attrSymbol = mFromIntent.group(1);  // extra datum
			String intentSymbol = mFromIntent.group(2);

			Matcher mHasParamRef = pHasParamRef.matcher(condsCombined);
			while (mHasParamRef.find()) {
				String prIntentSymbol = mHasParamRef.group(1);
				String prSymbol = mHasParamRef.group(2);

				Matcher mPrIndex = pPrIndex.matcher(condsCombined);
				while (mPrIndex.find()) {
					String prIndexSymbol = mPrIndex.group(1);
					String index = mPrIndex.group(2);

					Matcher mPrType = pPrType.matcher(condsCombined);
					while (mPrType.find()) {
						String prTypeSymbol = mPrType.group(1);
						String type = mPrType.group(2);

						Matcher mPrMethod = pPrMethod.matcher(condsCombined);
						while (mPrMethod.find()) {
							String prMethodSymbol = mPrMethod.group(1);
							String prMethodName = mPrMethod.group(2);

							if (prIndexSymbol.equals(prTypeSymbol) && prTypeSymbol.equals(prMethodSymbol) && prMethodSymbol.equals(prSymbol)) {
								String invokedMethodName = ie.getMethod().getDeclaringClass().getName() + "." + ie.getMethod().getName();
								if (prMethodName.equals(invokedMethodName)) {
									Value arg = ie.getArg(Integer.parseInt(index));
									if (arg.getType().toString().equals(type)) {
										if (arg instanceof Local) {
											Local argLocal = (Local) arg;
											for (Unit argDef : defs.getDefsOfAt(argLocal, currUnitInPath)) {
												if (!isDefInPathAndLatest(currIntraPath, argDef, argLocal, currUnitInPath, defs)) {
													continue;
												}
												String callerIntentSymbol = createSymbol(arg, method, argDef);
												// the two intent objects are the same
												String assertArgEqualsParam = "(assert (= " + callerIntentSymbol + " " + prIntentSymbol + "))";
												newAsserts.add(assertArgEqualsParam);
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
	}

	private void generateIntentExprForSumMethodPayloadArg(String condsCombined, Set<String> newAsserts, String callerArgSymbol, int argIdx, InvokeExpr ie) {

		// this is per tainted argument in a callee path

		Pattern pHasParamRef = Pattern.compile("\\(\\s*assert\\s*\\(\\s*=\\s*\\(\\s*isParamRef\\s+(\\S+)\\s+(\\S+)\\)\\s+(\\S+)\\)\\)");

		// ParamRef establishes which method, method's parameter position the Intent belongs to
		// index is the argument index
		Pattern pPrIndex = Pattern.compile("\\(\\s*assert\\s*\\(\\s*=\\s*\\(\\s*index\\s+(\\S+)\\)\\s+(\\S+)\\s*\\)\\)");
		Pattern pPrType = Pattern.compile("\\(\\s*assert\\s*\\(\\s*=\\s*\\(\\s*type\\s+(\\S+)\\)\\s+\"(\\S+)\"\\s*\\)\\)");
		Pattern pPrMethod = Pattern.compile("\\(\\s*assert\\s*\\(\\s*=\\s*\\(\\s*method\\s+(\\S+)\\)\\s+\"(\\S+)\"\\s*\\)\\)");

		Matcher mHasParamRef = pHasParamRef.matcher(condsCombined);
		while (mHasParamRef.find()) {
			String prCalleeSymbol = mHasParamRef.group(1);
			String prSymbol = mHasParamRef.group(2);

			Matcher mPrIndex = pPrIndex.matcher(condsCombined);
			while (mPrIndex.find()) {
				String prIndexSymbol = mPrIndex.group(1);
				String index = mPrIndex.group(2);

				Matcher mPrType = pPrType.matcher(condsCombined);
				while (mPrType.find()) {
					String prTypeSymbol = mPrType.group(1);
					String type = mPrType.group(2);

					Matcher mPrMethod = pPrMethod.matcher(condsCombined);
					while (mPrMethod.find()) {
						String prMethodSymbol = mPrMethod.group(1);
						String prMethodName = mPrMethod.group(2);

						if (prIndexSymbol.equals(prTypeSymbol) && prTypeSymbol.equals(prMethodSymbol) && prMethodSymbol.equals(prSymbol)) {
							String invokedMethodName = ie.getMethod().getDeclaringClass().getName() + "." + ie.getMethod().getName();
							if (prMethodName.equals(invokedMethodName)) {
								if (index.equals(String.valueOf(argIdx))) {
									// constraints in callee contains tainted arg value
									String assertArgEqualsParam = "(assert (= " + callerArgSymbol + " " + prCalleeSymbol + "))";
									newAsserts.add(assertArgEqualsParam);
								}
							}
						}
					}
				}
			}
		}

		/*
		Matcher mPrIndex = pPrIndex.matcher(condsCombined);
		while (mPrIndex.find()) {
			String prIndexSymbol = mPrIndex.group(1);
			String index = mPrIndex.group(2);

			Matcher mHasParamRef = pHasParamRef.matcher(condsCombined);
			while (mHasParamRef.find()) {
				String prCalleeSymbol = mHasParamRef.group(1);  // non pr symbol
				String prSymbol = mHasParamRef.group(2);  // pr symbol

				if (index.equals(String.valueOf(argIdx))) {
					// constraints in callee contains tainted arg value
					String assertArgEqualsParam = "(assert (= " + callerArgSymbol + " " + prCalleeSymbol + "))";
					newAsserts.add(assertArgEqualsParam);
				}
			}
		}
		 */
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

	protected void runSolvingPhase(int tabs, int fpIdx, int sumUpIdx, SootMethod method, String currClassName, Unit startingUnit,
									  List<Unit> currPath, Set<String> interPathCond,
									  Set<String> interDecls, Integer analysisMode, Boolean isApplyingSummary, Boolean isRootMethod,
									  Map<SootMethod, Map<Unit, Set<UnitPath>>> methodSum) {

		storeSummary(method, startingUnit, currPath, interPathCond, interDecls, isApplyingSummary, methodSum);
		if (!isRootMethod) {
			return;
		}
		/*
		this.pathsAnalyzedCount++;
		Pair<Intent, Boolean> soln = findSolutionForPath(fpIdx, sumUpIdx, interPathCond, method, interDecls, currPath,
				startingUnit, analysisMode);
		boolean feasible = soln.getValue1();
		Intent genIntent = soln.getValue0();

		if (feasible) {
			storeGeneratedData(currClassName, genIntent);
		}
		 */
		// write to annotated json

	}

	/**
	 * add interprocedural constraints to methodSummaries
	 */
	protected void storeSummary(SootMethod method,
								Unit startingUnit,
								List<Unit> currPath,
								Set<String> interPathCond,
								Set<String> interDecls,
								Boolean isApplyingSummary,
								Map<SootMethod, Map<Unit, Set<UnitPath>>> methodSummaries) {
		Map<Unit, Set<UnitPath>> unitSum;
		if (!isApplyingSummary) {
			// otherwise, adding redundant path constraints
			return;
		}
		if (methodSummaries.containsKey(method)) {
			unitSum = methodSummaries.get(method);
		} else {
			unitSum = new ConcurrentHashMap<Unit, Set<UnitPath>>();
		}

		Set<UnitPath> unitPaths = null;
		if (unitSum.containsKey(startingUnit)) {
			unitPaths = unitSum.get(startingUnit);
		} else {
			unitPaths = new HashSet<UnitPath>();
		}
		//UnitPath up = new UnitPath(interPathCond, interDecls, currPath);
		//unitPaths.add(up);
		//unitSum.put(startingUnit, unitPaths);
		//methodSummaries.put(method, unitSum);
	}

	protected synchronized void storeGeneratedData(String currClassName, Intent genIntent) {
		try {
			if (!wasPreviouslyWrittenIntentData(currClassName, genIntent)) {
				storeGeneratedDataToWriter(currClassName, genIntent);
			}

		} catch (RuntimeException e) {
			// will throw Exception for int extra intent
		}
	}

	public boolean isNullComparison(IfStmt ifStmt) {
		List<ValueBox> values = ifStmt.getCondition().getUseBoxes();
		for (ValueBox v : values) {
			if (v.getValue() instanceof NullConstant) {
				return true;
			}
		}
		return false;
	}

	private Boolean analyzeProgramPath(int tabs, SootMethod method, List<Unit> currPath, List<String> locations, List<String> constraintLocations,
									   List<String> locationsWithoutAttrs, Map<String, List<Pair<String,String>>> attrContraintsMap) {

		// extract backward. Traverse forward
		Collections.reverse(currPath);
		List<Unit> currPathAsList = new ArrayList<Unit>(currPath);
		for (int i = 0; i < currPathAsList.size(); i++) {
			if(Thread.currentThread().isInterrupted()) {
				// time is up
				return true;
			}
			// iterating each instruction in path currPath
			Unit currUnitInPath = currPathAsList.get(i); // current unit under analysis for current path
			Unit succUnit = null; // successor of currUnitINPath
			if (i + 1 < currPathAsList.size()) {
				succUnit = currPathAsList.get(i + 1);
			}
			UnitGraph unitGraph = null;
			SimpleLocalDefs defs = null;
			if (method.hasActiveBody()) {
				unitGraph = new ExceptionalUnitGraph(method.getActiveBody());
				synchronized (method) {
					defs = new SimpleLocalDefs(unitGraph);
				}
			} else {
				throw new RuntimeException("method has no active body, which shouldn't happen: " + method.getName());
			}

			try {
				Stmt currStmtInPath = (Stmt) currUnitInPath;
				Set<String> currExprs = new LinkedHashSet<String>();
				int lineNum = currUnitInPath.getJavaSourceStartLineNumber();
				if (currUnitInPath instanceof IfStmt) {
					if (currUnitInPath.hasTag("StringTag")) {
						Tag t = currUnitInPath.getTag("StringTag");
						String tagVal = String.valueOf(t);
						if (tagVal.startsWith("isIntentDependent")) {
							if (tagVal.contains(":")) {
								// contains attribute
								String attr = tagVal.split(":")[1];
								IfStmt currIfStmt = (IfStmt) currUnitInPath;
								if (isNullComparison(currIfStmt)) {
									// null comparison
									locations.add(lineNum + ":" + attr+"-nullness");
									if (!attrContraintsMap.containsKey(attr+"-nullness")) {
										attrContraintsMap.put(attr+"-nullness", new ArrayList());
									}
								} else {
									locations.add(lineNum + ":" + attr);
									if (!attrContraintsMap.containsKey(attr)) {
										attrContraintsMap.put(attr, new ArrayList());
									}
								}
							} else {
								// does not contain attribute
								locations.add(lineNum+":?");
								locationsWithoutAttrs.add(String.valueOf(lineNum));
							}
						}
					}
				} else if (currStmtInPath.containsInvokeExpr()) {
					InvokeExpr ie = Utils.getInvokeExpr(currStmtInPath);
					SootMethod calledMethod = ie.getMethod();
					String calledMethodClass = calledMethod.getDeclaringClass().getName();
					if (Globals.stringOpsSet.contains(calledMethod.getName()) && calledMethodClass.equals("java.lang.String")) {
						List<Value> calleeArgs = ie.getArgs();
						if (currUnitInPath.hasTag("StringTag")) {
							Tag t = currUnitInPath.getTag("StringTag");
							String tagVal = String.valueOf(t);
							if (tagVal.startsWith("isIntentDependent")) {
								if (tagVal.contains(":")) {
									// contains attribute
									String attr = tagVal.split(":")[1];
									constraintLocations.add(lineNum+":"+attr+"<c>"+calledMethod.getName());
									List<Pair<String, String>> constraints;
									if (attrContraintsMap.containsKey(attr)) {
										constraints = attrContraintsMap.get(attr);
									} else {
										constraints = new ArrayList<>();
									}
									if (calleeArgs.size() == 1) {
										Value arg = calleeArgs.get(0);
										String argStr = Utils.getConstant(arg, defs, currUnitInPath);
										if (argStr != null) {
											constraints.add(new Pair(calledMethod.getName(), argStr));
										} else {
											constraints.add(new Pair(calledMethod.getName(), null));
										}
										attrContraintsMap.put(attr, constraints);
									}
								}
							}
						}
					}
				}
			} catch (NullPointerException e) {
				e.printStackTrace();
			}
		}
		return false;
	}

	private void handleAliases(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls,
							   SimpleLocalDefs defs, AssignStmt currStmtInPath, Map<Value, String> localSymbolMap,
							   Map<String, Value> symbolLocalMap, Map<String, Unit> fieldUnitMap) {

		// generate constraints in case of aliasing / or taint transfer
		// ex:
		//    $r3 = staticinvoke <java.lang.Integer: java.lang.Integer valueOf(int)>($i0)
		//    $i0 = virtualinvoke $r3.<java.lang.Integer: int intValue()>()
		Value defValue = currStmtInPath.getLeftOp();
		Value rhs = currStmtInPath.getRightOp();
		if (rhs instanceof InvokeExpr) {
			InvokeExpr ie = (InvokeExpr)currStmtInPath.getRightOp();
			if (ie instanceof InstanceInvokeExpr) {
				// only InstanceInvokeExpr type has a callee base
				InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
				Value calleeBase = iie.getBase();
				// handle both string and integer base
				// EX: $i0 = virtualinvoke $r3.<java.lang.Integer: int intValue()>()
				//     where $r3 is data dependent on Intent
				String calleeDeclaringClass = ie.getMethod().getDeclaringClass().getName();
				if (calleeDeclaringClass.startsWith("java.lang.Integer")) {
					if (ie.getMethod().getName().equals("intValue")) {
						if (localSymbolMap.containsKey(calleeBase)) {
							String calleeBaseSymbol = localSymbolMap.get(calleeBase);
							// create constraints for statement
							// lhs is same z3 variable as arg in rhs
							String aliasSymbol = createSymbol(defValue, method, currStmtInPath);
							Value aliasValue = symbolLocalMap.get(aliasSymbol);
							if (aliasValue == null) {
								// new symbol for defValue, could be a redefinition of defValue
								localSymbolMap.put((Local) defValue, aliasSymbol);
								symbolLocalMap.put(aliasSymbol, (Local) defValue);
								String aliasDecl;
								if (calleeDeclaringClass.endsWith("String")) {
									aliasDecl = "(declare-const " + aliasSymbol + " String)";
								} else {
									aliasDecl = "(declare-const " + aliasSymbol + " Int)";
								}
								currDecls.add(aliasDecl);
							}
							String aliasConstraint = "(assert (= " + aliasSymbol + " " + calleeBaseSymbol + "))";
							currPathCond.add(aliasConstraint);
						}
					}
				}
			} else if (rhs instanceof StaticInvokeExpr) {
				StaticInvokeExpr sie = (StaticInvokeExpr) rhs;
				SootMethod calleeMethod = sie.getMethod();
				if (sie.getMethod().getDeclaringClass().getName().equals("java.lang.Integer") && calleeMethod.getName().equals("valueOf")) {
					List<Value> args = sie.getArgs();
					if (args.size() == 1) {
						Value arg = args.get(0);
						// primitive type such as Integer is represented as two statements:
						// $i0 = virtualinvoke $r2.<android.content.Intent: int getIntExtra(java.lang.String,int)>("idata", 0)
						// $r4 = staticinvoke <java.lang.Integer: java.lang.Integer valueOf(int)>($i0)
						// GEN
						if (arg instanceof JimpleLocal) {
							Local argLocal = (Local) arg;
							for (Unit argDef : defs.getDefsOfAt(argLocal, currStmtInPath)) {
								if (!isDefInPathAndLatest(currPath, argDef, argLocal, currStmtInPath, defs)) {
									continue;
								}
								if (localSymbolMap.containsKey(arg) && defValue instanceof Local) {
									String argSymbol = localSymbolMap.get(arg);
									// create constraints for statement
									// lhs is same z3 variable as arg in rhs
									String aliasSymbol = createSymbol(defValue, method, currStmtInPath);
									Value aliasValue = symbolLocalMap.get(aliasSymbol);
									if (aliasValue == null) {
										localSymbolMap.put((Local)defValue, aliasSymbol);
										symbolLocalMap.put(aliasSymbol, (Local)defValue);
										//symbolLocalMap.put(intentSymbol, intentLocal);
										String aliasDecl = "(declare-const " + aliasSymbol + " Int)";
										currDecls.add(aliasDecl);
									}
									String aliasConstraint = "(assert (= " + aliasSymbol + " " + argSymbol + "))";
									currPathCond.add(aliasConstraint);
								}
							}
						}
					}
				}
			}
		} else if (currStmtInPath instanceof AssignStmt) {
			Value lhs = currStmtInPath.getLeftOp();
			if (isVar(lhs) && isVar(rhs)){
				// create constraint to transfer taint
				// create lhs symbol
				String lhsSymbol = createSymbol(lhs, method, currStmtInPath);
				Value lhsValue = symbolLocalMap.get(lhsSymbol);
				if (lhsValue == null) {
					localSymbolMap.put((Value)lhs, lhsSymbol);
					symbolLocalMap.put(lhsSymbol, (Value)lhs);
					if (lhs instanceof FieldRef) {
						fieldUnitMap.put(lhs.toString(), currStmtInPath);
					}
					String lhsType = getZ3Type(lhs.getType());
					String aliasDecl = "(declare-const " + lhsSymbol + " " + lhsType + ")";
					currDecls.add(aliasDecl);
				}
				// create rhs symbol
				// can follow use-def chain only for Local
				if (rhs instanceof Local) {
					Local rhsLocal = (Local) rhs;
					for (Unit rhsDef : defs.getDefsOfAt(rhsLocal, currStmtInPath)) {
						if (!isDefInPathAndLatest(currPath, rhsDef, rhsLocal, currStmtInPath, defs)) {
							continue;
						}
						if (currPath.contains(rhsDef)) {
							String rhsSymbol = createSymbol(rhsLocal, method, rhsDef);
							Value rhsValue = symbolLocalMap.get(rhsSymbol);
							if (rhsValue == null) {
								localSymbolMap.put((Value)rhsLocal, rhsSymbol);
								symbolLocalMap.put(rhsSymbol, (Value)rhsLocal);
								String rhsType = getZ3Type(rhs.getType());
								String aliasDecl = "(declare-const " + rhsSymbol + " " + rhsType + ")";
								currDecls.add(aliasDecl);
							}
							String aliasConstraint = "(assert (= " + lhsSymbol + " " + rhsSymbol + "))";
							currPathCond.add(aliasConstraint);
							break;
						}
					}
				} else if (rhs instanceof FieldRef) {
					// TODO: make pass in FieldRef rhs def instead of currStmtInPath to createSymbol
					Unit rhsDef = currStmtInPath;
					if (fieldUnitMap.containsKey(rhs.toString())) {
						rhsDef = fieldUnitMap.get(rhs.toString());
					}
					String rhsSymbol = createSymbol(rhs, method, rhsDef);
					Value rhsValue = symbolLocalMap.get(rhsSymbol);
					if (rhsValue == null) {
						localSymbolMap.put((Value)rhs, rhsSymbol);
						symbolLocalMap.put(rhsSymbol, (Value)rhs);
						String rhsType = getZ3Type(rhs.getType());
						String aliasDecl = "(declare-const " + rhsSymbol + " " + rhsType + ")";
						currDecls.add(aliasDecl);
					}
					String aliasConstraint = "(assert (= " + lhsSymbol + " " + rhsSymbol + "))";
					currPathCond.add(aliasConstraint);
				}
			}
		}
	}

	public Boolean isVar(Value val) {
		if (val instanceof FieldRef || val instanceof Local) {
			return true;
		}
		return false;
	}

	private void handleGetExtraOfIntent(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls,
										SimpleLocalDefs defs, DefinitionStmt currStmtInPath, Map<Value, String> localSymbolMap, Map<String, Value> symbolLocalMap) {
		DefinitionStmt defStmt = currStmtInPath;
		if (defStmt.containsInvokeExpr() && defStmt.getInvokeExpr() instanceof InstanceInvokeExpr) {
			InstanceInvokeExpr ie = (InstanceInvokeExpr) defStmt.getInvokeExpr();
			if (Pattern.matches("get.*Extra", ie.getMethod().getName())) {
				if (ie.getMethod().getDeclaringClass().toString().equals("android.content.Intent")) {
					Pair<Set<String>, Set<String>> exprPair = buildGetExtraData(defStmt, defs, ie, method, currPath, localSymbolMap, symbolLocalMap);
					currDecls.addAll(exprPair.getValue0());
					currPathCond.addAll(exprPair.getValue1());
				}
			}
			if (Pattern.matches("get.*", ie.getMethod().getName())) {
				if (ie.getMethod().getDeclaringClass().toString().equals("android.os.Bundle")) {
					Pair<Set<String>, Set<String>> exprPair = buildGetBundleData(defStmt, defs, ie, method, currPath,
							localSymbolMap, symbolLocalMap);
					currDecls.addAll(exprPair.getValue0());
					currPathCond.addAll(exprPair.getValue1());
				} else if (ie.getMethod().getDeclaringClass().toString().equals("android.os.BaseBundle")) {
					Pair<Set<String>, Set<String>> exprPair = buildGetBundleData(defStmt, defs, ie, method, currPath,
							localSymbolMap, symbolLocalMap);
					currDecls.addAll(exprPair.getValue0());
					currPathCond.addAll(exprPair.getValue1());
				} else if (ie.getMethod().getDeclaringClass().toString().equals("android.os.PersistableBundle")) {
					Pair<Set<String>, Set<String>> exprPair = buildGetBundleData(defStmt, defs, ie, method, currPath,
							localSymbolMap, symbolLocalMap);
					currDecls.addAll(exprPair.getValue0());
					currPathCond.addAll(exprPair.getValue1());
				}
			}
		}
	}


	private void handleToStringOfIntent(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls,
									   SimpleLocalDefs defs, Stmt currStmtInPath, Map<Value, String> localSymbolMap, Map<String, Value> symbolLocalMap) {
		DefinitionStmt currDefStmt = (DefinitionStmt) currStmtInPath;
		InvokeExpr ie = currStmtInPath.getInvokeExpr();
		if (ie.getMethod().getName().equals("toString")) {
			if (ie.getMethod().getDeclaringClass().getName().equals("android.net.Uri")) {
				if (ie instanceof InstanceInvokeExpr) {
					InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
					if (currDefStmt.getLeftOp() instanceof Local) {
						Local leftLocal = (Local) currDefStmt.getLeftOp();
						if (iie.getBase() instanceof Local) {
							Local intentLocal = (Local) iie.getBase();
							for (Unit intentDef : defs.getDefsOfAt(intentLocal, currDefStmt)) {
								/*if (!currPath.contains(intentDef)) {
									continue;
								}*/
								if (!isDefInPathAndLatest(currPath, intentDef, intentLocal, currDefStmt, defs)) {
									continue;
								}
								if (currPath.contains(intentDef)) {
									String intentSymbol = localSymbolMap.get(intentLocal);
									if (intentSymbol == null) {
										intentSymbol = createSymbol(intentLocal, method, intentDef);
										localSymbolMap.put(intentLocal, intentSymbol);
										symbolLocalMap.put(intentSymbol, intentLocal);
										String intentDecl = "(declare-const " + intentSymbol + " Object)";
										currDecls.add(intentDecl);
									}

									String dataSymbol = createSymbol(currDefStmt.getLeftOp(), method, currStmtInPath);
									String storedDataSymbol = localSymbolMap.get((Local)currDefStmt.getLeftOp());
									if (storedDataSymbol == null || !storedDataSymbol.equals(dataSymbol)) {
										localSymbolMap.put((Local)currDefStmt.getLeftOp(), dataSymbol);
										symbolLocalMap.put(dataSymbol, (Local)currDefStmt.getLeftOp());
										String dataDecl = "(declare-const " + dataSymbol + " String)";
										currDecls.add(dataDecl);
									}

									String getDataAssert = "(assert (= (getData " + intentSymbol + ") " + dataSymbol + "))";
									String newFromIntent = "(assert (= (fromIntent " + dataSymbol + ") " + intentSymbol + "))";
									currPathCond.add(getDataAssert);
									currPathCond.add(newFromIntent);

									buildParamRefExpressions(method, currPath, currPathCond, currDecls, intentDef,
											intentSymbol, localSymbolMap, symbolLocalMap);
								}
							}
						}
					}
				}
			}
		}
	}

	private void handleGetDataOfIntent(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls,
										 SimpleLocalDefs defs, Stmt currStmtInPath, Map<Value, String> localSymbolMap, Map<String, Value> symbolLocalMap) {
		DefinitionStmt currDefStmt = (DefinitionStmt) currStmtInPath;
		InvokeExpr ie = currStmtInPath.getInvokeExpr();
		if (ie.getMethod().getName().equals("getDataString")) {
			if (ie.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
				if (ie instanceof InstanceInvokeExpr) {
					InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
					if (currDefStmt.getLeftOp() instanceof Local) {
						Local leftLocal = (Local) currDefStmt.getLeftOp();
						if (iie.getBase() instanceof Local) {
							Local intentLocal = (Local) iie.getBase();
							for (Unit intentDef : defs.getDefsOfAt(intentLocal, currDefStmt)) {
								/*if (!currPath.contains(intentDef)) {
									continue;
								}*/
								if (!isDefInPathAndLatest(currPath, intentDef, intentLocal, currDefStmt, defs)) {
									continue;
								}
								if (currPath.contains(intentDef)) {
									String intentSymbol = localSymbolMap.get(intentLocal);
									if (intentSymbol == null) {
										intentSymbol = createSymbol(intentLocal, method, intentDef);
										localSymbolMap.put(intentLocal, intentSymbol);
										symbolLocalMap.put(intentSymbol, intentLocal);
										String intentDecl = "(declare-const " + intentSymbol + " Object)";
										currDecls.add(intentDecl);
									}

									String dataSymbol = createSymbol(currDefStmt.getLeftOp(), method, currStmtInPath);
									String storedDataSymbol = localSymbolMap.get((Local)currDefStmt.getLeftOp());
									if (storedDataSymbol == null || !storedDataSymbol.equals(dataSymbol)) {
										localSymbolMap.put((Local)currDefStmt.getLeftOp(), dataSymbol);
										symbolLocalMap.put(dataSymbol, (Local)currDefStmt.getLeftOp());
										String dataDecl = "(declare-const " + dataSymbol + " String)";
										currDecls.add(dataDecl);
									}

									String getDataAssert = "(assert (= (getData " + intentSymbol + ") " + dataSymbol + "))";
									String newFromIntent = "(assert (= (fromIntent " + dataSymbol + ") " + intentSymbol + "))";
									currPathCond.add(getDataAssert);
									currPathCond.add(newFromIntent);

									buildParamRefExpressions(method, currPath, currPathCond, currDecls, intentDef,
											intentSymbol, localSymbolMap, symbolLocalMap);
								}
							}
						}
					}
				}
			}
		}
	}

	private void handleGetHostOfIntent(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls,
										 SimpleLocalDefs defs, Stmt currStmtInPath, Map<Value, String> localSymbolMap, Map<String, Value> symbolLocalMap) {
		DefinitionStmt currDefStmt = (DefinitionStmt) currStmtInPath;
		InvokeExpr ie = currStmtInPath.getInvokeExpr();
		if (ie.getMethod().getName().equals("getHost")) {
			if (ie.getMethod().getDeclaringClass().getName().equals("android.net.Uri")) {
				if (ie instanceof InstanceInvokeExpr) {
					InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
					if (currDefStmt.getLeftOp() instanceof Local) {
						Local leftLocal = (Local) currDefStmt.getLeftOp();
						if (iie.getBase() instanceof Local) {
							Local intentLocal = (Local) iie.getBase();
							for (Unit intentDef : defs.getDefsOfAt(intentLocal, currDefStmt)) {
								/*if (!currPath.contains(intentDef)) {
									continue;
								}*/
								if (!isDefInPathAndLatest(currPath, intentDef, intentLocal, currDefStmt, defs)) {
									continue;
								}
								if (currPath.contains(intentDef)) {
									String intentSymbol = localSymbolMap.get(intentLocal);
									if (intentSymbol == null) {
										intentSymbol = createSymbol(intentLocal, method, intentDef);
										localSymbolMap.put(intentLocal, intentSymbol);
										symbolLocalMap.put(intentSymbol, intentLocal);
										String intentDecl = "(declare-const " + intentSymbol + " Object)";
										currDecls.add(intentDecl);
									}

									String hostSymbol = createSymbol(currDefStmt.getLeftOp(), method, currStmtInPath);
									String storedHostSymbol = localSymbolMap.get((Local)currDefStmt.getLeftOp());
									if (storedHostSymbol == null || !storedHostSymbol.equals(hostSymbol)) {
										localSymbolMap.put((Local)currDefStmt.getLeftOp(), hostSymbol);
										symbolLocalMap.put(hostSymbol, (Local)currDefStmt.getLeftOp());
										String hostDecl = "(declare-const " + hostSymbol + " String)";
										currDecls.add(hostDecl);
									}

									String getHostAssert = "(assert (= (getHost " + intentSymbol + ") " + hostSymbol + "))";
									String newFromIntent = "(assert (= (fromIntent " + hostSymbol + ") " + intentSymbol + "))";
									currPathCond.add(getHostAssert);
									currPathCond.add(newFromIntent);

									buildParamRefExpressions(method, currPath, currPathCond, currDecls, intentDef,
											intentSymbol, localSymbolMap, symbolLocalMap);
								}
							}
						}
					}
				}
			}
		}
	}

	private void handleGetSchemeOfIntent(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls,
										 SimpleLocalDefs defs, Stmt currStmtInPath, Map<Value, String> localSymbolMap, Map<String, Value> symbolLocalMap) {
		DefinitionStmt currDefStmt = (DefinitionStmt) currStmtInPath;
		InvokeExpr ie = currStmtInPath.getInvokeExpr();
		if (ie.getMethod().getName().equals("getScheme")) {
			if (ie.getMethod().getDeclaringClass().getName().equals("android.net.Uri")) {
				if (ie instanceof InstanceInvokeExpr) {
					InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
					if (currDefStmt.getLeftOp() instanceof Local) {
						Local leftLocal = (Local) currDefStmt.getLeftOp();
						if (iie.getBase() instanceof Local) {
							Local intentLocal = (Local) iie.getBase();
							for (Unit intentDef : defs.getDefsOfAt(intentLocal, currDefStmt)) {
								/*if (!currPath.contains(intentDef)) {
									continue;
								}*/
								if (!isDefInPathAndLatest(currPath, intentDef, intentLocal, currDefStmt, defs)) {
									continue;
								}
								if (currPath.contains(intentDef)) {
									String intentSymbol = localSymbolMap.get(intentLocal);
									if (intentSymbol == null) {
										intentSymbol = createSymbol(intentLocal, method, intentDef);
										localSymbolMap.put(intentLocal, intentSymbol);
										symbolLocalMap.put(intentSymbol, intentLocal);
										String intentDecl = "(declare-const " + intentSymbol + " Object)";
										currDecls.add(intentDecl);
									}

									String schemeSymbol = createSymbol(currDefStmt.getLeftOp(), method, currStmtInPath);
									String storedSchemeSymbol = localSymbolMap.get((Local)currDefStmt.getLeftOp());
									if (storedSchemeSymbol == null || !storedSchemeSymbol.equals(schemeSymbol)) {
										localSymbolMap.put((Local)currDefStmt.getLeftOp(), schemeSymbol);
										symbolLocalMap.put(schemeSymbol, (Local)currDefStmt.getLeftOp());
										String schemeDecl = "(declare-const " + schemeSymbol + " String)";
										currDecls.add(schemeDecl);
									}

									String getSchemeAssert = "(assert (= (getScheme " + intentSymbol + ") " + schemeSymbol + "))";
									String newFromIntent = "(assert (= (fromIntent " + schemeSymbol + ") " + intentSymbol + "))";
									currPathCond.add(getSchemeAssert);
									currPathCond.add(newFromIntent);

									buildParamRefExpressions(method, currPath, currPathCond, currDecls, intentDef,
											intentSymbol, localSymbolMap, symbolLocalMap);
								}
							}
						}
					}
				}
			}
		}
	}

	private void handleGetActionOfIntent(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls,
										 SimpleLocalDefs defs, Stmt currStmtInPath, Map<Value, String> localSymbolMap, Map<String, Value> symbolLocalMap) {
		DefinitionStmt currDefStmt = (DefinitionStmt) currStmtInPath;
		InvokeExpr ie = currStmtInPath.getInvokeExpr();
		if (ie.getMethod().getName().equals("getAction")) {
			if (ie.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
				if (ie instanceof InstanceInvokeExpr) {
					InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
					if (currDefStmt.getLeftOp() instanceof Local) {
						Local leftLocal = (Local) currDefStmt.getLeftOp();
						if (iie.getBase() instanceof Local) {
							Local intentLocal = (Local) iie.getBase();
							for (Unit intentDef : defs.getDefsOfAt(intentLocal, currDefStmt)) {
								/*if (!currPath.contains(intentDef)) {
									continue;
								}*/
								if (!isDefInPathAndLatest(currPath, intentDef, intentLocal, currDefStmt, defs)) {
									continue;
								}
								if (currPath.contains(intentDef)) {
									String intentSymbol = localSymbolMap.get(intentLocal);
									if (intentSymbol == null) {
										intentSymbol = createSymbol(intentLocal, method, intentDef);
										localSymbolMap.put(intentLocal, intentSymbol);
										symbolLocalMap.put(intentSymbol, intentLocal);
										String intentDecl = "(declare-const " + intentSymbol + " Object)";
										currDecls.add(intentDecl);
									}

									String actionRefSymbol = createSymbol(currDefStmt.getLeftOp(), method, currStmtInPath);
									String storedActionRefSymbol = localSymbolMap.get((Local)currDefStmt.getLeftOp());
									if (storedActionRefSymbol == null || !storedActionRefSymbol.equals(actionRefSymbol)) {
										//actionRefSymbol = createSymbol(currDefStmt.getLeftOp(), method, currStmtInPath);
										localSymbolMap.put((Local)currDefStmt.getLeftOp(), actionRefSymbol);
										symbolLocalMap.put(actionRefSymbol, (Local)currDefStmt.getLeftOp());
										String actionRefDecl = "(declare-const " + actionRefSymbol + " String)";
										currDecls.add(actionRefDecl);
									}

									String getActionAssert = "(assert (= (getAction " + intentSymbol + ") " + actionRefSymbol + "))";
									String newFromIntent = "(assert (= (fromIntent " + actionRefSymbol + ") " + intentSymbol + "))";
									currPathCond.add(getActionAssert);
									currPathCond.add(newFromIntent);

									buildParamRefExpressions(method, currPath, currPathCond, currDecls, intentDef,
											intentSymbol, localSymbolMap, symbolLocalMap);
								}
							}
						}
					}
				}
			}
		}
	}

	private void buildParamRefExpressions(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls,
										  Unit intentDef, String intentSymbol, Map<Value, String> localSymbolMap, Map<String, Value> symbolLocalMap) {
		if (intentDef instanceof DefinitionStmt) {
			DefinitionStmt defStmt = (DefinitionStmt) intentDef;
			if (!currPath.contains(defStmt)) {
				return;
			}
			if (defStmt.getRightOp() instanceof ParameterRef) {
				ParameterRef pr = (ParameterRef) defStmt.getRightOp();

				String prSymbol = createParamRefSymbol(defStmt.getLeftOp(), pr.getIndex(), method, defStmt);
				currDecls.add("(declare-const " + prSymbol + " ParamRef)");
				currPathCond.add("(assert ( = (index " + prSymbol + ") " + pr.getIndex() + "))");
				currPathCond.add("(assert ( = (type " + prSymbol + ") \"" + pr.getType() + "\"))");
				currPathCond.add("(assert ( = (method " + prSymbol + ") \"" + method.getDeclaringClass().getName() + "." + method.getName() + "\"))");
				// TODO: HASPARAMREF LOC
				if (intentSymbol != null) {
					currPathCond.add("(assert (= (hasParamRef " + intentSymbol + " " + prSymbol + ") true))");
				}

				if (defStmt.getLeftOp() instanceof Local) {
					Local defLocal = (Local) defStmt.getLeftOp();
					String prNormalSymbol = createSymbol(defStmt.getLeftOp(), method, defStmt);
					String prNormalType = getZ3Type(defLocal.getType());
					symbolLocalMap.put(prNormalSymbol, defLocal);
					localSymbolMap.put(defLocal, prNormalSymbol);
					currDecls.add("(declare-const " + prNormalSymbol + " " + prNormalType + ")");
					String prConstraint;
					//prConstraint = "(assert (= (isParamRef " + prNormalSymbol + " " + prSymbol + ") true))";
					if (intentSymbol != null) {
						prConstraint = "(assert (= (isParamRef " + intentSymbol + " " + prSymbol + ") true))";
					} else {
						prConstraint = "(assert (= (isParamRef " + prNormalSymbol + " " + prSymbol + ") true))";
					}
					currPathCond.add(prConstraint);
				}

			}
		}
	}

	private Pair<Set<String>, Set<String>> buildGetExtraData(Unit currUnit, SimpleLocalDefs defs, InstanceInvokeExpr ie,
															 SootMethod method, List<Unit> currPath, Map<Value, String> localSymbolMap,
															 Map<String, Value> symbolLocalMap) {

		Set<String> newDecls = new LinkedHashSet<String>();
		Set<String> newAsserts = new LinkedHashSet<String>();
		Value arg1 = ie.getArg(0);
		Value arg2 = null;
		if (ie.getArgCount() > 1) {
			arg2 = ie.getArg(1);
		}

		String extraType = null;

		if (arg2 != null) {
			extraType = arg2.getType().toString();
		} else {
			extraType = ie.getMethod().getReturnType().toString();
		}

		String arg2Str = "unk";
		if (arg2 != null) {
			arg2Str = arg2.toString();
		}

		if (!(arg1 instanceof StringConstant)) {
			String maybeStr = getIeArg(ie, defs, currUnit);
			if (maybeStr != null) {
				arg1 = StringConstant.v(maybeStr);
			}
		}

		if (arg1 instanceof StringConstant) {
			StringConstant keyStrConst = (StringConstant) arg1;
			if (ie.getBase() instanceof Local) {
				Local intentLocal = (Local) ie.getBase();
				for (Unit intentDef : defs.getDefsOfAt(intentLocal, currUnit)) {
					/*if (!currPath.contains(intentDef)) {
						continue;
					}*/
					if (!isDefInPathAndLatest(currPath, intentDef, intentLocal, currUnit, defs)) {
						continue;
					}

					if (currUnit instanceof DefinitionStmt) {
						DefinitionStmt defStmt = (DefinitionStmt) currUnit;
						if (defStmt.getLeftOp() instanceof Local) {
							Local extraLocal = (Local) defStmt.getLeftOp();

							String extraLocalSymbol = createSymbol(extraLocal, method, defStmt);
							String storedExtraLocalSymbol = localSymbolMap.get(extraLocal);
							if (storedExtraLocalSymbol == null || !storedExtraLocalSymbol.equals(extraLocalSymbol)) {
								extraLocalSymbol = createSymbol(extraLocal, method, defStmt);
								symbolLocalMap.put(extraLocalSymbol, extraLocal);
								localSymbolMap.put(extraLocal, extraLocalSymbol);
								String newExtraType = getZ3Type(extraLocal.getType());
								newDecls.add("(declare-const " + extraLocalSymbol + " " + newExtraType + ")");
							}

							String intentSymbol = localSymbolMap.get(intentLocal);
							if (intentSymbol == null) {
								intentSymbol = createSymbol(intentLocal, method, intentDef);
								symbolLocalMap.put(intentSymbol, intentLocal);
								localSymbolMap.put(intentLocal, intentSymbol);
								String newIntentType = getZ3Type(intentLocal.getType());
								newDecls.add("(declare-const " + intentSymbol + " " + newIntentType + ")");
							}

							newAsserts.add("(assert (= (containsKey " + extraLocalSymbol + " \"" + keyStrConst.value + "\") true))");
							newAsserts.add("(assert (= (fromIntent " + extraLocalSymbol + ") " + intentSymbol + "))");

							//addIntentExtraForPath(currPath, keyStrConst.value, newExtraType);

							buildParamRefExpressions(method, currPath, newAsserts, newDecls, intentDef, intentSymbol,
									localSymbolMap, symbolLocalMap);
						}
					}
				}
			}
		}
		return new Pair<Set<String>, Set<String>>(newDecls, newAsserts);
	}

    public static String getIeArg(InvokeExpr ie, SimpleLocalDefs localDefs, Unit ieDefUnit) {
        Value arg = ie.getArg(0);
        String ret = null;
        if (arg instanceof StringConstant) {
            ret = arg.toString();
        } else if (arg instanceof Local) {
            // extract string constant
            List<Unit> argDefs = localDefs.getDefsOfAt((Local)arg, ieDefUnit);
            for (Unit argDef : argDefs) {
                if (argDef instanceof DefinitionStmt) {
                    DefinitionStmt argDefStmt = (DefinitionStmt) argDef;
                    if (argDefStmt instanceof JAssignStmt) {
                        JAssignStmt argAssignStmt = (JAssignStmt) argDefStmt;
                        if (argAssignStmt.containsFieldRef()) {
                            SootField argField = argAssignStmt.getFieldRef().getField();
                            if (argField.getType().toString().equals("java.lang.String")) {
                                StringConstantValueTag str = (StringConstantValueTag) argField.getTag("StringConstantValueTag");
                                if (str != null) {
                                    ret = str.getConstant().value;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (ret != null) {
            ret = ret.replaceAll("^\"|\"$", "");
        }
        return ret;
    }

	private Pair<Set<String>, Set<String>> buildGetBundleData(Unit currUnit, SimpleLocalDefs defs, InstanceInvokeExpr ie,
															  SootMethod method, List<Unit> currPath,
															  Map<Value, String> localSymbolMap, Map<String, Value> symbolLocalMap) {
		Set<String> newDecls = new LinkedHashSet<String>();
		Set<String> newAsserts = new LinkedHashSet<String>();
		Value arg1 = ie.getArg(0);
		Value arg2 = null;
		if (ie.getArgCount() > 1) {
			arg2 = ie.getArg(1);
		}

		String extraType = null;

		if (arg2 != null) {
			extraType = arg2.getType().toString();
		} else {
			extraType = ie.getMethod().getReturnType().toString();
		}

		String arg2Str = "unk";
		if (arg2 != null) {
			arg2Str = arg2.toString();
		}

		if (!(arg1 instanceof StringConstant)) {
			String maybeStr = getIeArg(ie, defs, currUnit);
			if (maybeStr != null) {
				arg1 = StringConstant.v(maybeStr);
			}
		}

		if (arg1 instanceof StringConstant) {
			StringConstant keyStrConst = (StringConstant) arg1;
			if (ie.getBase() instanceof Local) {
				Local bundleLocal = (Local) ie.getBase();
				for (Unit bundleDef : defs.getDefsOfAt(bundleLocal, currUnit)) {
					/*if (!currPath.contains(intentDef)) {
						continue;
					}*/
					if (!isDefInPathAndLatest(currPath, bundleDef, bundleLocal, currUnit, defs)) {
						continue;
					}
					DefinitionStmt bundleDefStmt = (DefinitionStmt) bundleDef;
					if (bundleDefStmt.containsInvokeExpr()) {
						if (bundleDefStmt.getInvokeExpr() instanceof InstanceInvokeExpr) {
							InstanceInvokeExpr iie = (InstanceInvokeExpr) bundleDefStmt.getInvokeExpr();
							if (iie.getBase().getType().toString().equals("android.content.Intent")) {
								if (iie.getBase() instanceof Local) {
									Local intentLocal = (Local) iie.getBase();
									for (Unit intentDef : defs.getDefsOfAt(intentLocal, bundleDefStmt)) {
										if (!isDefInPathAndLatest(currPath, intentDef, intentLocal, bundleDefStmt, defs)) {
											continue;
										}

										if (currUnit instanceof DefinitionStmt) {
											DefinitionStmt defStmt = (DefinitionStmt) currUnit;
											if (defStmt.getLeftOp() instanceof Local) {
												Local extraLocal = (Local) defStmt.getLeftOp();

												String extraLocalSymbol = createSymbol(extraLocal, method, defStmt);
												String storedExtraLocalSymbol = localSymbolMap.get(extraLocal);
												if (storedExtraLocalSymbol == null || !storedExtraLocalSymbol.equals(extraLocalSymbol)) {
													extraLocalSymbol = createSymbol(extraLocal, method, defStmt);
													symbolLocalMap.put(extraLocalSymbol, extraLocal);
													String newExtraType = getZ3Type(extraLocal.getType());
													newDecls.add("(declare-const " + extraLocalSymbol + " " + newExtraType + ")");
												}

												String intentSymbol = localSymbolMap.get(intentLocal);
												if (intentSymbol == null) {
													intentSymbol = createSymbol(intentLocal, method, intentDef);
													symbolLocalMap.put(intentSymbol, intentLocal);
													String newIntentType = getZ3Type(intentLocal.getType());
													newDecls.add("(declare-const " + intentSymbol + " " + newIntentType + ")");
												}

												newAsserts.add("(assert (= (containsKey " + extraLocalSymbol + " \"" + keyStrConst.value + "\") true))");
												newAsserts.add("(assert (= (fromIntent " + extraLocalSymbol + ") " + intentSymbol + "))");

												buildParamRefExpressions(method, currPath, newAsserts, newDecls, intentDef,
														intentSymbol, localSymbolMap, symbolLocalMap);
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
		return new Pair<Set<String>, Set<String>>(newDecls, newAsserts);
	}

	private String getZ3Type(Type type) {
		switch (type.toString()) {
			case "short":
				return "Int";
			case "int":
				return "Int";
			case "long":
				return "Int";
			case "float":
				return "Real";
			case "double":
				return "Real";
			case "boolean":
				return "Int";
			case "byte":
			case "java.lang.Integer":
				return "Int";
			case "java.lang.String":
				return "String";
			default:
				return "Object";
		}
	}

	private synchronized boolean wasPreviouslyWrittenIntentData(String className, Intent intent) {
		return !prevWrittenIntents.add(intent);
	}

	public synchronized void storeGeneratedDataToWriter(String currClassName, Intent genIntent) {
		Component comp = androidProcessor.findComponent(currClassName);
		totalIntents.add(genIntent);

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
		} else if (Utils.extendFromActivity(currClassName)) {
			// activity that extends from PreferenceActivity does not have to be in manifest
			drozerWriter = activityCmdsDrozerFileWriter;
		} else {
//			logger.error("Unsupported component type: " + comp);
//			logger.error("Won't write new intent command files for this component");
			return;
		}
		try {
//			logger.debug("<<< writeIntentCmdsForDrozer");
			androidProcessor.writeIntentCmdsForADB(currClassName, comp, genIntent, drozerWriter);
			//androidProcessor.writeIntentCmdsForDrozer(currClassName, comp, genIntent, drozerWriter);
			/*
			if (genIntent.action == null) {
				androidProcessor.writeIntentCmdsForDrozer(currClassName, comp, genIntent, drozerWriter);
			} else {
				androidProcessor.writeIntentCmdsForADB(currClassName, comp, genIntent, drozerWriter);
			}
			 */
			drozerWriter.flush();
			//adbWriter.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private Triplet<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>, String> findStringValuesOfBoolType(SootMethod method,
																																   SimpleLocalDefs defs,
																																   Unit inUnit, Value value,
																																   List<Unit> currPath,
																																   Map<String, Value> symbolLocalMap) {
		// soot variable, new decls, new asserts, def of variable
		Quartet<Value, String, String, Unit> leftVal = null;
		Quartet<Value, String, String, Unit> rightVal = null;
		String strOp = null;
		if (value instanceof Local) {
			Local local = (Local) value;
			if (local.getType() instanceof BooleanType) {
				List<Unit> potentialStringEqualsUnits = defs.getDefsOfAt(local, inUnit);
				for (Unit pseUnit : potentialStringEqualsUnits) {
					/*if (!currPath.contains(pseUnit)) {
						continue;
					}*/
					if (!isDefInPathAndLatest(currPath, pseUnit, local, inUnit, defs)) {
						continue;
					}
//					logger.debug("Found potential string equal comparison statement: " + pseUnit);
					if (pseUnit instanceof DefinitionStmt) {
						DefinitionStmt defStmt = (DefinitionStmt) pseUnit;
						if (defStmt.getRightOp() instanceof JVirtualInvokeExpr) {
							JVirtualInvokeExpr jviExpr = (JVirtualInvokeExpr) defStmt.getRightOp();
							if (jviExpr.getMethod().getDeclaringClass().getName().equals("java.lang.String")) {
								if (jviExpr.getMethod().getName().equals("equals")) {
//									logger.debug("Identified actual string equals comparison statement");
									leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath, symbolLocalMap);
									rightVal = findOriginalVal(method, defs, pseUnit, jviExpr.getArg(0), currPath, symbolLocalMap);
								} else if (jviExpr.getMethod().getName().equals("startsWith")) {
									leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath, symbolLocalMap);
									rightVal = findOriginalVal(method, defs, pseUnit, jviExpr.getArg(0), currPath, symbolLocalMap);
									strOp = "startsWith";
								} else if (jviExpr.getMethod().getName().equals("endsWith")) {
									leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath, symbolLocalMap);
									rightVal = findOriginalVal(method, defs, pseUnit, jviExpr.getArg(0), currPath, symbolLocalMap);
									strOp = "endsWith";
								} else if (jviExpr.getMethod().getName().equals("contains")) {
									leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath, symbolLocalMap);
									rightVal = findOriginalVal(method, defs, pseUnit, jviExpr.getArg(0), currPath, symbolLocalMap);
									strOp = "contains";
								} else if (jviExpr.getMethod().getName().equals("isEmpty")) {
									leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath, symbolLocalMap);
									rightVal = new Quartet<>(StringConstant.v(""), null, null, null);  // equals against empty string
								}

							}

							if (jviExpr.getMethod().getName().equals("booleanValue") && jviExpr.getMethod().getDeclaringClass().getName().equals("java.lang.Boolean")) {
								if (jviExpr instanceof InstanceInvokeExpr) {
									InstanceInvokeExpr jviExprInvoke = (InstanceInvokeExpr) jviExpr;
									if (jviExprInvoke.getBase() instanceof Local) {
										Local base = (Local) jviExprInvoke.getBase();
										List<Unit> defUnits = defs.getDefsOfAt(base, inUnit);
										for (Unit defUnit : defUnits) {
											InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
											if (invokeExpr == null) {
												continue;
											}
											if (invokeExpr.getMethod().getName().equals("valueOf")) {
												Value valueOfVal = invokeExpr.getArg(0);
												// the definition of a valueOf arg is the hasExtra
												if (valueOfVal  instanceof Local) {
													List<Unit> defUnits2 = defs.getDefsOfAt((Local)valueOfVal, defUnit);
													for (Unit defUnit2 : defUnits2) {
														InvokeExpr invokeExpr2 = Utils.getInvokeExprOfAssignStmt(defUnit2);
														if (invokeExpr2 == null) {
															continue;
														}
														JVirtualInvokeExpr jInvokeExpr2 = (JVirtualInvokeExpr) invokeExpr2;
														if (Pattern.matches("hasExtra", jInvokeExpr2.getMethod().getName())) {
//															logger.debug("Found hasExtra invocation");
															leftVal = findOriginalVal(method, defs, defUnit2, jInvokeExpr2.getBase(), currPath, symbolLocalMap);
															rightVal = findOriginalVal(method, defs, defUnit2, jInvokeExpr2.getArg(0), currPath, symbolLocalMap);

															Body b = method.getActiveBody();
															UnitGraph ug = new BriefUnitGraph(b);

															List<Unit> currPathList = new ArrayList<Unit>(currPath);
															int indexOfUnit = currPathList.indexOf(inUnit);
															if (indexOfUnit == -1) {
																throw new RuntimeException(inUnit + " is not in path");
															}
															Unit succ;
															try {
																succ = currPathList.get(indexOfUnit - 1);
															} catch (Exception e) {
																continue;
															}
															//Unit succ = currPathList.get(indexOfUnit - 1);

															boolean isFallThrough = isFallThrough(inUnit, succ);
															String newAssert = null;

															// TODO: following definition of isFallThroughSuccessor only checks
															//   if the successor is the fall-through method for the ifstmt
															//   return (succ == null && inUnit instanceof IfStmt) ? true : icfg.isFallThroughSuccessor(inUnit, succ);
															//   BUGGY POINT FOR MAJUN_2, I BELIEVE. It doesn't consider !hasExtra("bool"), negation.
															//	 It will result !hasExtra("bool") and hasExtra("bool") having same Z3 output
															//	 ALSO APPLY TO CATEGORY
															List useBoxes = inUnit.getUseBoxes();
															ConditionExprBox conditonBox = (ConditionExprBox) useBoxes.get(2);
															Value conditionBoxValue = conditonBox.getValue();
															String conditionValueString = conditionBoxValue.toString();
															Pattern conditionPattern = Pattern.compile("(\\S+)\\s+(\\S+)\\s+(\\S+)");
															Matcher conditionMatcher = conditionPattern.matcher(conditionValueString);
															boolean negation = false;
															if (conditionMatcher.find()) {
																String condition = conditionMatcher.group(2);
																negation = condition.equals("!=");
															}
															if ((isFallThrough && !negation) || (!isFallThrough && negation)) {
																//if(isFallThrough){    // intent contains the extra
																newAssert = "(assert (exists ((index Int)) (= (select keys index) " + rightVal.getValue0().toString() + ")))";
																//addIntentExtraForPath(currPath, rightVal.getValue0().toString(), rightVal.getValue0().getType().toString());
															} else { // intent does not contain the extra
																newAssert = "(assert (forall ((index Int)) (not(= (select keys index) " + rightVal.getValue0().toString() + "))))";
															}
															leftVal = new Quartet<Value, String, String, Unit>(jviExpr.getBase(), null, newAssert, leftVal.getValue3());
														}
													}
												}
											}
										}
									}
								}

							}
							/*if (Pattern.matches("get.*Extra",jviExpr.getMethod().getName())) {
								logger.debug("Found extra data getter method");
								leftVal = findOriginalVal(method, defs,pseUnit,jviExpr.getBase(),currPath);
								rightVal = findOriginalVal(method, defs,pseUnit,jviExpr.getArg(0),currPath);
							}*/
							if (Pattern.matches("hasExtra", jviExpr.getMethod().getName())) {
//								logger.debug("Found hasExtra invocation");
								leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath, symbolLocalMap);
								rightVal = findOriginalVal(method, defs, pseUnit, jviExpr.getArg(0), currPath, symbolLocalMap);

								Body b = method.getActiveBody();
								UnitGraph ug = new BriefUnitGraph(b);

								List<Unit> currPathList = new ArrayList<Unit>(currPath);
								int indexOfUnit = currPathList.indexOf(inUnit);
								if (indexOfUnit == -1) {
									throw new RuntimeException(inUnit + " is not in path");
								}
								Unit succ;
								try {
									succ = currPathList.get(indexOfUnit - 1);
								} catch (Exception e) {
									continue;
								}
								//Unit succ = currPathList.get(indexOfUnit - 1);

								boolean isFallThrough = isFallThrough(inUnit, succ);
								String newAssert = null;

								// TODO: following definition of isFallThroughSuccessor only checks
								//   if the successor is the fall-through method for the ifstmt
								//   return (succ == null && inUnit instanceof IfStmt) ? true : icfg.isFallThroughSuccessor(inUnit, succ);
								//   BUGGY POINT FOR MAJUN_2, I BELIEVE. It doesn't consider !hasExtra("bool"), negation.
								//	 It will result !hasExtra("bool") and hasExtra("bool") having same Z3 output
								//	 ALSO APPLY TO CATEGORY
								List useBoxes = inUnit.getUseBoxes();
								ConditionExprBox conditonBox = (ConditionExprBox) useBoxes.get(2);
								Value conditionBoxValue = conditonBox.getValue();
								String conditionValueString = conditionBoxValue.toString();
								Pattern conditionPattern = Pattern.compile("(\\S+)\\s+(\\S+)\\s+(\\S+)");
								Matcher conditionMatcher = conditionPattern.matcher(conditionValueString);
								boolean negation = false;
								if (conditionMatcher.find()) {
									String condition = conditionMatcher.group(2);
									negation = condition.equals("!=");
								}
								if ((isFallThrough && !negation) || (!isFallThrough && negation)) {
									//if(isFallThrough){    // intent contains the extra
									newAssert = "(assert (exists ((index Int)) (= (select keys index) " + rightVal.getValue0().toString() + ")))";
									//addIntentExtraForPath(currPath, rightVal.getValue0().toString(), rightVal.getValue0().getType().toString());
								} else { // intent does not contain the extra
									newAssert = "(assert (forall ((index Int)) (not(= (select keys index) " + rightVal.getValue0().toString() + "))))";
								}
								leftVal = new Quartet<Value, String, String, Unit>(jviExpr.getBase(), null, newAssert, leftVal.getValue3());
							}
						}
					}
				}
			}
		}
		return new Triplet<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>, String>(leftVal, rightVal, strOp);
	}

	private Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> findCategories(SootMethod method, SimpleLocalDefs defs,
																											Unit inUnit, Value value, List<Unit> currPath,
																											Map<String, Value> symbolLocalMap) {
		Quartet<Value, String, String, Unit> leftVal = null;
		Quartet<Value, String, String, Unit> rightVal = null;
		if (value instanceof Local) {
			Local local = (Local) value;
			if (local.getType() instanceof BooleanType) {
				List<Unit> potentialStringEqualsUnits = defs.getDefsOfAt(local, inUnit);
				for (Unit pseUnit : potentialStringEqualsUnits) {
					/*if (!currPath.contains(pseUnit)) {
						continue;
					}*/
					if (!isDefInPathAndLatest(currPath, pseUnit, local, inUnit, defs)) {
						continue;
					}
//					logger.debug("Found potential string equal comparison statement: " + pseUnit);
					if (pseUnit instanceof DefinitionStmt) {
						DefinitionStmt defStmt = (DefinitionStmt) pseUnit;
						if (defStmt.getRightOp() instanceof JVirtualInvokeExpr) {
							JVirtualInvokeExpr jviExpr = (JVirtualInvokeExpr) defStmt.getRightOp();
							if (jviExpr.getMethod().getName().equals("hasCategory")) {
								if (jviExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
									if (jviExpr.getBase() instanceof Local) {
										Local intentLocal = (Local) jviExpr.getBase();
										for (Unit intentDef : defs.getDefsOfAt(intentLocal, defStmt)) {
											/*if (!currPath.contains(intentDef)) {
												continue;
											}*/
											if (!isDefInPathAndLatest(currPath, intentDef, intentLocal, defStmt, defs)) {
												continue;
											}
											String intentSymbol = createSymbol(intentLocal, method, intentDef);
											symbolLocalMap.put(intentSymbol, intentLocal);

											String category = null;
											if (jviExpr.getArg(0) instanceof StringConstant) {
												StringConstant catStrConst = (StringConstant) jviExpr.getArg(0);
												category = catStrConst.value;
											}

											Body b = method.getActiveBody();
											UnitGraph ug = new BriefUnitGraph(b);

											List<Unit> currPathList = new ArrayList<Unit>(currPath);
											int indexOfUnit = currPathList.indexOf(inUnit);
											if (indexOfUnit == -1) {
												throw new RuntimeException(inUnit + " is not in path");
											}
											Unit succ = currPathList.get(indexOfUnit - 1);

											boolean isFallThrough = isFallThrough(inUnit, succ);
											String newAssert = null;

											// TODO: IT ALSO FACES THE PROBLEM OF FALLTHROUGH like hasExtra(...)
											List useBoxes = inUnit.getUseBoxes();
											ConditionExprBox conditonBox = (ConditionExprBox) useBoxes.get(2);
											Value conditionBoxValue = conditonBox.getValue();
											String conditionValueString = conditionBoxValue.toString();
											Pattern conditionPattern = Pattern.compile("(\\S+)\\s+(\\S+)\\s+(\\S+)");
											Matcher conditionMatcher = conditionPattern.matcher(conditionValueString);
											boolean negation = false;
											if (conditionMatcher.find()) {
												String condition = conditionMatcher.group(2);
												negation = condition.equals("!=");
											}
											if ((isFallThrough && !negation) || (!isFallThrough && negation)) {
												//if (isFallThrough) { // intent contains the category
												newAssert = "(assert (exists ((index Int)) (= (select cats index) \"" + category + "\")))";
												//addIntentCategoryForPath(currPath,category);
											} else { // intent does not contain the category
												newAssert = "(assert (forall ((index Int)) (not(= (select cats index) \"" + category + "\"))))";
											}
											leftVal = new Quartet<Value, String, String, Unit>(intentLocal, null, newAssert, intentDef);
										}
									}
								}
							}
						}
					}
				}
			}
		}
		return new Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>>(leftVal, rightVal);
	}

	private Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> findBundleValues(SootMethod method,
																											  SimpleLocalDefs defs,
																											  Unit inUnit, Value value,
																											  List<Unit> currPath,
																											  Map<String, Value> symbolLocalMap) {
		Quartet<Value, String, String, Unit> leftVal = null;
		Quartet<Value, String, String, Unit> rightVal = null;
		if (value instanceof Local) {
			Local local = (Local) value;
			if (local.getType() instanceof BooleanType) {
				for (Unit defUnit : defs.getDefsOfAt(local, inUnit)) {
					/*if (!currPath.contains(defUnit)) {
						continue;
					}*/
					if (!isDefInPathAndLatest(currPath, defUnit, local, inUnit, defs)) {
						continue;
					}

					Stmt defStmt = (Stmt) defUnit;
					if (defStmt.containsInvokeExpr()) {
						if (defStmt.getInvokeExpr() instanceof InstanceInvokeExpr) {
							InstanceInvokeExpr ie = (InstanceInvokeExpr) defStmt.getInvokeExpr();
							if (ie.getMethod().getDeclaringClass().getName().equals("android.os.Bundle")) {
								if (ie.getMethod().getName().equals("containsKey")) {
									Value keyVal = ie.getArg(0);
									if (keyVal instanceof StringConstant) {
										StringConstant keyStringConst = (StringConstant) keyVal;
										String keyString = keyStringConst.value;


										if (ie.getBase() instanceof Local) {
											Local bundleLocal = (Local) ie.getBase();
											for (Unit bundleDef : defs.getDefsOfAt(bundleLocal, defUnit)) {
												/*if (!currPath.contains(bundleDef)) {
													continue;
												}*/
												if (!isDefInPathAndLatest(currPath, bundleDef, bundleLocal, defUnit, defs)) {
													continue;
												}
												Stmt bundleStmt = (Stmt) bundleDef;
												if (bundleStmt.containsInvokeExpr()) {
													if (bundleStmt.getInvokeExpr() instanceof InstanceInvokeExpr) {
														InstanceInvokeExpr bundleInvoke = (InstanceInvokeExpr) bundleStmt.getInvokeExpr();
														if (bundleInvoke.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
															if (bundleInvoke.getMethod().getName().equals("getExtras")) {
																if (bundleInvoke.getBase() instanceof Local) {
																	Local intentLocal = (Local) bundleInvoke.getBase();
																	for (Unit intentDef : defs.getDefsOfAt(intentLocal, bundleStmt)) {
																		/*if (!currPath.contains(intentDef)) {
																			continue;
																		}*/
																		if (!isDefInPathAndLatest(currPath, intentDef, intentLocal, bundleStmt, defs)) {
																			continue;
																		}
																		String intentLocalSymbol = createSymbol(intentLocal, method, intentDef);
																		symbolLocalMap.put(intentLocalSymbol, intentLocal);
																		String newDecl = "(declare-const " + intentLocalSymbol + " Object)";
																		String newAssert = "(assert (= " + intentLocalSymbol + " NotNull))";

																		Body b = method.getActiveBody();
																		UnitGraph ug = new BriefUnitGraph(b);
																		List<Unit> currPathList = new ArrayList<Unit>(currPath);
																		Unit succ = currPathList.get(currPathList.indexOf(inUnit) - 1);

																		boolean isFallThrough = isFallThrough(inUnit, succ);
																		// TODO: ContainsKey same as hasExtra
																		List useBoxes = inUnit.getUseBoxes();
																		ConditionExprBox conditonBox = (ConditionExprBox) useBoxes.get(2);
																		Value conditionBoxValue = conditonBox.getValue();
																		String conditionValueString = conditionBoxValue.toString();
																		Pattern conditionPattern = Pattern.compile("(\\S+)\\s+(\\S+)\\s+(\\S+)");
																		Matcher conditionMatcher = conditionPattern.matcher(conditionValueString);
																		boolean negation = false;
																		if (conditionMatcher.find()) {
																			String condition = conditionMatcher.group(2);
																			negation = condition.equals("!=");
																		}
																		if ((isFallThrough && !negation) || (!isFallThrough && negation)) {
																			//if (isFallThrough) { // then intent contains the key
																			newAssert += "\n(assert (= (containsKey " + intentLocalSymbol + " \"" + keyString + "\") true))";
																			//addIntentExtraForPath(currPath,keyString,keyVal.getType().toString());
																		} else { // the intent does NOT contain the key
																			newAssert += "\n(assert (= (containsKey " + intentLocalSymbol + " \"" + keyString + "\") false))";
																		}

																		leftVal = new Quartet<Value, String, String, Unit>(intentLocal, newDecl, newAssert, intentDef);
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
							}
						}
					}
				}
			}
		}
		return new Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>>(leftVal, rightVal);
	}

	private boolean isFallThrough(Unit inUnit, Unit succ) {
//		return (succ == null && inUnit instanceof IfStmt) ? true : icfg.isFallThroughSuccessor(inUnit, succ);
		// for intraprocedural analysis
		if (succ == null && inUnit instanceof IfStmt) {
			return true;
		}
		if (!(inUnit instanceof IfStmt)) {
			return true;
		}
		IfStmt ifInUnit = (IfStmt) inUnit;
		if (ifInUnit.getTarget().equals(succ)) {
			return false;
		}
		return true;
	}

	public Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> findLeftAndRightValuesOfByteVal(SootMethod method,
																															SimpleLocalDefs defs,
																															Unit inUnit, Value value,
																															List<Unit> currPath,
																															Map<String, Value> symbolLocalMap) {

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
//						logger.debug("Found potential cmp* statement: " + potentialCmpUnit);
						if (potentialCmpUnit instanceof DefinitionStmt) {
							DefinitionStmt defStmt = (DefinitionStmt) potentialCmpUnit;
							Value rightOp = defStmt.getRightOp();
							if (rightOp instanceof AbstractJimpleIntBinopExpr) {
								AbstractJimpleIntBinopExpr cmpExpr = (AbstractJimpleIntBinopExpr) rightOp;
								leftVal = findOriginalVal(method, defs, potentialCmpUnit, cmpExpr.getOp1(), currPath, symbolLocalMap);
								rightVal = findOriginalVal(method, defs, potentialCmpUnit, cmpExpr.getOp2(), currPath, symbolLocalMap);
							}
						}
					}
				}
			}
		}
		return new Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>>(leftVal, rightVal);
	}

	public Quartet<Value, String, String, Unit> findOriginalVal(SootMethod method, SimpleLocalDefs defs, Unit potentialCmpUnit,
																Value cmpOp, List<Unit> currPath, Map<String, Value> symbolLocalMap) {
		Value origVal = null;
		String newDecl = null;
		String newAssert = null;
		Unit defUnit = null;
		if (cmpOp instanceof Local) {
			Value cmpVal = cmpOp;
			Quartet<Value, String, String, Unit> r = findOriginalValFromCmpVal(method, defs, potentialCmpUnit, cmpVal,
					currPath, symbolLocalMap);
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

	public Quartet<Value, String, String, Unit> findOriginalValFromCmpVal(SootMethod method, SimpleLocalDefs defs,
																		  Unit potentialCmpUnit, Value cmpVal,
																		  List<Unit> currPath, Map<String, Value> symbolLocalMap) {
		Value origVal = null;
		String key = null;
		Local cmpOp1 = (Local) cmpVal;
		List<Unit> castOrInvokeUnits = defs.getDefsOfAt(cmpOp1, potentialCmpUnit);
		String newDecl = null;
		String newAssert = null;
		Unit defUnit = null;
		for (Unit coiUnit : castOrInvokeUnits) {
			if (!isDefInPathAndLatest(currPath, coiUnit, cmpOp1, potentialCmpUnit, defs)) {
				continue;
			}
//			logger.debug("Found potential cast or invoke stmt: " + coiUnit);
			if (coiUnit instanceof DefinitionStmt) {
				DefinitionStmt coiStmt = (DefinitionStmt) coiUnit;
				origVal = coiStmt.getLeftOp();
				defUnit = coiUnit;
				if (!currPath.contains(defUnit)) {
					continue;
				}
				if (coiStmt.getRightOp() instanceof JCastExpr) {
//					logger.debug("Handling cast expression from potential API invocation assigned to local");
					JCastExpr expr = (JCastExpr) coiStmt.getRightOp();
					if (expr.getOp() instanceof Local) {
						Local localFromCast = (Local) expr.getOp();
						List<Unit> defsOfLocalFromCast = defs.getDefsOfAt(localFromCast, coiUnit);
						for (Unit defLocalAssignFromCastUnit : defsOfLocalFromCast) {
							if (!isDefInPathAndLatest(currPath, defLocalAssignFromCastUnit, localFromCast, coiUnit, defs)) {
								continue;
							}
							if (defLocalAssignFromCastUnit instanceof DefinitionStmt) {
								DefinitionStmt defLocalAssignFromCastStmt = (DefinitionStmt) defLocalAssignFromCastUnit;
								origVal = defLocalAssignFromCastStmt.getLeftOp();
								defUnit = defLocalAssignFromCastUnit;
								//key = extractKeyFromIntentExtra(defLocalAssignFromCastStmt, defs, currPath);
							}
						}
					}
				} else if (coiStmt instanceof JAssignStmt) {
					JAssignStmt coiAssignStmt = (JAssignStmt) coiStmt;
					if (coiAssignStmt.containsFieldRef()) {
						SootField coiField = coiAssignStmt.getFieldRef().getField();
						if (coiField.getType().toString().equals("java.lang.String")) {
							// field is a string constant
							StringConstantValueTag str = (StringConstantValueTag) coiField.getTag("StringConstantValueTag");
							if (str != null) {
								origVal = StringConstant.v(str.getConstant().value);
							}
						}
					}
					//key = extractKeyFromIntentExtra(coiStmt, defs, currPath);
				} else {
					//key = extractKeyFromIntentExtra(coiStmt, defs, currPath);
				}

				if (coiStmt.getRightOp() instanceof StringConstant) {
					Local local = (Local) coiStmt.getLeftOp();
					String symbol = createSymbol(local, method, coiStmt);
					symbolLocalMap.put(symbol, local);
					newDecl = "(declare-const " + symbol + " String)";

					StringConstant stringConst = (StringConstant) coiStmt.getRightOp();
					if (newAssert == null) {
						newAssert = "(assert (= " + symbol + " " + stringConst + " ))";
					} else {
						newAssert += "\n(assert (= " + symbol + " " + stringConst + " ))";
					}
				}

				if (coiStmt.getRightOp() instanceof ParameterRef) {
//					logger.debug("Found parameter ref when searching for original value");
					if (coiStmt.getLeftOp() instanceof Local) {
						Local prLocal = (Local) coiStmt.getLeftOp();
						String localSymbol = createSymbol(prLocal, method, coiStmt);

						origVal = coiStmt.getLeftOp();
						ParameterRef pr = (ParameterRef) coiStmt.getRightOp();
						String prSymbol = createParamRefSymbol(prLocal, pr.getIndex(), method, coiStmt);
						String prNormalSymbol = createSymbol(prLocal, method, coiStmt);

						// make sure param symbol does not exist first
/*
						if (newAssert == null || !newAssert.contains(prSymbol)) {
							newDecl = "(declare-const " + prSymbol + " ParamRef)\n";
							//newDecl = "(isParamRef (" + prSymbol + ") True)";
							newAssert = "(assert ( = (index " + prSymbol + ") " + pr.getIndex() + "))\n";
							newAssert += "(assert ( = (type " + prSymbol + ") \"" + pr.getType() + "\"))\n";
							newAssert += "(assert ( = (method " + prSymbol + ") \"" + method.getDeclaringClass().getName() + "." + method.getName() + "\"))\n";
							// TODO: HASPARAMREF LOC
//							newAssert += "(assert (= (hasParamRef " + localSymbol + " " + prSymbol + ") true))";
							defUnit = coiStmt;
							symbolLocalMap.put(prNormalSymbol, prLocal);
							localSymbolMap.put(prLocal, prNormalSymbol);
							String prNormalType = getZ3Type(prLocal.getType());
							newDecl += "(declare-const " + prNormalSymbol + " " + prNormalType + " )";
							String prConstraint = "(assert (= (isParamRef " + prNormalSymbol + " " + prSymbol + ") true))\n";
							newAssert += prConstraint;
						}
 */
					}
				}
			}
		}
		/*
		if (key != null){
			valueKeyMap.put(origVal, key);
		}
		 */
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
//				logger.debug("We can extract the key from this expression");
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
								} else if (keyLocalDefStmt.getRightOp() instanceof StaticInvokeExpr) {
									StaticInvokeExpr invokeExpr = (StaticInvokeExpr) keyLocalDefStmt.getRightOp();
									SootMethod invokedMethod = invokeExpr.getMethod();
									if (invokedMethod.getName().equals("toString") && invokeExpr.getArgCount()==1) {
										Local numArg = (Local) invokeExpr.getArg(0);
										List<Unit> numDefs = defs.getDefsOfAt(numArg, keyLocalDefStmt);
										for (Unit numDef : numDefs) {
											if (!isDefInPathAndLatest(currPath, numDef, numArg, keyLocalDefStmt, defs)) {
												continue;
											}
											if (numDef instanceof DefinitionStmt) {
												DefinitionStmt numDefStmt = (DefinitionStmt) numDef;
												if (numDefStmt.getRightOp() instanceof IntConstant) {
													IntConstant numConst = (IntConstant) numDefStmt.getRightOp();
													key = String.valueOf(numConst.value);
												}
											}
										}
									}
								} else if (keyLocalDefStmt.getRightOp() instanceof ParameterRef) {
									// since the definition is from a parameter, will require interprocedural analysis
									continue;
								}else {
									throw new RuntimeException("Unhandled case for: " + keyLocalDefStmt.getRightOp());
								}

							}
						}
					}
				} else {
					// is a string constant
					key = expr.getArg(0).toString();
				}
			}
		}
		return key;
	}

	/*
	public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit unit) {
		if (unit instanceof InvokeStmt) {
			InvokeStmt stmt = (InvokeStmt) unit;
			if (stmt.getInvokeExpr().getMethod().getName().equals("d")) {
				return true;
			}
		}
		return false;
	}
	 */

	public boolean unitNeedsAnalysisTag(SootMethod method, String currClassName, Unit unit) {
		if (unit instanceof InvokeStmt) {
			InvokeStmt stmt = (InvokeStmt) unit;
			if (stmt.getInvokeExpr().getMethod().getName().equals("d")) {
				return true;
			}
		}
		return false;
	}

	public boolean unitNeedsAnalysisTag(SootMethod method, String currClassName, Unit unit, Set<SootMethod> methodsWithSum) {
		if (unit instanceof InvokeStmt) {
			InvokeStmt stmt = (InvokeStmt) unit;
			if (stmt.getInvokeExpr().getMethod().getName().equals("d")) {
				return true;
			}
		}
		return false;
	}

	public boolean unitNeedsAnalysisTag(SootMethod method, String currClassName, Unit unit, Set<SootMethod> methodsWithSum, List<String> intentLocs) {
		if (unit instanceof InvokeStmt) {
			InvokeStmt stmt = (InvokeStmt) unit;
			if (stmt.getInvokeExpr().getMethod().getName().equals("d")) {
				return true;
			}
		}
		return false;
	}

	public synchronized Pair<Intent,Boolean> findSolutionForPath(Integer fpIdx,
																 Integer sumUpIdx,
																 Set<String> currPathCond,
																 SootMethod method,
																 Set<String> decls,
																 List<Unit> currPath,
																 Unit startingUnit,
																 Integer analysisMode) {
		Set<Triplet<String,String,String>> extraData = new LinkedHashSet<Triplet<String,String,String>>();
		String action = null;
		String data = null;
		String scheme = "";
		String host = "";
		String uri = null;
		Set<String> categories = new LinkedHashSet<String>();
		boolean isPathFeasible = false;

		try {
			Pair<Map<String, String>,Boolean> ret = returnSatisfyingModel(fpIdx, sumUpIdx, decls, currPathCond, startingUnit, method, analysisMode);
			Map<String,String> model = ret.getValue0();
			Boolean isSat = ret.getValue1();
			if (!isSat) {
				isPathFeasible=false;
			} else {
				isPathFeasible=true;

				// from path constraints identify the attributes we modelled

				Map<String,String> intentActionSymbols = new ConcurrentHashMap<>();
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(= \\(getAction (.+)\\) (.+)\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String intentSymbol = m.group(1);
						String actionStrSymbol = m.group(2);
						intentActionSymbols.put(intentSymbol,actionStrSymbol);
					}
				}

				Map<String,String> intentDataSymbols = new ConcurrentHashMap<>();
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(= \\(getData (.+)\\) (.+)\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String intentSymbol = m.group(1);
						String dataStrSymbol = m.group(2);
						intentDataSymbols.put(intentSymbol,dataStrSymbol);
					}
				}

				Map<String,String> intentSchemeSymbols = new ConcurrentHashMap<>();
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(= \\(getScheme (.+)\\) (.+)\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String intentSymbol = m.group(1);
						String schemeStrSymbol = m.group(2);
						intentSchemeSymbols.put(intentSymbol,schemeStrSymbol);
					}
				}

				Map<String,String> intentHostSymbols = new ConcurrentHashMap<>();
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(= \\(getHost (.+)\\) (.+)\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String intentSymbol = m.group(1);
						String hostStrSymbol = m.group(2);
						intentHostSymbols.put(intentSymbol,hostStrSymbol);
					}
				}

				/*
				Map<String,String> intentUriSymbols = new ConcurrentHashMap<>();
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(= \\(getUri (.+)\\) (.+)\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String intentSymbol = m.group(1);
						String uriStrSymbol = m.group(2);
						intentUriSymbols.put(intentSymbol,uriStrSymbol);
					}
				}
				 */

				Map<String,String> extraLocalKeys = new ConcurrentHashMap<>();
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(= \\(containsKey (.+) \\\"(.+)\\\"\\) true\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String extraLocalSymbol = m.group(1);
						String key = m.group(2);
						extraLocalKeys.put(extraLocalSymbol,key);
					}
				}

				Set<String> nullExtraKeys = new HashSet<>();
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(= \\(isNull (.+)\\) true\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String extraNullSymbol = m.group(1);
						nullExtraKeys.add(extraNullSymbol);
					}
				}
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(= \\(isNull (.+)\\) true\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String extraNullSymbol = m.group(1);
						nullExtraKeys.add(extraNullSymbol);
					}
				}

				for (Map.Entry<String,String> entry : model.entrySet()) {
					String symbol = entry.getKey();
					String generatedValue = entry.getValue();

					Triplet<String, String, String> genDatum = null;
					if (!nullExtraKeys.contains(symbol)) {
						genDatum = generateDatum(symbol, generatedValue, extraLocalKeys);
					}
					/*if (genDatum == null) {
						logger.warn("Skipping generation of extra datum for " + symbol);
						continue;
					}*/

					Triplet<String, String, String> extraDatum = genDatum;
					if (extraDatum != null) {
						extraData.add(extraDatum);
					}

					for (String actionSymbol : intentActionSymbols.values()) {
						if (actionSymbol.equals(symbol)) {
							action = generatedValue.replaceAll("^\"|\"$", "");
						}
					}

					for (String dataSymbol : intentDataSymbols.values()) {
						if (dataSymbol.equals(symbol)) {
							data = generatedValue.replaceAll("^\"|\"$", "");
						}
					}

					for (String schemeSymbol : intentSchemeSymbols.values()) {
						if (schemeSymbol.equals(symbol)) {
							scheme = generatedValue.replaceAll("^\"|\"$", "");
						}
					}

					for (String hostSymbol : intentHostSymbols.values()) {
						if (hostSymbol.equals(symbol)) {
							host = generatedValue.replaceAll("^\"|\"$", "");
						}
					}

//					for (String uriSymbol : intentUriSymbols.values()) {
//						if (uriSymbol.equals(symbol)) {
//							uri = generatedValue.replaceAll("^\"|\"$", "");
//						}
//					}

				}

				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(exists \\(\\(index Int\\)\\) \\(= \\(select cats index\\) \\\"(.+)\\\"\\)\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String category = m.group(1);
						categories.add(category);
					}
				}

				// TODO: HERE IS THE BUG for Majun_234 ??????
				//		It doesn't generate EXTRA for hasExtra
				//		This is also relate to the expression which needs (exists ... (select keys index) ...)
				//		hasExtra provided doesn't generate correct Z3 expression, solution is commented in function "findStringValuesOfBoolType"

				// I cannot generate an Intent for an extra datum if I don't know it's type
				// ex: hasExtra
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(exists \\(\\(index Int\\)\\) \\(= \\(select keys index\\) \\\"(.+)\\\"\\)\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String key = m.group(1);
						// TODO: TYPE CANNOT BE NULL
						//		So we just assume it is String, just need to bypass the if/else statement
						Triplet<String,String,String> extraDatum = new Triplet("String",key,null);
						extraData.add(extraDatum);
					}
				}
			}
		} catch (Z3Exception e) {
			e.printStackTrace();
		}

		// extra data from hasExtras has value of null
		Set<Triplet<String,String,String>> nullextras = new LinkedHashSet<Triplet<String,String,String>>();
		for (Triplet<String,String,String> extra : extraData) {
			if (extra.getValue2() == null) {
				nullextras.add(extra);
			}
		}
		Set<Triplet<String,String,String>> extraDataFiltered = new LinkedHashSet<Triplet<String,String,String>>();
		for (Triplet<String,String,String> extra : extraData) {
			if (extra.getValue2() != null) {
				extraDataFiltered.add(extra);
			}
		}
		for (Triplet<String,String,String> nullex : nullextras) {
			boolean nullSymExist = false;
			for (Triplet<String,String,String> extra : extraDataFiltered) {
				if (extra.getValue1().equals(nullex.getValue1())) {
					nullSymExist = true;
				}
			}
			if (!nullSymExist) {
				extraDataFiltered.add(nullex);
			}
		}

		Intent genIntent = new Intent();
		genIntent.extras = new LinkedHashSet<>(extraDataFiltered);
		genIntent.action = action;
		if (!scheme.equals("") || !host.equals("")) {
			genIntent.uri = new Uri(scheme, host);
		} else if (data != null) {
			genIntent.uri = new Uri(data);
		}
		genIntent.categories = categories;
		genIntent.targetComponent = method.getDeclaringClass().getName();
		genIntent.targetMethod = method.getName();

		Intent modIntent = modifyGeneratedIntent(genIntent, startingUnit);

		return new Pair<Intent,Boolean>(modIntent,isPathFeasible);
	}

	protected Intent modifyGeneratedIntent(Intent genIntent, Unit startingUnit) {
		return genIntent;
	}

	public Triplet<String, String, String> generateDatum(String symbol, String generatedValue,
														 Map<String, String> extraLocalKeys) {
		if (generatedValue.equals("Null")) {
			// to reach this path, this extra datum cannot exist
			return null;
		}
		Triplet<String, String, String> extraDatum = null;

		//Local local = symbolLocalMap.get(symbol);
		String key = extraLocalKeys.get(symbol);

//		if (local != null && key != null) {
		String[] symbol_parts = symbol.split("_");
		if (key != null && symbol_parts.length > 1) {
			// if symbol_parts has length of 1, symbol does not contain the "_" character
//			logger.debug(symbol.toString() + "'s key: " + key);
			String symbol_type = symbol_parts[1];
			if (!generatedValue.equals("NotNull")) {
				// extra datum value has a particular value it needs to be set to
				extraDatum = new Triplet<String, String, String>(symbol_type, key, generatedValue.toString().replaceAll("^\"|\"$", ""));
			} else {
				// extra datum value just has to exist
				// create "random" extra datum value for the extra datum  type
				String newGen;
				switch (symbol_type.trim()) {
					case "short":
						newGen = "1";
						break;
					case "int":
						newGen = "1";
						break;
					case "long":
						newGen = "1";
						break;
					case "float":
						newGen = "1.1";
						break;
					case "double":
						newGen = "1.1";
						break;
					case "boolean":
						newGen = "true";
						break;
					case "byte":
						newGen = "1";
						break;
					case "java.lang.String":
						newGen = "a string";
						break;
					case "java.lang.String[]":
						newGen = "abc,abc,abc";
						break;
					case "java.util.ArrayList":
						newGen = "abc,abc,abc";
						break;
					case "long[]":
						newGen = "1,1";
						break;
					case "int[]":
						newGen = "1,1";
						break;
					case "float[]":
						newGen = "1.0,1.0";
						break;
					default:
						newGen = generatedValue.toString().replaceAll("^\"|\"$", "");
				}
				extraDatum = new Triplet<String, String, String>(symbol_type, key, newGen);
			}
		}
		else {
			extraDatum = null;
		}
		return extraDatum;
	}

	public synchronized Pair<Map<String,String>,Boolean> returnSatisfyingModel(Integer fpIdx, Integer sumUpIdx,
																			   Set<String> decls, Set<String> pathCond,
																			   Unit startingUnit, SootMethod method,
																			   Integer analysisMode) throws Z3Exception {

		return returnSatisfyingModelForZ3(fpIdx, sumUpIdx, decls, pathCond, startingUnit, method, analysisMode);
	}

	public synchronized Pair<Map<String,String>,Boolean> returnSatisfyingModelForZ3(Integer fpIdx, Integer sumUpIdx,
																					Set<String> decls, Set<String> pathCond,
																					Unit startingUnit, SootMethod method,
																					Integer analysisMode) throws Z3Exception {

		String pathCondFileName = null;
		try {
			if (isODCG) {
				pathCondFileName = Z3_RUNTIME_SPECS_DIR + File.separator + method.getDeclaringClass().getName() + "_" + startingUnit.getJavaSourceStartLineNumber() + "_z3_path_cond_O_" + fpIdx.toString() + "_" + sumUpIdx.toString();
			} else {
				pathCondFileName = Z3_RUNTIME_SPECS_DIR + File.separator + method.getDeclaringClass().getName() + "_" + startingUnit.getJavaSourceStartLineNumber() + "_z3_path_cond_P_" + fpIdx.toString() + "_" + sumUpIdx.toString();
			}
			System.out.println(java.time.LocalDateTime.now() + "- Sovling the following z3 constraint file: " + pathCondFileName);
			// where z3 file is created
			String outSpec = "";
			// Object can be Null or NotNull
			outSpec +=	"(declare-datatypes () ((Object Null NotNull)))\n" +
						"(declare-fun containsKey (Object String) Bool)\n" +
						"(declare-fun containsKey (String String) Bool)\n" +
						"(declare-fun containsKey (Int String) Bool)\n" +
						"(declare-fun containsKey (Real String) Bool)\n" +

						"(declare-fun getAction (Object) String)\n" +
					    "(declare-fun getUri (Object) Object)\n" +
						"(declare-fun getData (Object) String)\n" +
						"(declare-fun getHost (Object) String)\n" +
						"(declare-fun getScheme (Object) String)\n" +
						"(declare-fun toString (Object) String)\n" +

						"(declare-fun fromIntent (Object) Object)\n" +
						"(declare-fun fromIntent (String) Object)\n" +
						"(declare-fun fromIntent (Int) Object)\n" +
						"(declare-fun fromIntent (Real) Object)\n" +

						"(declare-datatypes () ((ParamRef (mk-paramref (index Int) (type String) (method String)))))\n"+
						"(declare-fun hasParamRef (Object) ParamRef)\n"+
						"(declare-fun hasParamRef (String) ParamRef)\n"+
						"(declare-fun hasParamRef (Object ParamRef) Bool)\n"+
						"(declare-fun hasParamRef (Int) ParamRef)\n"+
						"(declare-fun hasParamRef (Real) ParamRef)\n"+

						"(declare-fun isParamRef (Object ParamRef) Bool)\n"+
						"(declare-fun isParamRef (String ParamRef) Bool)\n"+
						"(declare-fun isParamRef (Int ParamRef) Bool)\n"+
						"(declare-fun isParamRef (Real ParamRef) Bool)\n"+

						"(declare-fun isNull (String) Bool)\n" +
						"(declare-fun isNull (Object) Bool)\n" +
						"(declare-fun oEquals (String Object) Bool)\n" +
						"(declare-fun oEquals (Object String) Bool)\n" +
						"(declare-const cats (Array Int String))\n" +
						"(declare-const keys (Array Int String))\n";
			for (String d : decls) {
				// variable declarations
				outSpec+=d+"\n";
			}
			for (String c : pathCond) {
				// creating constraints on the variables
				outSpec+=c+"\n";
			}
			outSpec+="(check-sat-using (then qe smt))\n";
			outSpec+="(get-model)\n";
			//logger.debug("z3 specification sent to solver:");
			//logger.debug(outSpec);
			PrintWriter out = new PrintWriter(pathCondFileName);
			out.print(outSpec);
			out.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

		String solverLoc = System.getenv("Z3_EXEC");

		ProcessBuilder pb = new ProcessBuilder(solverLoc,pathCondFileName);
//		logger.debug(pb.command().toString());
		/*Map<String,String> env = pb.environment();
		for (Map.Entry<String,String> e : env.entrySet()) {
			logger.debug(e.getKey() + "=" + e.getValue());
		}*/
//		logger.debug("Running z3 solver");
		Process p = null;
		String returnedOutput = null;
		try {
			p = pb.start();
			if(!p.waitFor(3, TimeUnit.SECONDS)) {
				//timeout - kill the process.
				p.destroy(); // consider using destroyForcibly instead
				Boolean isSat = false;
				Map<String,String> model = new ConcurrentHashMap<String,String>();
				if (!debugFlag) {
					Files.deleteIfExists(Paths.get(pathCondFileName));
				}
				System.out.println(java.time.LocalDateTime.now() + "- Finished solving (timedout)");
				return new Pair<Map<String,String>,Boolean>(model,isSat);
			}
			System.out.println(java.time.LocalDateTime.now() + "- Finished solving");
//			logger.debug("Returned input stream as string:");
			returnedOutput = convertStreamToString(p.getInputStream());
//			logger.debug(returnedOutput);
//			logger.debug("Returned error stream as string:");
			String errorOut = convertStreamToString(p.getErrorStream());
//			logger.debug(errorOut);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			//timeout - kill the process.
			p.destroy(); // consider using destroyForcibly instead
			Boolean isSat = false;
			Map<String,String> model = new ConcurrentHashMap<String,String>();
			try {
				if (!debugFlag) {
					Files.deleteIfExists(Paths.get(pathCondFileName));
				}
			} catch (IOException ex) {
				throw new RuntimeException(ex);
			}
			return new Pair<Map<String,String>,Boolean>(model,isSat);
		}

		Map<String,String> model = new ConcurrentHashMap<String,String>();
		Pattern pat = Pattern.compile("\\s+\\(define-fun\\s+(\\S+)\\s+\\(\\)\\s+\\w+\\s+(.+)(?=\\))");
		Matcher m = pat.matcher(returnedOutput);
		while (m.find()) {
			String symbol = m.group(1);
			String value = m.group(2);
			model.put(symbol, value);
		}

		String[] outLines = returnedOutput.split("\\n");
		Boolean isSat = false;
		for (String line : outLines) {
			if (line.trim().equals("sat")) {
				isSat = true;
				break;
			}
		}
		try {
			if (!debugFlag) {
				Files.deleteIfExists(Paths.get(pathCondFileName));
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return new Pair<Map<String,String>,Boolean>(model,isSat);
	}

	static String convertStreamToString(InputStream is) {
		Scanner s = new Scanner(is).useDelimiter("\\A");
		return s.hasNext() ? s.next() : "";
	}

	public Set<String> handleIfStmt(int tabs, IfStmt currIfStmt, Unit succUnit, SootMethod method, SimpleLocalDefs defs,
									Set<String> decls, List<Unit> currPath, Map<Value, String> localSymbolMap,
									Map<String, Value> symbolLocalMap) {

		String returnExpr = "";
		String opVal1Assert = null;
		String opVal2Assert = null;

		Unit opVal1DefUnit = null;
		Unit opVal2DefUnit = null;

		Boolean isSpecialStrOp = false;  // ex: .startsWith

		ConditionExpr condition = (ConditionExpr) currIfStmt.getCondition();
		Value opVal1 = condition.getOp1();
		Value opVal2 = condition.getOp2();

		Value opVal1Org = opVal1;
		//Value opVal2Org = opVal2;

		boolean generateCondExpr = true;
		if (opVal1.getType() instanceof ByteType) {
//			logger.debug("opVal1.getType() instanceof ByteType");
			Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> condValuesPair = findLeftAndRightValuesOfByteVal(method, defs,
					currIfStmt, opVal1, currPath, symbolLocalMap);
			Quartet<Value, String, String, Unit> left = condValuesPair.getValue0();
			Quartet<Value, String, String, Unit> right = condValuesPair.getValue1();
			// defensive check
			if (left == null || right == null) {
				generateCondExpr = false;
			} else {
				opVal1 = left.getValue0();
				opVal2 = right.getValue0();
				if (left.getValue1() != null)
					decls.add(left.getValue1());
				if (right.getValue1() != null)
					decls.add(right.getValue1());
				if (left.getValue2() != null) {
					opVal1Assert = left.getValue2();
				}
				if (right.getValue2() != null) {
					opVal2Assert = right.getValue2();
				}
				opVal1DefUnit = left.getValue3();
				opVal2DefUnit = right.getValue3();
			}
		} else if (opVal1.getType() instanceof BooleanType) {
//			logger.debug("opVal1.getType() instanceof BooleanType");
			Triplet<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>, String> condValuesPair = findStringValuesOfBoolType(method, defs, currIfStmt, opVal1, currPath, symbolLocalMap);
			Quartet<Value, String, String, Unit> left = condValuesPair.getValue0();
			Quartet<Value, String, String, Unit> right = condValuesPair.getValue1();
			String strOp = condValuesPair.getValue2();

			if (left == null) {
				Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> valuesPair = findBundleValues(method, defs,
						currIfStmt, opVal1, currPath, symbolLocalMap);
				left = valuesPair.getValue0();
				right = valuesPair.getValue1();

				if (left!= null || right!=null) {
					generateCondExpr = false;
				}

				if (left!=null) {
					opVal1 = left.getValue0();
				}
				if (right!=null) {
					opVal2 = right.getValue0();
				}
				AssignOpVals assignOpVals = new AssignOpVals(decls, opVal1Assert, opVal2Assert, opVal1, opVal2, left, right).invoke();
				opVal1DefUnit = assignOpVals.getOpVal1DefUnit();
				opVal2DefUnit = assignOpVals.getOpVal2DefUnit();
				opVal1Assert = assignOpVals.getOpVal1Assert();
				opVal2Assert = assignOpVals.getOpVal2Assert();
			}

			if (left != null && right != null) {
				if (left.getValue0() == null && right.getValue0() == null) {
					//findKeysForLeftAndRightValues(currIfStmt, opVal1, opVal2, defs, currPath);
				} else {
					opVal1 = left.getValue0();
					opVal2 = right.getValue0();
					AssignOpVals assignOpVals = new AssignOpVals(decls, opVal1Assert, opVal2Assert, opVal1, opVal2, left, right).invoke();
					opVal1DefUnit = assignOpVals.getOpVal1DefUnit();
					opVal2DefUnit = assignOpVals.getOpVal2DefUnit();
					opVal1Assert = assignOpVals.getOpVal1Assert();
					opVal2Assert = assignOpVals.getOpVal2Assert();

					if (strOp != null && strOp.equals("startsWith") && opVal2 instanceof StringConstant) {
						StringConstant opVal2Const = (StringConstant) opVal2;
						String opExpr1 = createZ3Expr(opVal1, currIfStmt, opVal1DefUnit, method, decls, tabs, localSymbolMap, symbolLocalMap);
						//String opExpr2 = "(str.substr " + opExpr1 + " 0 "+ opVal2Const.value.length() +")";
						//String opExpr2 = "(str.prefixof \"" + opVal2Const.value + "\" " + opExpr1 + ")";
						//String condExpr = "(assert (= \"" + opVal2Const.value + "\" " + opExpr2 + "))";
						String condExpr = buildZ3CondExpr(tabs, "\""+opVal2Const.value+"\"", opExpr1,
								getBranch(currIfStmt, succUnit, opVal1Org, condition),
								"str.prefixof", symbolLocalMap);
						if (opVal1Assert != null) {
							opVal1Assert += "\n"+condExpr;
						} else {
							opVal1Assert = condExpr;
						}
						isSpecialStrOp = true;
					} else if (strOp != null && strOp.equals("endsWith") && opVal2 instanceof StringConstant) {
						StringConstant opVal2Const = (StringConstant) opVal2;
						String opExpr1 = createZ3Expr(opVal1, currIfStmt, opVal1DefUnit, method, decls, tabs, localSymbolMap, symbolLocalMap);
						String condExpr = buildZ3CondExpr(tabs, "\""+opVal2Const.value+"\"", opExpr1,
								getBranch(currIfStmt, succUnit, opVal1Org, condition),
								"str.suffixof", symbolLocalMap);
						if (opVal1Assert != null) {
							opVal1Assert += "\n"+condExpr;
						} else {
							opVal1Assert = condExpr;
						}
						isSpecialStrOp = true;
					} else if (strOp != null && strOp.equals("contains") && opVal2 instanceof StringConstant) {
						StringConstant opVal2Const = (StringConstant) opVal2;
						String opExpr1 = createZ3Expr(opVal1, currIfStmt, opVal1DefUnit, method, decls, tabs, localSymbolMap, symbolLocalMap);
						String condExpr = buildZ3CondExpr(tabs, opExpr1, "\""+opVal2Const.value+"\"",
								getBranch(currIfStmt, succUnit, opVal1Org, condition),
								"str.contains", symbolLocalMap);
						if (opVal1Assert != null) {
							opVal1Assert += "\n"+condExpr;
						} else {
							opVal1Assert = condExpr;
						}
						isSpecialStrOp = true;
					}
				}
			}

			if (left == null && right == null) {
				Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> valuesPair = findCategories(method, defs,
						currIfStmt, opVal1, currPath, symbolLocalMap);
				left = valuesPair.getValue0();
				right = valuesPair.getValue1();

				if (left!= null || right!=null) {
					generateCondExpr = false;
				}

				if (left!=null) {
					opVal1 = left.getValue0();
				}
				if (right!=null) {
					opVal2 = right.getValue0();
				}

				AssignOpVals assignOpVals = new AssignOpVals(decls, opVal1Assert, opVal2Assert, opVal1, opVal2, left, right).invoke();
				if (left == null) {
					opVal1DefUnit = getDefOfValInPath(opVal1, currIfStmt, currPath, defs);
				} else {
					opVal1DefUnit = assignOpVals.getOpVal1DefUnit();
				}
				opVal2DefUnit = assignOpVals.getOpVal2DefUnit();
				opVal1Assert = assignOpVals.getOpVal1Assert();
				opVal2Assert = assignOpVals.getOpVal2Assert();
			}
		} else {
//			logger.debug("else branch, simply invoking findKeysForLeftAndRightValues(...)");
			//findKeysForLeftAndRightValues(currIfStmt, opVal1, opVal2, defs, currPath);
			opVal1DefUnit = getDefOfValInPath(opVal1, currIfStmt, currPath, defs);
			opVal2DefUnit = getDefOfValInPath(opVal2, currIfStmt, currPath, defs);
			Stmt opVal1DefStmt = (Stmt) opVal1DefUnit;
			Stmt opVal2DefStmt = (Stmt) opVal2DefUnit;
			// sharetobrowser has a intent string extra that checks what it starts with
			if (opVal1DefStmt != null && opVal1DefStmt.containsInvokeExpr()) {
				InvokeExpr ie = opVal1DefStmt.getInvokeExpr();
				if (ie.getMethod().getName().equals("length") && ie.getMethod().getDeclaringClass().toString().equals("java.lang.String")) {
					// String length method is called
					String opExpr1 = createZ3Expr(opVal1, currIfStmt, opVal1DefUnit, method, decls, tabs, localSymbolMap, symbolLocalMap);
					Local opStr = (Local) ((JVirtualInvokeExpr) ie).getBase();
					Unit opStrDefUnit = getDefOfValInPath(opStr, currIfStmt, currPath, defs);
					String opExpr2 = "(str.len " + createZ3Expr(opStr, currIfStmt, opStrDefUnit, method, decls, tabs, localSymbolMap, symbolLocalMap) + ")";

					String condExpr = "(assert (= " + opExpr1 + " " + opExpr2 + "))";
					if (opVal1Assert != null) {
						opVal1Assert += "\n"+condExpr;
					} else {
						opVal1Assert = condExpr;
					}
				}
			}
			// check if opVal2 is a constant but given a variable in Jimple. In this case, change it to the constant
			if (opVal2DefStmt instanceof AssignStmt) {
				AssignStmt opVal2AssignStmt = (AssignStmt) opVal2DefStmt;
				if (opVal2AssignStmt.getRightOp() instanceof IntConstant) {
					opVal2 = opVal2AssignStmt.getRightOp();
				}
			}
		}

		Set<String> returnExprs = new LinkedHashSet<String>();
		if (opVal1DefUnit == null && opVal2DefUnit == null && opVal1Assert == null && opVal2Assert == null) {
//			logger.debug("No new information from this if stmt, so returning empty set of expressions");
			return returnExprs;
		}

		// create z3 variable
		String opExpr1 = null;
		String opExpr2 = null;
		try {
			if (opVal1 == null) {
//				logger.debug("Could not resolve opVal1, so setting it to true");
				opExpr1 = "";
			} else {
				opExpr1 = createZ3Expr(opVal1, currIfStmt, opVal1DefUnit, method, decls, tabs, localSymbolMap, symbolLocalMap);
			}

			if (opVal2 == null) {
//				logger.debug("Could not resolve opVal2, so setting it to true");
				opExpr2 = "";
			} else {
				opExpr2 = createZ3Expr(opVal2, currIfStmt, opVal2DefUnit, method, decls, tabs, localSymbolMap, symbolLocalMap);
			}
		} catch (RuntimeException e) {
//			logger.warn("caught exception: ", e);
			return null;
		}

		if (opExpr1 == opExpr2 && opExpr1 == null) {
			return Collections.singleton(returnExpr);
		}

		if (opVal1Assert != null) {
			if (opVal1Assert.contains("select keys index") && opVal2Assert == null) { // handling a hasExtra statement, so do not create additional expressions
				generateCondExpr = false;
			}
		}

		// get z3 constraints
		if (generateCondExpr && !isSpecialStrOp) {
			// generatedCondExpr is initially set to true
			// at different points, can be set to false
			String cond = getBranch(currIfStmt, succUnit, opVal1Org, condition);
			returnExpr = buildZ3CondExpr(tabs, opExpr1, opExpr2, cond , null, symbolLocalMap);
			returnExprs.add(returnExpr);
		}
		if (opVal1Assert != null) {
			returnExprs.add(opVal1Assert);
		}
		if (opVal2Assert != null) {
			returnExprs.add(opVal2Assert);
		}
		return returnExprs;
	}

	private Unit getDefOfValInPath(Value opVal, Unit currUnit, List<Unit> currPath, SimpleLocalDefs defs) {
		Unit defUnit = null;
		if (opVal instanceof Local) {
			Local opLocal1 = (Local) opVal;
			for (Unit opLocalDefUnit : defs.getDefsOfAt(opLocal1, currUnit)) {
				if (currPath.contains(opLocalDefUnit)) {
					defUnit = opLocalDefUnit;
				}
			}
		}
		return defUnit;
	}

	private String getBranch(IfStmt currIfStmt, Unit succUnit, Value opVal1Org, ConditionExpr condition) {
		boolean isFallThrough = isFallThrough(currIfStmt, succUnit);
		// get constraint (in)equalities
		String branchSensitiveSymbol = null;
		if (isFallThrough) {
			if (opVal1Org.getType() instanceof BooleanType) {
				branchSensitiveSymbol = condition.getSymbol();
			} else {
				branchSensitiveSymbol = negateSymbol(condition.getSymbol());
			}
		} else {
			if (opVal1Org.getType() instanceof BooleanType) {
				branchSensitiveSymbol = negateSymbol(condition.getSymbol());
			} else {
				branchSensitiveSymbol = condition.getSymbol();
			}
		}
		return branchSensitiveSymbol;
	}

	private String buildZ3CondExpr(int tabs, String opExpr1, String opExpr2, String branchSensitiveSymbol, String z3func,
								   Map<String, Value> symbolLocalMap) {
		String returnExpr;
		String condExpr = null;

		switch (branchSensitiveSymbol.trim()) {
			case "==":
				if (z3func != null) {
					condExpr = "(assert (= true (" + z3func + " " + opExpr1 + " " + opExpr2 + ")))";
				} else if (opExpr2.equals("Null")) {
					JimpleLocal local = (JimpleLocal) symbolLocalMap.get(opExpr1);
					if (localIsAnZ3Object(local)) {
						condExpr = "(assert (= " + opExpr1 + " Null))";
					} else {
						condExpr = "(assert (= (isNull " + opExpr1 + ") true))";
					}
				} else if (isObjectEquals(opExpr1,opExpr2)) {
					condExpr = "(assert (= (oEquals " + opExpr1 + " " + opExpr2 + ") true))";
				} else {
					condExpr = "(assert (= " + opExpr1 + " " + opExpr2 + "))";
				}
				break;
			case "!=":
				if (z3func != null) {
					condExpr = "(assert (not (= true (" + z3func + " " + opExpr1 + " " + opExpr2 + "))))";
				} else if (opExpr2.equals("Null")) {
					JimpleLocal local = (JimpleLocal) symbolLocalMap.get(opExpr1);
					if (localIsAnZ3Object(local)) {
						condExpr = "(assert (= " + opExpr1 + " NotNull))";
					} else {
						condExpr = "(assert (= (isNull " + opExpr1 + ") false))";
					}
				} else if (isObjectEquals(opExpr1,opExpr2)) {
					condExpr = "(assert (= (oEquals " + opExpr1 + " " + opExpr2 + ") false))";
				} else {
					condExpr = "(assert (not (= " + opExpr1 + " " + opExpr2 + ")))";
				}
				break;
			case ">":
				condExpr = "(assert (> " + opExpr1 + " " + opExpr2 + "))";
				break;
			case ">=":
				condExpr = "(assert (>= " + opExpr1 + " " + opExpr2 + "))";
				break;
			case "<":
				condExpr = "(assert (< " + opExpr1 + " " + opExpr2 + "))";
				break;
			case "<=":
				condExpr = "(assert (<= " + opExpr1 + " " + opExpr2 + "))";
				break;
		}
//		logger.debug(Utils.createTabsStr(tabs) + "z3 conditional expr: " + condExpr);

		if (condExpr == null) {
//            logger.error("currExpr should not be null");
//            logger.debug("opExpr1: " + opExpr1);
//            logger.debug("opExpr2: " + opExpr2);
            throw new RuntimeException("currExpr should not be null");
        }
		returnExpr = condExpr;
		return returnExpr;
	}

	private boolean isObjectEquals(String opExpr1, String opExpr2) {
		if (opExpr1.contains("_java.lang.String_") && !opExpr2.contains("_java.lang.String_") && !opExpr2.contains("\""))
			return true;
		else if (!opExpr1.contains("_java.lang.String_") && opExpr2.contains("_java.lang.String_") && !opExpr2.contains("\""))
			return true;
		else
			return false;
	}

	public void findKeysForLeftAndRightValues(Unit currUnit, Value opVal1, Value opVal2, SimpleLocalDefs defs, List<Unit> currPath) {
		findKeyForVal(currUnit, opVal1, defs, currPath);
		findKeyForVal(currUnit, opVal2, defs, currPath);
	}

	public void findKeyForVal(Unit currUnit, Value opVal, SimpleLocalDefs defs, List<Unit> currPath) {
		if (opVal instanceof Local) {
			Local local = (Local) opVal;
			List<Unit> defUnits = defs.getDefsOfAt(local, currUnit);
			for (Unit defUnit : defUnits) {
				/*if (!currPath.contains(defUnit)) {
					continue;
				}*/
				if (!isDefInPathAndLatest(currPath,defUnit,local,currUnit,defs)) {
					continue;
				}
				if (defUnit instanceof DefinitionStmt) {
					DefinitionStmt defStmt = (DefinitionStmt) defUnit;
					//String key = extractKeyFromIntentExtra(defStmt, defs, currPath);
					/*
					if(key != null) {
						valueKeyMap.put(opVal, key);
					}
					 */
				}
			}
		}
	}

	private String negateSymbol(String symbol) {
		switch (symbol.trim()) {
		case "==":
			return "!=";
		case "!=":
			return "==";
		case ">":
			return "<=";
		case "<":
			return ">=";
		case ">=":
			return "<";
		case "<=":
			return ">";
		default:
			throw new RuntimeException("invalid symbol passed to negateSymbol(): " + symbol);
		}
	}

	private String createZ3Expr(Value opVal, Unit currUnit, Unit defUnit, SootMethod method, Set<String> decls, int tabs,
								Map<Value, String> localSymbolMap, Map<String, Value> symbolLocalMap) {
		String opExpr = null;
		String newDecl = null;

		if (opVal instanceof IntConstant) {
			IntConstant intConst = (IntConstant) opVal;
			opExpr = Integer.toString(intConst.value);

		} else if (opVal instanceof LongConstant) {
			LongConstant longConst = (LongConstant) opVal;
			opExpr = Long.toString(longConst.value);
		} else if (opVal instanceof FloatConstant) {
			FloatConstant floatConst = (FloatConstant) opVal;
			opExpr = Float.toString(floatConst.value);
		} else if (opVal instanceof DoubleConstant) {
			DoubleConstant doubleConst = (DoubleConstant) opVal;
			opExpr = Double.toString(doubleConst.value);
		} else if (opVal instanceof NullConstant) {
			opExpr = "Null";
		} else if (opVal instanceof StringConstant) {
			StringConstant strConst = (StringConstant) opVal;
			opExpr = "\"" + strConst.value + "\"";
		} else if (opVal instanceof JimpleLocal) {
			Local opLocal = (Local) opVal;
//			logger.debug(Utils.createTabsStr(tabs + 1) + "opLocal type: " + opLocal.getType());

			String symbol = null;

			DefinitionStmt defStmt = (DefinitionStmt) defUnit;
			if (defStmt.getLeftOp() == opVal) {
//				symbol = localSymbolMap.get(opLocal);
//				if (symbol == null) {
				symbol = createSymbol(opVal, method, defStmt);
				symbolLocalMap.put(symbol, opLocal);
				localSymbolMap.put(opLocal, symbol);
				opExpr = createConstraintByType(opLocal, symbol, decls);
//				}
			}

//			symbol = localSymbolMap.get(opLocal);
//			if (symbol == null) {
			symbol = createSymbol(opVal, method, defUnit);
			symbolLocalMap.put(symbol, opLocal);
			localSymbolMap.put(opLocal, symbol);
			opExpr = createConstraintByType(opLocal, symbol, decls);
//			}

		} else {
			throw new RuntimeException("I don't know what to do with this Value's type: " + opVal.getType());
		}

		return opExpr;
	}

	String createConstraintByType(Local local, String symbol, Set<String> decls) {
		String declare = null;
		String opExpr = null;
		switch (local.getType().toString().trim()) {
			case "short":
				declare = "(declare-const " + symbol + " Int)";
				opExpr = symbol;
				break;
			case "int":
				declare = "(declare-const " + symbol + " Int)";
				opExpr = symbol;
				break;
			case "long":
				declare = "(declare-const " + symbol + " Int)";
				opExpr = symbol;
				break;
			case "float":
				declare = "(declare-const " + symbol + " Real)";
				opExpr = symbol;
				break;
			case "double":
				declare = "(declare-const " + symbol + " Real)";
				opExpr = symbol;
				break;
			case "boolean":
				declare = "(declare-const " + symbol + " Int)";
				opExpr = symbol;
				break;
			case "byte":
				declare = "(declare-const " + symbol + " Int)";
				opExpr = symbol;
				break;
			case "java.lang.String":
				declare = "(declare-const " + symbol + " String)";
				opExpr = symbol;
				break;
			default:
				// object is an arbitrary type so we'll mark it as null or not null
				declare = "(declare-const " + symbol + " Object)";
				opExpr = symbol;
		}
		if (declare != null) {
			decls.add(declare);
		}
		return opExpr;
	}

	boolean localIsAnZ3Object(JimpleLocal local) {
		// return true if JimpleLocal is a z3 Object
		switch (local.getType().toString().trim()) {
			case "short":
				return false;
			case "int":
				return false;
			case "long":
				return false;
			case "float":
				return false;
			case "double":
				return false;
			case "boolean":
				return false;
			case "byte":
				return false;
			case "java.lang.String":
				return false;
			default:
				return true;
		}
	}

	private static String convertTypeNameForZ3(Type type) {
		String returnStr = type.toString();
		returnStr = returnStr.replace("[]","-Arr");
		return returnStr;
	}

	private static String createParamRefSymbol(Value opVal, int index, SootMethod method, Unit unit) {
		String symbol = null;
		if (unit.getJavaSourceStartLineNumber() > -1)
			symbol = "pr" + index + "_" + convertTypeNameForZ3(opVal.getType()) + "_" + method.getName() + "_" + method.getDeclaringClass().getName() + "_" + String.valueOf(unit.getJavaSourceStartLineNumber());
		else
			symbol = "pr" + index + "_" + convertTypeNameForZ3(opVal.getType()) + "_" + method.getName() + "_" + method.getDeclaringClass().getName();
		return symbol;
	}

	private static String createSymbol(Value opVal, SootMethod method, Unit unit) {
		String valNameNoDollar = opVal.toString();
		valNameNoDollar = valNameNoDollar.replace("<", "_");
		valNameNoDollar = valNameNoDollar.replace(">", "_");
		valNameNoDollar = valNameNoDollar.replace(":", "_");
		valNameNoDollar = valNameNoDollar.replace(" ", "_");
		int unitHash = unit.hashCode();
		String symbol = null;
		if (unit.getJavaSourceStartLineNumber() > -1)
			symbol = valNameNoDollar + "_" + convertTypeNameForZ3(opVal.getType()) + "_" + method.getName() + "_" + method.getDeclaringClass().getName() + "_" + unit.getJavaSourceStartLineNumber() + "_" + unitHash;
		else
			symbol = valNameNoDollar + "_" + convertTypeNameForZ3(opVal.getType()) + "_" + method.getName() + "_" + method.getDeclaringClass().getName() + "_" + unitHash;
		return symbol;
	}

	private class AssignOpVals {
		private Set<String> decls;
		private String opVal1Assert;
		private String opVal2Assert;
		private Value opVal1;
		private Value opVal2;
		private Quartet<Value, String, String, Unit> left;
		private Quartet<Value, String, String, Unit> right;
		private Unit opVal1DefUnit;
		private Unit opVal2DefUnit;

		public AssignOpVals(Set<String> decls, String opVal1Assert, String opVal2Assert, Value opVal1, Value opVal2, Quartet<Value, String, String, Unit> left, Quartet<Value, String, String, Unit> right) {
			this.decls = decls;
			this.opVal1Assert = opVal1Assert;
			this.opVal2Assert = opVal2Assert;
			this.opVal1 = opVal1;
			this.opVal2 = opVal2;
			this.left = left;
			this.right = right;
		}

		public String getOpVal1Assert() {
			return opVal1Assert;
		}

		public String getOpVal2Assert() {
			return opVal2Assert;
		}

		public Unit getOpVal1DefUnit() {
			return opVal1DefUnit;
		}

		public Unit getOpVal2DefUnit() {
			return opVal2DefUnit;
		}

		public AssignOpVals invoke() {
			if (left != null) {
				if (left.getValue1() != null)
					decls.add(left.getValue1());
				if (left.getValue2() != null)
					opVal1Assert = left.getValue2();
				opVal1DefUnit = left.getValue3();
			}

			if (right!=null) {
				if (right.getValue1() != null)
					decls.add(right.getValue1());
				if (right.getValue2() != null)
					opVal2Assert = right.getValue2();
				opVal2DefUnit = right.getValue3();
			}

			return this;
		}
	}
}