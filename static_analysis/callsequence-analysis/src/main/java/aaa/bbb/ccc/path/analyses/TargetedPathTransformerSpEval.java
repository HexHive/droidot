package aaa.bbb.ccc.path.analyses;

import com.google.common.base.Joiner;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.microsoft.z3.Z3Exception;
import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import aaa.bbb.ccc.android.model.*;
import aaa.bbb.ccc.path.analyses.getnatives.FullPathIntra;
import org.javatuples.Pair;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.options.Options;
import soot.shimple.Shimple;
import soot.shimple.ShimpleBody;
import soot.tagkit.BytecodeOffsetTag;
import soot.tagkit.StringConstantValueTag;
import soot.tagkit.Tag;
import soot.toolkits.graph.BriefBlockGraph;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.io.*;
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

public class TargetedPathTransformerSpEval {

	protected static final String DROZER_TARGETED_INTENT_CMDS = "drozer_targeted_intent_cmds_";
	private static String ADB_TARGETED_INTENT_CMDS = "adb_targeted_intent_cmds_";

	static Logger logger = LoggerFactory.getLogger(TargetedPathTransformerSpEval.class);
	private final String Z3_RUNTIME_SPECS_DIR = "z3_runtime_specs";
	private Set<SootClass> dynRegReceivers;

	Map<SootMethod, List<Unit>> methodFinalPaths = new ConcurrentHashMap<SootMethod, List<Unit>>();

	/**
	 * object that performs application-independent path operations
	 */
	private DefaultPathAnalysis pathAnalyses = new DefaultPathAnalysis();

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

	protected JimpleBasedInterproceduralCFG icfg;

	private AndroidProcessor androidProcessor = new AndroidProcessor();

	private ExecutorService executor;

	private int basicBlockSize = Integer.MAX_VALUE;

	private static boolean outInitialization = false;

	Set<Pair<String, Set<Triplet<String, String, Type>>>> writableGenData = new LinkedHashSet<Pair<String, Set<Triplet<String, String, Type>>>>();

	Set<Intent> prevWrittenIntents = new LinkedHashSet<Intent>();
	Set<Pair<Unit, SootMethod>> unitsWithGenData = new LinkedHashSet<Pair<Unit, SootMethod>>();
	Set<Pair<Unit, SootMethod>> unitsWithoutGenData = new LinkedHashSet<Pair<Unit, SootMethod>>();
	Set<Pair<Unit, SootMethod>> targetedUnits = new LinkedHashSet<Pair<Unit, SootMethod>>();
	Set<Pair<Unit, SootMethod>> infeasibleTargets = new LinkedHashSet<Pair<Unit, SootMethod>>();
	Set<Pair<Unit, SootMethod>> possiblyFeasibleNoGenTargets = new LinkedHashSet<Pair<Unit, SootMethod>>();
	Map< SootMethod, Map<Unit, Pair<String,List<UnitPath>>> > methodSummaries = new ConcurrentHashMap<>();

	public Map<List<Unit>, Intent> getPathIntents() {
		return pathIntents;
	}

	Map<List<Unit>, Intent> pathIntents = new ConcurrentHashMap<List<Unit>, Intent>();

	public Boolean pathInsensitiveEval = false;

	public static Integer tmp = 0;

	class CompareInfo {
		String attr;
		String arg;
		String value;
		SootMethod method;
		String currClassName;
		Boolean needsValue;
		String branchCondition;
		Integer extraType;
		String strOp;
		Integer lineNum;
		Boolean first;

		public CompareInfo(String attr, String arg, SootMethod method, String currClassName, Boolean needsValue, String value, String branchCondition, Integer extraType, String strOp, int lineNum, Boolean first) {
			this.attr = attr;  // intent attribute type
			this.arg = arg;  // intent attribute argument
			this.method = method;
			this.currClassName = currClassName;
			this.needsValue = needsValue;  // whether the attribute has an associated value. Eg. getIntExtra("int")
			this.value = value;  // intent attribute value
			this.branchCondition = branchCondition;
			this.extraType = extraType;  // 0: Not-Extra, 1: String, 2: Boolean, 3: Number, 4: Array
			this.strOp = strOp;
			this.lineNum = lineNum;
			this.first = first;  // for path-insensitive analysis. Is this the first intent attribute reached
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			CompareInfo ci = (CompareInfo) o;

			if (!attr.equals(ci.attr)) return false;
			if (value != null) {
				if (!value.equals(ci.value)) return false;
			}
			if (!branchCondition.equals(ci.branchCondition)) return false;
			if (arg != null) {
				if (!arg.equals(ci.arg)) {
					return false;
				}
			}
			if (!method.equals(ci.method)) return false;
			if (!currClassName.equals(ci.currClassName)) return false;
			if (strOp != null) {
				if (!strOp.equals(ci.strOp)) return false;
			}
			if (!Objects.equals(lineNum, ci.lineNum)) return false;
			if (!Objects.equals(extraType, ci.extraType)) return false;
			if (first != ci.first) return false;
			return needsValue == ci.needsValue;
		}

		@Override
		public int hashCode() {
			int result = attr.hashCode();
			if (arg != null) {
				result = 31 * result + arg.hashCode();
			}
			result = 31 * result + method.hashCode();
			result = 31 * result + currClassName.hashCode();
			result = 31 * result + needsValue.hashCode();
			if (value != null) {
				result = 31 * result + value.hashCode();
			}
			result = 31 * result + branchCondition.hashCode();
			if (strOp != null) {
				result = 31 * result + strOp.hashCode();
			}
			result = 31 * result + extraType.hashCode();
			result = 31 * result + lineNum.hashCode();
			result = 31 * result + first.hashCode();
			return result;
		}

		@Override
		public String toString() {
			if (extraType == 1) {
				return "className: " + currClassName + ", method: " + method.getName() + ", lineNum: " + lineNum + ", first: " + first + ", attr: " + attr + ", arg:" + arg + ", needsValue: " + needsValue + ", cmpConst: " + value + ", branchCondition: " + branchCondition + ", strOp: " + strOp;
			} else {
				return "className: " + currClassName + ", method: " + method.getName() + ", lineNum: " + lineNum + ", first: " + first +", attr: " + attr + ", arg:" + arg + ", needsValue: " + needsValue + ", cmpConst: " + value + ", branchCondition: " + branchCondition;
			}
		}

	}

	class UnitPath {
		Set<CompareInfo> pathCond;
		List<Unit> path;

		public UnitPath(Set<CompareInfo> currPathCond, List<Unit> currPath) {
			this.pathCond = currPathCond;
			this.path = currPath;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			UnitPath unitPath = (UnitPath) o;

			//if (!pathCond.equals(unitPath.pathCond)) return false;
			// NOTE: unitpath equals if have same set of CompareInfo
			if (!path.equals(unitPath.path)) return false;
			return pathCond.equals(unitPath.pathCond);
		}

		@Override
		public int hashCode() {
			int result = pathCond.hashCode();
			result = 31 * result + path.hashCode();
			return result;
		}

		public Set<CompareInfo> getPathCond() {
			return pathCond;
		}

		public void setPathCond(Set<CompareInfo> pathCond) {
			this.pathCond = pathCond;
		}

		public List<Unit> getPath() {
			return path;
		}

		public void setPath(List<Unit> path) {
			this.path = path;
		}
	}

	protected int pathsAnalyzedCount = 0;

	public int getPathsAnalyzedCount() {
		return pathsAnalyzedCount;
	}

	public boolean parallelEnabled = false;
	public boolean pathLimitEnabled = true;

	public long mainAnalysisRuntime = -1;

	List jsons = null;

	TargetedPathTransformerSpEval() {
		HashMap<String, String> config = new HashMap<String, String>();
		config.put("model", "true"); // turn on model generation for z3
		pathsAnalyzedCount = 0;
	}

	public Integer totalIcs = 0;  // total intent-controlled statements

	public String apkFilePath;
	public Map<String,Integer> intentCatCountsA = new LinkedHashMap<String,Integer>();
	public Map<String,Integer> intentCatCountsS = new LinkedHashMap<String,Integer>();
	public Map<String,Integer> intentCatCountsR = new LinkedHashMap<String,Integer>();
	public Map<String,Integer> compareOutA = new LinkedHashMap<String,Integer>();
	public Map<String,Integer> compareOutS = new LinkedHashMap<String,Integer>();
	public Map<String,Integer> compareOutR = new LinkedHashMap<String,Integer>();

	public TargetedPathTransformerSpEval(String apkFilePath, List jsons) {
		this();
		G.reset();
		this.apkFilePath = apkFilePath;
		Config.apkFilePath = apkFilePath;
		compareOutA.put("fw", 0);
		compareOutA.put("fwc", 0);
		compareOutA.put("fwi", 0);
		compareOutA.put("fax", 0);
		compareOutA.put("ic3", 0);
		compareOutA.put("iccbot", 0);
		compareOutA.put("lb", 0);
		compareOutA.put("fw-first", 0);
		compareOutA.put("fwc-first", 0);
		compareOutA.put("fwi-first", 0);
		compareOutA.put("fax-first", 0);
		compareOutA.put("ic3-first", 0);
		compareOutA.put("iccbot-first", 0);
		compareOutA.put("lb-first", 0);
		compareOutA.put("total", 0);
		compareOutA.put("cis", 0);
		compareOutS.put("fw", 0);
		compareOutS.put("fwc", 0);
		compareOutS.put("fwi", 0);
		compareOutS.put("fax", 0);
		compareOutS.put("ic3", 0);
		compareOutS.put("iccbot", 0);
		compareOutS.put("lb", 0);
		compareOutS.put("fw-first", 0);
		compareOutS.put("fwc-first", 0);
		compareOutS.put("fwi-first", 0);
		compareOutS.put("fax-first", 0);
		compareOutS.put("ic3-first", 0);
		compareOutS.put("iccbot-first", 0);
		compareOutS.put("lb-first", 0);
		compareOutS.put("total", 0);
		compareOutS.put("cis", 0);
		compareOutR.put("fw", 0);
		compareOutR.put("fwc", 0);
		compareOutR.put("fwi", 0);
		compareOutR.put("fax", 0);
		compareOutR.put("ic3", 0);
		compareOutR.put("iccbot", 0);
		compareOutR.put("lb", 0);
		compareOutR.put("fw-first", 0);
		compareOutR.put("fwc-first", 0);
		compareOutR.put("fwi-first", 0);
		compareOutR.put("fax-first", 0);
		compareOutR.put("ic3-first", 0);
		compareOutR.put("iccbot-first", 0);
		compareOutR.put("lb-first", 0);
		compareOutR.put("total", 0);
		compareOutR.put("cis", 0);
		this.jsons = jsons;
        intentCatCountsA.put("action", 0);
		intentCatCountsA.put("serial", 0);
        intentCatCountsA.put("uri", 0);
        intentCatCountsA.put("uri-nullness", 0);
        intentCatCountsA.put("extras-key", 0);
        intentCatCountsA.put("extras-value", 0);
        intentCatCountsA.put("bundleExtras-key", 0);
        intentCatCountsA.put("bundleExtras-value", 0);
        intentCatCountsA.put("category", 0);
		intentCatCountsS.put("action", 0);
		intentCatCountsS.put("serial", 0);
		intentCatCountsS.put("uri", 0);
		intentCatCountsS.put("uri-nullness", 0);
		intentCatCountsS.put("extras-key", 0);
		intentCatCountsS.put("extras-value", 0);
		intentCatCountsS.put("bundleExtras-key", 0);
		intentCatCountsS.put("bundleExtras-value", 0);
		intentCatCountsS.put("category", 0);
		intentCatCountsR.put("action", 0);
		intentCatCountsR.put("serial", 0);
		intentCatCountsR.put("uri", 0);
		intentCatCountsR.put("uri-nullness", 0);
		intentCatCountsR.put("extras-key", 0);
		intentCatCountsR.put("extras-value", 0);
		intentCatCountsR.put("bundleExtras-key", 0);
		intentCatCountsR.put("bundleExtras-value", 0);
		intentCatCountsR.put("category", 0);
	}

	// Inter-procedural analysis
	public void main(boolean isODCG){
		logger.debug("Extracting data from manifest");
		androidProcessor.extractApkMetadata();

		logger.debug("Constructing entry points");
		Hierarchy h = Scene.v().getActiveHierarchy();
		List<SootMethod> nonLifeCycleEntryPoints = new ArrayList<SootMethod>();
		// dynamic registration
		for (SootClass c : Scene.v().getApplicationClasses()) {
			if (c.isInterface() || c.getPackageName().startsWith("android.")) {
				// Don't care about non-implementation
				// Don't care about non-user code
				continue;
			}
			for (SootClass superClass : h.getSuperclassesOfIncluding(c)) {
				if (superClass.isInterface()) {
					continue;
				}
				if (superClass.getName().equals("android.support.v4.content.Loader")) {
					for (SootMethod m : c.getMethods()) {
						if (m.isConcrete() && m.getName().startsWith("on")) {
							logger.debug("Marking " + m + " as a new entry point");
							nonLifeCycleEntryPoints.add(m);
						}
					}
				}
			}
		}
		List<SootMethod> newEntryPoints = new ArrayList<SootMethod>(Scene.v().getEntryPoints());
		newEntryPoints.addAll(nonLifeCycleEntryPoints);
		Scene.v().setEntryPoints(newEntryPoints);
		logger.debug("Entry points identified and added to Scene");

		logger.debug("Constructing CHA call graph");
		Options.v().set_time(false);
		CHATransformer.v().transform();
		logger.debug("CHA call graph built");

		List<SootMethod> rtoMethods = Utils.getMethodsInReverseTopologicalOrder();

		for (SootMethod m : rtoMethods) {
			if (m.getDeclaringClass().getName().contains("PackageIntentReceiver")) {
				logger.debug("Found method of PackageIntentReceiver: " + m);
			}
		}

		// dynamic registration
		dynRegReceivers = new LinkedHashSet<SootClass>();  // EX: BroadcastReceivers
		List<SootMethod> dynRegReceiverEntryPoints = new ArrayList<SootMethod>();
		for (SootMethod m : rtoMethods) {
			if (m.hasActiveBody()) {
				Body b = m.retrieveActiveBody();
				for (Unit u : b.getUnits()) {
					Stmt s = (Stmt) u;
					if (s.containsInvokeExpr()) {
						InvokeExpr ie = s.getInvokeExpr();
						if (ie.getMethod().getDeclaringClass().isInterface()) {
							continue;
						}

						for (SootClass superClass : h.getSuperclassesOfIncluding(ie.getMethod().getDeclaringClass())) {
							if (superClass.getName().equals("android.content.Context")) {
								if (ie.getMethod().getName().equals("registerReceiver")) {
									logger.debug("Found android.content.Context.registerReceiver invocation at + " + u + " in " + m);
									String registeredType = ie.getArg(0).getType().toString();

									logger.debug("Type registered here: " + registeredType);
									SootClass receiverClass = Scene.v().getSootClass(registeredType);
									dynRegReceivers.add(receiverClass);
									for (SootMethod regTypeMethod : receiverClass.getMethods()) {
										if (regTypeMethod.getName().startsWith("on") && regTypeMethod.isConcrete()) {
											dynRegReceiverEntryPoints.add(regTypeMethod);
										}
									}
								}
							}
						}
					}
				}
			}
		}

		if (!dynRegReceiverEntryPoints.isEmpty()) {
			newEntryPoints.addAll(dynRegReceiverEntryPoints);
			logger.debug("Constructing CHA call graph with entry points for dynamically registered receivers");
			Options.v().set_time(false);
			CHATransformer.v().transform();
			logger.debug("CHA call graph built");
			logger.debug("Recomputing RTO methods");
			rtoMethods = Utils.getMethodsInReverseTopologicalOrder();
		}

		String RECEIVER_FULL_PKG_NAME = "android.content.BroadcastReceiver";
		for (SootClass c : Scene.v().getApplicationClasses()) {
			if (c.isInterface()) {
				continue;
			}
			for (SootClass superClass : h.getSuperclassesOf(c)) {
				if (superClass.getName().equals(RECEIVER_FULL_PKG_NAME)) {
					logger.debug(c + " is a broadcast receiver");
				}
			}
		}

		icfg = new JimpleBasedInterproceduralCFG();

		try {
			int currMethodCount = 1;
			logger.debug("total number of possible methods to analyze: " + rtoMethods.size());

			executor = null;
			logger.debug(">>> parallism on: " + String.valueOf(parallelEnabled));
			executor = Executors.newSingleThreadExecutor();
			/*
			if (parallelEnabled) {
				executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
			}else{
				executor = Executors.newSingleThreadExecutor();
			}
			 */
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

			long mainAnalysisStartTime = System.currentTimeMillis();
			for (SootMethod method : rtoMethods) {
				// filter out methods we cannot identify the component of
				String currClassName = method.getDeclaringClass().getName();
				Component comp = androidProcessor.findComponent(currClassName);
				if (comp == null) {
					for (SootClass dynReceiver : dynRegReceivers) {
						if (dynReceiver.getName().equals(currClassName)) {
							comp = new Receiver(currClassName);
							comp.setExported(true);
						}
					}
				}
				Boolean canIdComp = false;
				if (comp instanceof Activity) {
					canIdComp = true;
				} else if (comp instanceof Service) {
					canIdComp = true;
				} else if (comp instanceof Receiver) {
					canIdComp = true;
				} else if (Utils.extendFromActivity(currClassName)) {
					canIdComp = true;
				}
				if (!canIdComp) {
					continue;
				}
				//logger.debug("Checking if I should analyze method: " + method);
				//System.out.println("Checking if I should analyze method: " + method);
				if (Utils.isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
					if (method.hasActiveBody()) {
						// analyze method
						// will update MethodSummaries (sub sub sub call..)
						// will write the ...z3_path_cond file
						// will generate intents to data/ if encountered
						Collection<Future<?>> futures = new LinkedList<Future<?>>();
						doPathAnalysis(method, futures, false);
						for (Future<?> future : futures) {
							try {
								future.get(3, TimeUnit.MINUTES);
							} catch (TimeoutException e) {
								future.cancel(true);  // send interrupt to thread
							}
						}
						// perform intraprocedural analysis to mark the units in methodSummaries[method] that
						// will always be called by another unit that is also in methodSummaries[method] for
						// interprocedural expansion
						UnitGraph ug = new BriefUnitGraph(method.getActiveBody());
						if (methodSummaries.containsKey(method)) {
							Map< Unit, Pair<String,List<UnitPath>> > unitSum = methodSummaries.get(method);
							Set<Unit> unitSumKeys = unitSum.keySet();
							FullPathIntra intraAnalysis = new FullPathIntra(ug, unitSumKeys);
							List<Unit> fullPaths = new ArrayList<Unit>();
							for (Map.Entry< Unit, Pair<String,List<UnitPath>> > ue : unitSum.entrySet()) {
								Unit u = ue.getKey();
								if (intraAnalysis.getFlowAfter(u).isEmpty()) {
									// get paths where it ends at a JNI call that will not be followed by another JNI
									fullPaths.add(u);
								}
							}
							methodFinalPaths.put(method, fullPaths);
						}
					} else {
						logger.debug("method " + method + " has no active body, so it won't be analyzed.");
					}
				}
				logger.debug("Finished path analysis on method: " + method);
				logger.debug("Number of methods analyzed: " + currMethodCount);
				currMethodCount++;
			}

			System.out.println("Finishing executor...");
			executor.shutdown();  // stop allowing new task to be added
			System.out.println("Executor shutdown...");
			executor.shutdownNow();  // stop all tasks. Analysis is done
			System.out.println("Executor shutdownNow() finished...");

			Integer ics = 0;
			// iterate each UnitPath's intent-controlled statements for evaluation with tools
			for (Map.Entry< SootMethod, Map<Unit, Pair<String,List<UnitPath>>> > e : methodSummaries.entrySet()) {
				SootMethod m = e.getKey();
				Map<Unit, Pair<String,List<UnitPath>>> unitSum = e.getValue();
				for (Map.Entry<Unit, Pair<String,List<UnitPath>>> ue : unitSum.entrySet()) {
					ics += 1;  // each intent-controlled statement
					Unit u = ue.getKey();
					Pair<String,List<UnitPath>> pathsInfo = ue.getValue();
					String compName = pathsInfo.getValue0();
					List<UnitPath> paths = pathsInfo.getValue1();
					System.out.println( "COMP: " + compName + ", UNIT: " + u.getJavaSourceStartLineNumber() + " " + u);
					boolean firstPath = true;
					for (UnitPath p : paths) {
						Set<CompareInfo> cis = p.getPathCond();  // necessary intent attribute along path
						// if a tool identifies all the Intent attributes in cis (along a path), then we count it
						// as 1 success (all or nothing)
						int fwTotal = 0;  // total per path
						int fwcTotal = 0;
						int fwiTotal = 0;
						int ic3Total = 0;
						int iccbotTotal = 0;
						int faxTotal = 0;
						int lbTotal = 0;
						System.out.println("intent along path:");
						for (CompareInfo ci : cis) {
							System.out.println("<ATTRIBUTE> " + ci);
							// check each attribute

							if (jsons == null)  {
								continue;
							}

							List<Integer> currCiOut = null;  // fw, ic3, iccbot, fax
							boolean isFirstCi = false;
							currCiOut = compareTools(ci.attr, ci.arg, ci.method, ci.currClassName, ci.needsValue, ci.value, ci.extraType, ci.branchCondition, ci.lineNum);
							if (ci.first && firstPath) {
								firstPath = false;
								// could be the first compareInfo for a path-insensitive comparison
								isFirstCi = true;

							}

							if (currCiOut.get(0) > 0) {
								// whether current attribute in path is found by fw
								fwTotal += 1;
								if (isFirstCi) {
									updateCompareOutFirst("fw", compName);
								}
							}
							if (currCiOut.get(1) > 0) {
								// whether current attribute in path is found by ic3
								ic3Total += 1;
								if (isFirstCi) {
									updateCompareOutFirst("ic3", compName);
								}
							}
							if (currCiOut.get(2) > 0) {
								// whether current attribute in path is found by iccbot
								iccbotTotal += 1;
								System.out.println("DETECTED1: " + ci);
								if (isFirstCi) {
									tmp += 1;
									System.out.println("DETECTED2: " + ci);
									updateCompareOutFirst("iccbot", compName);
								}
							}
							if (currCiOut.get(3) > 0) {
								// whether current attribute in path is found by fax
								faxTotal += 1;
								if (isFirstCi) {
									updateCompareOutFirst("fax", compName);
								}
							}
							if (currCiOut.get(4) > 0) {
								// whether current attribute in path is found by fw with cg reduction
								fwcTotal += 1;
								if (isFirstCi) {
									updateCompareOutFirst("fwc", compName);
								}
							}
							if (currCiOut.get(5) > 0) {
								// whether current attribute in path is found by fw intra-procedural
								fwiTotal += 1;
								if (isFirstCi) {
									updateCompareOutFirst("fwi", compName);
								}
							}
							if (currCiOut.get(6) > 0) {
								// whether current attribute in path is found by letterbomb
								lbTotal += 1;
								if (isFirstCi) {
									updateCompareOutFirst("lb", compName);
								}
							}
						}
						updateCompareOutPerPath(compName);
						// check all or nothing per path
						if (fwTotal == cis.size()) {
							updateCompareOut("fw", compName);
						}
						if (ic3Total == cis.size()) {
							updateCompareOut("ic3", compName);
						}
						if (iccbotTotal == cis.size()) {
							updateCompareOut("iccbot", compName);
						}
						if (faxTotal == cis.size()) {
							updateCompareOut("fax", compName);
						}
						if (fwcTotal == cis.size()) {
							updateCompareOut("fwc", compName);
						}
						if (fwiTotal == cis.size()) {
							updateCompareOut("fwi", compName);
						}
						if (lbTotal == cis.size()) {
							updateCompareOut("lb", compName);
						}
					}
				updateCompareOutPerIcs(compName);
				}
			}
			totalIcs = ics;
			System.out.println("TMP: " + tmp);
		} catch (ExecutionException|InterruptedException e) {
			throw new RuntimeException(e);
		}
	}


	public void updateCompareOutPerIcs(String compName) {
		if (compName.equals("Activity")) {
			compareOutA.put("cis", compareOutA.get("cis") + 1);
		} else if (compName.equals("Service")) {
			compareOutS.put("cis", compareOutS.get("cis") + 1);
		} else {  // Receiver
			compareOutR.put("cis", compareOutR.get("cis") + 1);
		}
	}

	public void updateCompareOutPerPath(String compName) {
		if (compName.equals("Activity")) {
			compareOutA.put("total", compareOutA.get("total") + 1);
		} else if (compName.equals("Service")) {
			compareOutS.put("total", compareOutS.get("total") + 1);
		} else {  // Receiver
			compareOutR.put("total", compareOutR.get("total") + 1);
		}
	}

	public void updateCompareOut(String tool, String compName) {
		if (compName.equals("Activity")) {
			compareOutA.put(tool, compareOutA.get(tool) + 1);
		} else if (compName.equals("Service")) {
			compareOutS.put(tool, compareOutS.get(tool) + 1);
		} else {  // Receiver
			compareOutR.put(tool, compareOutR.get(tool) + 1);
		}
	}

	public void updateCompareOutFirst(String tool, String compName) {
		if (compName.equals("Activity")) {
			compareOutA.put(tool+"-first", compareOutA.get(tool+"-first") + 1);
		} else if (compName.equals("Service")) {
			compareOutS.put(tool+"-first", compareOutS.get(tool+"-first") + 1);
		} else {  // Receiver
			compareOutR.put(tool+"-first", compareOutR.get(tool+"-first") + 1);
		}
	}

    public List<Integer> compareTools(String attr,
									  String arg,
									  SootMethod method,
									  String currClassName,
									  Boolean needsValue,
									  String value,
									  Integer extraType,
									  String branchCondition,
									  Integer lineNum) {
        // arg : argument of Intent extraction method
        // needsValue : does Intent-controlled statement requires extra data value
		Integer fwOut = 0;
		Integer ic3Out = 0;
		Integer iccbotOut = 0;
		Integer faxOut = 0;
		Integer fwcOut = 0;
		Integer fwiOut = 0;
		Integer lbOut = 0;
		String cmpValue = value;
		/*
		if (needsValue) {
			cmpValue = value;
		} else {
			System.out.println("");
		}
		 */

        if (needsValue) {
            // only phenomenon and fax can identify extra data / Bundle value
            if (fwCanId(attr, arg, method.getName(), currClassName, cmpValue, extraType, branchCondition, lineNum, 0)) {
				// phenomenon
				fwOut = 1;
			}
			if (fwCanId(attr, arg, method.getName(), currClassName, cmpValue, extraType, branchCondition, lineNum, 1)) {
				// phenomenon with cg reduction
				fwcOut = 1;
			}
			if (fwCanId(attr, arg, method.getName(), currClassName, cmpValue, extraType, branchCondition, lineNum, 2)) {
				// phenomenon intra-procedural
				fwiOut = 1;
			}
			if (fwCanId(attr, arg, method.getName(), currClassName, cmpValue, extraType, branchCondition, lineNum, 3)) {
				// letterbomb
				lbOut = 1;
			}
			if (faxCanId(attr, arg, method.getName(), currClassName, cmpValue, extraType, branchCondition, lineNum)) {
				faxOut = 1;
			}
        } else {
            // track previous attr value
			// ic3 JSON uses method signature produced by Soot
			// ic3 has two JSONs
			if (ic3CanId(attr, arg, method.getSignature(), currClassName, cmpValue, extraType, branchCondition, lineNum)) {
				ic3Out = 1;
			} else {
				if (ic3CanIdExit(attr, arg, method.getSignature(), currClassName, cmpValue, extraType, branchCondition, lineNum)) {
					ic3Out = 1;
				}
			}
			if (iccBotCanId(attr, arg, method.getName(), currClassName, cmpValue, extraType, branchCondition, lineNum)) {
				iccbotOut = 1;
			}
			if (fwCanId(attr, arg, method.getName(), currClassName, cmpValue, extraType, branchCondition, lineNum, 0)) {
				fwOut = 1;
			}
			if (fwCanId(attr, arg, method.getName(), currClassName, cmpValue, extraType, branchCondition, lineNum, 1)) {
				fwcOut = 1;
			}
			if (fwCanId(attr, arg, method.getName(), currClassName, cmpValue, extraType, branchCondition, lineNum, 2)) {
				fwiOut = 1;
			}
			if (fwCanId(attr, arg, method.getName(), currClassName, cmpValue, extraType, branchCondition, lineNum, 3)) {
				// letterbomb
				lbOut = 1;
			}
			if (faxCanId(attr, arg, method.getName(), currClassName, cmpValue, extraType, branchCondition, lineNum)) {
				faxOut = 1;
			}
        }

		List<Integer> out = new ArrayList<>();  // fw, ic3, iccbot, fax, fwc, fwi
		out.add(fwOut);
		out.add(ic3Out);
		out.add(iccbotOut);
		out.add(faxOut);
		out.add(fwcOut);
		out.add(fwiOut);
		out.add(lbOut);
		return out;
    }

	public boolean faxCanId(String attr, String arg, String method, String currClassName, String cmpValue, Integer extraType, String branchCondition, Integer lineNum) {
		String branchConditionTrimmed = branchCondition.trim();
		JSONObject faxobj = (JSONObject) jsons.get(4);

		if (faxobj == null) {
			return false;
		}
		if (!faxobj.keySet().contains(currClassName)) {
			return false;
		}
		JSONArray comp = (JSONArray) faxobj.get(currClassName);

		String key = null;
		if (attr.equals("uri-nullness")) {
			key = "data";
		} else if (attr.equals("extras-value")) {
			key = "extras";
		} else if (attr.equals("extras-key")) {
			key = "extras";
		} else if (attr.equals("bundleExtras-key")) {
			key = "extras";
		} else if (attr.equals("bundleExtras-value")) {
			key = "extras";
		} else if (attr.equals("category")) {
			key = "category";
		} else if (attr.equals("action")) {
			key = "action";
		}
		Iterator compIter = comp.iterator();
		while (compIter.hasNext()) {
			JSONObject currIntent = (JSONObject) compIter.next();
			if (currIntent.keySet().contains(key)) {
				if (key.equals("data")) {
					if (branchConditionTrimmed.equals("!=")) {
						// check uri is not null
						if (!((String)currIntent.get("data")).equals("")) {
							// uri is not null
							return true;
						}
					} else if (branchConditionTrimmed.equals("==")) {
						// check uri is null
						if (((String)currIntent.get("data")).equals("")) {
							// uri is null
							return true;
						}
					}
				} else if (key.equals("extras")) {
					JSONArray extras = (JSONArray) currIntent.get(key);
					Iterator extrasIter = extras.iterator();
					while (extrasIter.hasNext()) {
						String eItem = (String) extrasIter.next();
						String[] eItemSplit = eItem.split("->");
						if (eItemSplit.length != 3) {
							// not a string corresponding to an extra
							continue;
						}
						if (eItemSplit[1].equals(arg)) {
							if (cmpValue == null) {
								// only a extra key check
								return true;
							}
						}
					}

				} else if (key.equals("category")) {
					if (arg == null) {
						// getCategories()
						if (branchConditionTrimmed.equals("==")) {
							// no categories
							if (((String)currIntent.get("category")).equals("")) {
								return true;
							}
						} else if (branchConditionTrimmed.equals("!=")) {
							// has categories
							if (!((String)currIntent.get("category")).equals("")){
								return true;
							}
						}
					}
				} else if (key.equals("action")) {
					// contains action
					if (branchConditionTrimmed.equals("==")) {
						// check existence of cmpValue
						if (((String)currIntent.get(key)).contains(cmpValue)) {
							return true;
						}
					} else if (branchConditionTrimmed.equals("!=")) {
						// check non-existence of cmpValue
						if (!((String)currIntent.get(key)).contains(cmpValue)) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}

    public boolean fwCanId(String attr, String arg, String method, String currClassName, String cmpValue, Integer extraType, String branchCondition, Integer lineNum, Integer fwVersion) {
		String branchConditionTrimmed = branchCondition.trim();
        JSONObject fwobj;
		if (fwVersion == 0) {
			// phenomenon
			fwobj = (JSONObject) jsons.get(2);
		} else if (fwVersion == 1) {
			// phenomenon with cg reduction
			fwobj = (JSONObject) jsons.get(5);
		} else if (fwVersion == 2) {
			// phenomenon intra-procedural
			fwobj = (JSONObject) jsons.get(6);
		} else {
			// letterbomb
			fwobj = (JSONObject) jsons.get(7);
		}

		if (fwobj == null) {
			return false;
		}
        if (!fwobj.keySet().contains(currClassName)) {
            return false;
        }

		JSONArray comp = (JSONArray) fwobj.get(currClassName);

        String key = null;
        if (attr.equals("uri-nullness")) {
           key = "uri";
        } else if (attr.equals("extras-value")) {
            key = "extras";
        } else if (attr.equals("extras-key")) {
            key = "extras";
        } else if (attr.equals("bundleExtras-key")) {
            key = "extras";
        } else if (attr.equals("bundleExtras-value")) {
            key = "extras";
        } else if (attr.equals("category")) {
            key = "categories";
        } else if (attr.equals("action")) {
            key = "action";
        }
        Iterator compIter = comp.iterator();
        while (compIter.hasNext()) {
            JSONObject currIntent = (JSONObject) compIter.next();
            if (currIntent.keySet().contains(key)) {
                if (key.equals("uri")) {
					if (branchConditionTrimmed.equals("!=")) {
						// check uri is not null
						if (((String)currIntent.get(key)).equals("NotNull")) {
							// uri is not null
							return true;
						}
					} else if (branchConditionTrimmed.equals("==")) {
						// check uri is null
						if (((String)currIntent.get(key)).equals("Null")) {
							// uri is null
							return true;
						}
					}
                } else if (key.equals("extras")) {
                    // extras is a list
					Boolean notNull = false;
                    JSONArray extras = (JSONArray) currIntent.get(key);
                    Iterator extrasIter = extras.iterator();
                    while (extrasIter.hasNext()) {
                        JSONObject eItem = (JSONObject) extrasIter.next();
                        if (arg != null) {
                            if (eItem.containsKey("val1") && eItem.get("val1").equals(arg)) {
								if (extraType == 1) {  // string operations
									// string operation
									if (branchConditionTrimmed.equals("==")) {
										// check existence of cmpValue
										if (eItem.containsKey("val2") && ((String)eItem.get("val2")).contains(cmpValue)) {
											return true;
										}
									} else if (branchConditionTrimmed.equals("!=")) {
										// check non-existence of cmpValue
										if (eItem.containsKey("val2") && !((String)eItem.get("val2")).contains(cmpValue)) {
											return true;
										}
									}
								} else if (extraType == 3) {
									// number operation
									Integer cmpNum;
									Integer extraNum;
									try {
										cmpNum = Integer.parseInt(cmpValue);
										extraNum = Integer.parseInt((String)eItem.get("val2"));
									} catch (NumberFormatException nfe) {
										continue;
									}
									// check against branchCondition
									if (branchConditionTrimmed.equals("==")) {
										if (extraNum == cmpNum) {
											return true;
										}
									} else if (branchConditionTrimmed.equals("!=")) {
										if (extraNum != cmpNum) {
											return true;
										}
									} else if (branchConditionTrimmed.equals("<=")) {
										if (extraNum <= cmpNum) {
											return true;
										}
									} else if (branchConditionTrimmed.equals(">=")) {
										if (extraNum >= cmpNum) {
											return true;
										}
									} else if (branchConditionTrimmed.equals("<")) {
										if (extraNum < cmpNum) {
											return true;
										}
									} else if (branchConditionTrimmed.equals(">")) {
										if (extraNum > cmpNum) {
											return true;
										}
									}
								} else if (extraType == 2) {
									// boolean operation
									if (branchConditionTrimmed.equals("==")) {
										if (eItem.containsKey("val2") && !((String)eItem.get("val2")).equals("0")) {
											// 0: false, any other num: true
											return true;
										}
									} else if (branchConditionTrimmed.equals("!=")) {
										if (eItem.containsKey("val2") && ((String)eItem.get("val2")).equals("0")) {
											// 0: false, any other num: true
											return true;
										}
									}
								} else if (extraType == 4) {
									// array operation
									if (branchConditionTrimmed.equals("!=")) {
										if (eItem.containsKey("val2") && ((String)eItem.get("val2")).equals("NotNull")) {
											return true;
										}
									} else if (branchConditionTrimmed.equals("==")) {
										if (eItem.containsKey("val2") && ((String)eItem.get("val2")).equals("NotNull")) {
											notNull = true;
											break;
										}
									}
								} else if (extraType == 0) {
									// other operation (e.g., Bundle.containsKey)
									if (cmpValue == null) {
										if (branchConditionTrimmed.equals("!=")) {
											// check is not null
											if (eItem.containsKey("val2") && ((String)eItem.get("val2")).equals("NotNull")) {
												return true;
											}
										} else if (branchConditionTrimmed.equals("==")) {
											// check is null
											if (eItem.containsKey("val2") && ((String)eItem.get("val2")).equals("NotNull")) {
												notNull = true;
											}
										}
									}
								}
                            }
                        }
                    }
					// check for NULL (Bundle.containsKey, array extra null check)
					if (key.equals("extras") && ( (extraType==0||extraType==4) && cmpValue==null) ) {
						if (!notNull) {
							// is null
							return true;
						}
					}
                } else if (key.equals("categories")) {
                    // categories is a list
                    JSONArray categories = (JSONArray) currIntent.get(key);
                    if (arg == null) {
                        // getCategories()
						if (branchConditionTrimmed.equals("==")) {
							// no categories
							if (categories.size() == 0) {
								return true;
							}
						} else if (branchConditionTrimmed.equals("!=")) {
							// has categories
							if (categories.size() != 0){
								return true;
							}
						}
                    }
					Boolean foundCategory = false;
                    Iterator categoriesIter = categories.iterator();
                    while (categoriesIter.hasNext()) {
                        String cItem = (String) categoriesIter.next();
						if (branchConditionTrimmed.equals("==")) {
							if (cItem.equals(arg)) {
								// found the category in the list
								return true;
							}
						}
						if (cItem.equals(arg)) {
							foundCategory = true;
						}
                    }
					if (branchConditionTrimmed.equals("!=") && !foundCategory) {
						// branchCondition does not want category in list
						// did not find category in list if foundCategory is false
						return true;
					}
                } else if (key.equals("action")) {
                    // contains action
					if (branchConditionTrimmed.equals("==")) {
						// check existence of cmpValue
						if (((String)currIntent.get(key)).contains(cmpValue)) {
							return true;
						}
					} else if (branchConditionTrimmed.equals("!=")) {
						// check non-existence of cmpValue
						if (!((String)currIntent.get(key)).contains(cmpValue)) {
							return true;
						}
					}
                }
            }
        }
        return false;
    }

    public boolean ic3CanIdExit(String attr, String arg, String methodSignature, String currClassName, String cmpValue, Integer extraType, String branchCondition, Integer lineNum) {
        // action, URI, and categories IC3 identifies is at the component-level
        // only extras are at the method-level. methodSignature is relevant for extras
        // (with the exception if the extra is extracted from exit_points)
        // action, URI, and categories are identified based on manifest's intent filters
		String branchConditionTrimmed = branchCondition.trim();
        JSONObject ic3exitsobj = (JSONObject) jsons.get(3);
		if (ic3exitsobj == null) {
			return false;
		}
        if (!ic3exitsobj.keySet().contains(currClassName)) {
            return false;
        }
        JSONObject comp = (JSONObject) ic3exitsobj.get(currClassName);

        String key = null;
        if (attr.equals("uri-nullness")) {
           // "kind": "TYPE",
           key = "URI";
        } else if (attr.equals("extras-value")) {
            key = "EXTRA";
        } else if (attr.equals("extras-key")) {
            key = "EXTRA";
        } else if (attr.equals("bundleExtras-key")) {
            key = "EXTRA";
        } else if (attr.equals("bundleExtras-value")) {
            key = "EXTRA";
        } else if (attr.equals("category")) {
            // "kind": "CATEGORY",
            key = "CATEGORY";
        } else if (attr.equals("action")) {
            // "kind": "ACTION",
            key = "ACTION";
        }
		if (key.equals("URI") && branchConditionTrimmed.equals("==")) {
			// check uri does not exist
			if (!comp.keySet().contains(key)) {
				return true;
			} else {
				JSONArray uris = (JSONArray) comp.get(key);
				if (uris.size() == 0) {
					return true;
				}
			}
		}

		if (key.equals("URI")) {
			if (branchConditionTrimmed.equals("!=")) {
				// check URI is not null
				if (comp.keySet().contains(key)) {
					JSONArray uris = (JSONArray) comp.get(key);
					if (uris.size() != 0) {
						return true;
					}
				}
			}
		} else if (key.equals("ACTION")) {
			// if action is not in comp it action list will not be present
			if (comp.keySet().contains(key)) {
				JSONArray actions = (JSONArray) comp.get(key);
				if (branchConditionTrimmed.equals("==")) {
					// contains action
					Iterator actionsIter = actions.iterator();
					while (actionsIter.hasNext()) {
						String aItem = (String) actionsIter.next();
						if (aItem.contains(cmpValue)) {
							return true;
						}
					}
				} else if (branchConditionTrimmed.equals("!=")) {
					// not contains action
					if (actions.size() == 0) {
						return true;
					}
					Boolean noAction = true;
					Iterator actionsIter = actions.iterator();
					while (actionsIter.hasNext()) {
						String aItem = (String) actionsIter.next();
						if (aItem.contains(cmpValue)) {
							noAction = false;
							break;
//							return true;
						}
					}
					if (noAction) {
						return true;
					}
				}
			}
		} else if (key.equals("CATEGORY")) {
			if (comp.keySet().contains(key)) {
				JSONArray categories = (JSONArray) comp.get(key);
				if (arg == null) {
					// getCategories()
					if (branchConditionTrimmed.equals("!=")) {
						if (categories.size() != 0) {
							return true;
						}
					} else if (branchConditionTrimmed.equals("==")) {
						if (categories.size() == 0) {
							return true;
						}
					}
				}
				if (arg != null && branchConditionTrimmed.equals("==") && categories.size() == 0) {
					// null check
					return true;
				}
				Iterator categoriesIter = categories.iterator();
				Boolean noCategory = true;
				while (categoriesIter.hasNext()) {
					String cItem = (String) categoriesIter.next();
					if (arg != null) {
						// hasCategory(x)
						if (branchConditionTrimmed.equals("!=")) {
							// check category exist
							if (cItem.contains(arg)) {
								// key found
								return true;
							}
						} else if (branchConditionTrimmed.equals("==")) {
							// check category does not exist
							if (cItem.contains(arg)) {
								// key found
								noCategory = false;
								break;
							}
						}
					}
				}
				if (arg != null && branchConditionTrimmed.equals("==") && noCategory) {
					return true;
				}
			}
		} else if (key.equals("EXTRA")) {
			if (comp.keySet().contains(key)) {
				JSONArray extras = (JSONArray) comp.get(key);
				Iterator extrasIter = extras.iterator();
				Boolean noExtra = true;
				while (extrasIter.hasNext()) {
					String eItem = (String) extrasIter.next();
					if (arg != null) {
						if (branchConditionTrimmed.equals("!=")) {
							// check extra key exists
							if (eItem.equals(arg)) {
								// key found
								return true;
							}
						} else if (branchConditionTrimmed.equals("==")) {
							// check extra key does not exist
							if (eItem.equals(arg)) {
								// key found
								noExtra = false;
								break;
							}
						}
					}
				}
				if (arg != null && branchConditionTrimmed.equals("==") && noExtra) {
					return true;
				}
			}
		}

       return false;
    }

    public boolean ic3CanId(String attr, String arg, String methodSignature, String currClassName, String cmpValue, Integer extraType, String branchCondition, Integer lineNum) {
        // TODO: need to pre-process ic3 output so components contain information in exit-points
        // action, URI, and categories IC3 identifies is at the component-level
        // only extras are at the method-level. methodSignature is relevant for extras
        // (with the exception if the extra is extracted from exit_points)
        // action, URI, and categories are identified based on manifest's intent filters
		String branchConditionTrimmed = branchCondition.trim();
        JSONObject ic3obj = (JSONObject) jsons.get(0);
		if (ic3obj == null) {
			return false;
		}
        if (!ic3obj.keySet().contains("components")) {
            // ic3 did not identify any component
            return false;
        }
        JSONArray compsArray = (JSONArray) ic3obj.get("components");
        Iterator compsIter = compsArray.iterator();
        while (compsIter.hasNext()) {
            JSONObject comp = (JSONObject) compsIter.next();
            if (comp.get("name").toString().equals(currClassName)) {
                // found component corresponding to currClassName
                String key = null;
                if (attr.equals("uri-nullness")) {
                   // "kind": "TYPE",
                   key = "TYPE";
                } else if (attr.equals("extras-value")) {
                    key = "extras";
                } else if (attr.equals("extras-key")) {
                    key = "extras";
                } else if (attr.equals("bundleExtras-key")) {
                    key = "extras";
                } else if (attr.equals("bundleExtras-value")) {
                    key = "extras";
                } else if (attr.equals("category")) {
                    // "kind": "CATEGORY",
                    key = "CATEGORY";
                } else if (attr.equals("action")) {
                    // "kind": "ACTION",
                    key = "ACTION";
                }

                if (key.equals("TYPE") || key.equals("CATEGORY") || key.equals("ACTION")) {
                    // they are identified by analyzing manifest
                    if (!comp.keySet().contains("intent_filters")) {
                        // did not identify attributes in manifest
                        continue;
                    }
                    JSONArray filters = (JSONArray) comp.get("intent_filters");
                    Iterator filtersIter = filters.iterator();
					Boolean noCategory = true;
					Boolean noUri = true;
                    while (filtersIter.hasNext()) {
                        JSONObject currFilter = (JSONObject) filtersIter.next();

                        // for URI, just check for existence
                        // for action, also check for value
                        if (key.equals("ACTION")) {
                            if (currFilter.keySet().contains("kind") && currFilter.get("kind").equals(key)) {
								// check ic3 action value to see if the cmpValue exists in the value
								Boolean notFound = true;
								for (Object keyStr : currFilter.keySet()) {
									if (keyStr.equals("kind")) {
										continue;
									}
									String keyValue = (String) currFilter.get(keyStr);
									if (branchConditionTrimmed.equals("==")) {
										// not a null check. Checking against actual value
										// contains check
										if (keyValue.contains(cmpValue)) {
											// check against actual value
											return true;
										}
									} else if (branchConditionTrimmed.equals("!=")) {
										if (keyValue.contains(cmpValue)) {
											// check against actual value
											notFound = false;  // the action is found but the check is for otherwise
											break;
										}
									}
								}
								if (branchConditionTrimmed.equals("!=") && notFound) {
									return true;
								}
                            }
                        } else if (key.equals("TYPE")) {
							if (branchConditionTrimmed.equals("!=")) {
								// nullness check
								// uri must exists
								if (currFilter.keySet().contains("kind")) {
									if (
											currFilter.get("kind").equals(key) ||
													currFilter.get("kind").equals("SCHEME") ||
													currFilter.get("kind").equals("HOST") ||
													currFilter.get("kind").equals("PATH")
									) {
										return true;
									}
								}
							} else if (branchConditionTrimmed.equals("==")) {
								// nullness check
								// uri cannot exists
								if (currFilter.keySet().contains("kind")) {
									if (
											currFilter.get("kind").equals(key) ||
													currFilter.get("kind").equals("SCHEME") ||
													currFilter.get("kind").equals("HOST") ||
													currFilter.get("kind").equals("PATH")
									) {
										noUri = false;
										break;
//										return false;
									}
								}
							}
                        } else if (key.equals("CATEGORY")) {
                            // for category, check for existence of arg in the categories list
                            if (arg == null) {
                                // getCategories()
								if (branchConditionTrimmed.equals("==")) {
									// check category does not exist
									if (currFilter.keySet().contains("kind") && currFilter.get("kind").equals(key)) {
										noCategory = false;  // found a category
										break;
										// flow-sensitivity cannot detect category nullness
//										return false;
									}
								} else if (branchConditionTrimmed.equals("!=")) {
									if (currFilter.keySet().contains("kind") && currFilter.get("kind").equals(key)) {
										return true;
									}
								}
                            } else {
                                // hasCategories(arg)
                                // iterate JSONObject currFilter to identify category string
                                // skip key-value pair where key is "kind"
                                Set<String> filterKeys = currFilter.keySet();
                                for (String k : filterKeys) {
                                    if (!k.equals("kind")) {
										if (branchConditionTrimmed.equals("!=")) {
											if (currFilter.get(k).equals(arg)) {
												// category string found
												return true;
											}
										} else if (branchConditionTrimmed.equals("==")) {
											// want to make sure category does not exist
											if (currFilter.get(k).equals(arg)) {
												// category string found
												noCategory = false;
												break;
//												return false;
											}
										}
                                    }
                                }
                            }
                       }
                    }
					// no category found check
					if (key.equals("CATEGORY") && arg == null && branchConditionTrimmed.equals("==") && noCategory) {
						return true;
					}
					if (key.equals("CATEGORY") && arg != null && branchConditionTrimmed.equals("==") && noCategory) {
						return true;
					}
					// no uri found check
					if (key.equals("TYPE") && branchConditionTrimmed.equals("==") && noUri) {
						return true;
					}
                } else if (key.equals("extras")) {
                    if (!comp.keySet().contains("extras")) {
                        // package+class name did not have extras
                        continue;
                    }
                    JSONArray extras = (JSONArray) comp.get("extras");
					Boolean extraNotFound = true;
                    Iterator extrasIter = extras.iterator();
                    while (extrasIter.hasNext()) {
                        JSONObject currExtra = (JSONObject) extrasIter.next();
                        if (arg != null && cmpValue==null) {
							if (branchConditionTrimmed.equals("!=")) {
								// does not equal null for checking key exists
								if (currExtra.keySet().contains("extra") && currExtra.get("extra").toString().equals(arg)) {
									return true;
								}
							} else if (branchConditionTrimmed.equals("==")) {
								// equal null needs to make sure key does not exists
								if (currExtra.keySet().contains("extra") && currExtra.get("extra").toString().equals(arg)) {
									extraNotFound = false;
									break;
//									return false;
								}
							}
                        }
                    }
					// check for extra not found case
					if (arg!=null && branchConditionTrimmed.equals("==") && cmpValue==null && extraNotFound) {
						return true;
					}
                }

            }
       }
       return false;
    }

    public boolean iccBotCanId(String attr, String arg, String method, String currClassName, String cmpValue, Integer extraType, String branchCondition, Integer lineNum) {
        // ICCBot differentiates Intents up to the package+class name, not method name like
        // phenomenon and IC3
		String branchConditionTrimmed = branchCondition.trim();
        JSONObject iccbotobj = (JSONObject) jsons.get(1);
		if (iccbotobj == null) {
			return false;
		}
        if (!iccbotobj.keySet().contains(currClassName)) {
            return false;
        }
        JSONObject comp = (JSONObject) iccbotobj.get(currClassName);

        String key = null;
        String extrasType = null;
        if (attr.equals("uri-nullness")) {
           key = "uri";
        } else if (attr.equals("extras-value")) {
            key = "extras";
            extrasType = "extras-value";
        } else if (attr.equals("extras-key")) {
            key = "extras";
            extrasType = "extras-key";
        } else if (attr.equals("bundleExtras-key")) {
            key = "extras";
            extrasType = "extras-key";
        } else if (attr.equals("bundleExtras-value")) {
            key = "extras";
            extrasType = "extras-value";
        } else if (attr.equals("category")) {
            key = "categories";
        } else if (attr.equals("action")) {
            key = "actions";
        }

		if (key.equals("uri")) {
			if (comp.keySet().contains(key)) {
//				String uriValue = (String) comp.get(key);
				if (branchConditionTrimmed.equals("==")) {
					// check uri is null
					if (comp.get(key).equals("Null")) {
						return true;
					}
				} else if (branchConditionTrimmed.equals("!=")) {
					// check uri is not null
					if (comp.get(key).equals("NotNull")) {
						return true;
					}
				}
			}
		} else if (key.equals("actions")) {
			// if action is not in comp it action list will not be present
			if (comp.keySet().contains(key)) {
				JSONArray actions = (JSONArray) comp.get(key);
				Iterator actionsIter = actions.iterator();
				Boolean noAction = true;
				while (actionsIter.hasNext()) {
					String aItem = (String) actionsIter.next();
					if (branchConditionTrimmed.equals("==")) {
						// check if action is cmpValue (or if cmpValue is a substring)
						if (cmpValue!=null && aItem.contains(cmpValue)) {
							return true;
						}
					} else if (branchConditionTrimmed.equals("!=")) {
						// check if there is action that is not cmpValue
						// iccbot is flow-sensitive so it detects possible list of actions
						// if any action in the list is not cmpValue, we will count it as correct
						if (cmpValue!=null && !aItem.contains(cmpValue)) {
//							return true;
							noAction = false;
							break;
						}
					}
				}
				if (cmpValue!=null && branchConditionTrimmed.equals("!=") && noAction) {
					return true;
				}
			}
		} else if (key.equals("categories")) {
			// categories is a list
			if (!comp.keySet().contains(key) && branchConditionTrimmed.equals("==")) {
				// no category and the check is if categories is null
				// for either arg==null (getCategories) or arg!=null (hasCategories)
				return true;
			}
			if (comp.keySet().contains(key)) {
				JSONArray categories = (JSONArray) comp.get(key);
				if (arg == null) {
					// getCategories()
					if (branchConditionTrimmed.equals("!=")) {
						if (categories.size() != 0) {
							return true;
						}
					} else if (branchConditionTrimmed.equals("==")) {
						if (categories.size() == 0) {
							return true;
						}
					}
				}
				Iterator categoriesIter = categories.iterator();
				Boolean noCategory = true;
				while (categoriesIter.hasNext()) {
					String cItem = (String) categoriesIter.next();
					if (arg != null) {
						// hasCategory(x)
						if (branchConditionTrimmed.equals("!=")) {
							// check category exist (not null check)
							if (cItem.contains(arg)) {
								// key found
								return true;
							}
						} else if (branchConditionTrimmed.equals("==")) {
							// check category does not exist (null check)
							if (!cItem.contains(arg)) {
								// key found
								noCategory = false;
								break;
//								return true;
							}
						}
					}
				}
				if (arg != null && branchConditionTrimmed.equals("==") && noCategory) {
					return true;
				}
			}
		} else if (key.equals("extras")) {
			// extras is a list
			if (!comp.keySet().contains(key) && arg != null && cmpValue==null && branchConditionTrimmed.equals("==")) {
				// no extras
				// equal null needs to make sure key does not exists
				return true;
			}
			if (comp.keySet().contains(key)) {
				JSONArray extras = (JSONArray) comp.get(key);
				Iterator extrasIter = extras.iterator();
				Boolean extraNotFound = true;
				while (extrasIter.hasNext()) {
					JSONObject eItem = (JSONObject) extrasIter.next();
					if (arg != null && cmpValue==null) {
						// cmpValue==null since iccbot cannot identify extra value
						if (branchConditionTrimmed.equals("!=")) {
							// does not equal null for checking key exists
							if (eItem.keySet().contains("name") && eItem.get("name").toString().equals(arg)) {
								return true;
							}
						} else if (branchConditionTrimmed.equals("==")) {
							// equal null needs to make sure key does not exists
							if (eItem.keySet().contains("name") && eItem.get("name").toString().equals(arg)) {
								// due to flow-sensitivity, cannot identify extras along different paths
								extraNotFound = false;
								break;
//								return false;
							}
						}

					}
				}
				if (branchConditionTrimmed.equals("==") && extraNotFound) {
					return true;
				}
			}
		}
        return false;
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

	private void doPathAnalysis(final SootMethod method, Collection<Future<?>> futures, boolean isIntra) {
		Body b = method.getActiveBody();
		PatchingChain<Unit> units = b.getUnits();
		final BriefUnitGraph ug = new BriefUnitGraph(b);
		final String currClassName = method.getDeclaringClass().getName();
		System.out.println(method.getSignature().toString());
		int totalUnitsToAnalyzeCount = 0;

		int currUnitToAnalyzeCount = 0;
		for (final Unit unit : units) {
			boolean performPathAnalysis = false;
			String attr;
			synchronized (method) {
				attr = unitNeedsAnalysis(method, currClassName, unit);
			}

			if (attr != null) {
				logger.debug("Performing path analysis for unit: " + unit);
				logger.debug("Currently analyzing unit " + currUnitToAnalyzeCount + " of " + totalUnitsToAnalyzeCount);
				StopWatch stopWatch = new StopWatch();
				stopWatch.start();
				// unit becomes startingUnit in callees
//				Map<SootMethod, Map<Unit, List<UnitPath>>> summariesBefore = new ConcurrentHashMap<>(methodSummaries);
				doPathAnalysisOnUnitUsingExecutor(method, ug, currClassName, unit, futures, isIntra, attr);
//				if (summariesBefore.equals(methodSummaries)) {
//					System.out.println("broken");
//				}
				totalUnitsToAnalyzeCount++;
				stopWatch.stop();
				logger.debug("Time to compute unit " + currUnitToAnalyzeCount + ": " + stopWatch.getElapsedTime());

				Pair<Unit, SootMethod> unitMethod = new Pair<Unit, SootMethod>(unit, method);
				targetedUnits.add(unitMethod);

				currUnitToAnalyzeCount++;
			}

			if (performPathAnalysis) {
				logger.debug("wjtp.pathexec - end path analysis on unit: " + unit);
			}

		}
		logger.debug("total number of units in method " + method.getSignature() + ": " + units.size());

	}


	public void doPathAnalysisOnUnitUsingExecutor(final SootMethod method,
												  final BriefUnitGraph ug,
												  final String currClassName,
												  final Unit unit,
												  Collection<Future<?>> futures,
												  boolean isIntra,
												  String attr
	) {
		futures.add(executor.submit(new Runnable() {
			@Override
			public void run() {
				Options.v().set_time(false);

				logger.debug("begin path analysis on unit " + unit + " of method " + method);
				boolean isFeasible = doPathAnalysisOnUnit(0, method, ug, currClassName, unit, pathAnalyses, isIntra, attr);
				logger.debug("end path analysis on unit " + unit + " of method " + method);
			}
		}));
	}


	public boolean doPathAnalysisOnUnit(int tabs, SootMethod method, BriefUnitGraph ug, String currClassName, Unit startingUnit, PathAnalysis pathAnalyses, boolean isIntra, String attr) {

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

		int finalPathsLimit = 100;
		boolean hitPathsLimit = false;
		if (!pathLimitEnabled) {
			finalPathsLimit = Integer.MAX_VALUE;
		}

		// Perform backward analysis to fill in finalPaths with all paths that can lead to unit
		// No "actual" analysis is performed yet, just paths extraction
		Map<Unit, Pair<String,List<UnitPath>>> unitSum = null;
		while (!workUnits.isEmpty()) {
			if (Thread.currentThread().isInterrupted()) {
				// time is up
				return false;
			}
			if (workPaths.size() != workUnits.size()) {
				throw new RuntimeException(Utils.createTabsStr(tabs) + "workUnits size is different from workPaths size");
			}

			Unit startUnitOfCurrPath = workUnits.pop(); // starting unit in current path
			List<Unit> currPath = workPaths.pop(); // current path to work on
			discoveredUnits.add(startUnitOfCurrPath);

			if (ug.getPredsOf(startUnitOfCurrPath).isEmpty()) { // if there are no more predecessors than we reached the end of the path
				if (logger.isTraceEnabled()) {
					logger.trace("A final path:");
					logger.trace("\n" + Joiner.on("\n").join(currPath));
				}
				if (startUnitOfCurrPath instanceof IdentityStmt) {
					// Reach the beginning of the function
					IdentityStmt idStmt = (IdentityStmt) startUnitOfCurrPath;
					if (idStmt.getRightOp() instanceof CaughtExceptionRef) {
						// inside a catch block
						logger.trace("Exceptional path is not being analyzed for now");
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
				if (Thread.currentThread().isInterrupted()) {
					// time is up
					return false;
				}
				if (currPath.contains(pred)) {
					logger.trace(Utils.createTabsStr(tabs) + "loop detected---already followed this edge!");
					continue;
				}

				if (logger.isTraceEnabled()) {
					logger.trace("Forking the following path on predecessor unit " + pred);
					logger.trace(Joiner.on("\n").join(currPath) + "\n");
				}

				List<Unit> newPath = new ArrayList<Unit>(currPath);
				newPath.add(pred); // add to end of list, so path is reverse

				// if there are two preds, two new paths will be created
				workPaths.push(newPath);
				workUnits.push(pred);
				logger.trace(Utils.createTabsStr(tabs) + "workUnits size: " + workUnits.size());

				if (Thread.interrupted()) {
					try {
						throw new InterruptedException();
					} catch (InterruptedException e) {
						return false;
					}
				}
			}

			if (Thread.interrupted()) {
				try {
					throw new InterruptedException();
				} catch (InterruptedException e) {
					return false;
				}
			}
		}

		if (hitPathsLimit) {
			logger.debug("Path limit hit for unit " + startingUnit + " in method " + method);
		}

		/*
		if (finalPaths.isEmpty()) {
			intentCatCounts.put(attr, intentCatCounts.get(attr)-1);
		}
		 */

		// finalPaths contain all possible paths in the function
		// each element of finalPaths is a possible path in the function based on CFG
		// each path is in reverse
		Boolean isIcs = false;
		for (List<Unit> currPath : finalPaths) { // analyzed fully-determined relevant program paths
			if (Thread.currentThread().isInterrupted()) {
				// time is up
				return false;
			}
			//this.pathsAnalyzedCount++;
			Set<Set<CompareInfo>> currPathConds = new HashSet<Set<CompareInfo>>();

			// perform intra-procedural analysis
			// updates currPathCond and currDecls
			Boolean isInterrupted = analyzeProgramPath(tabs, method, currPath, currPathConds, currClassName, ug);
			if (isInterrupted) {
				return false;
			}

			Iterator iterCurrPathConds = currPathConds.iterator();
			while (iterCurrPathConds.hasNext()) {
				/*  // Though time is up, we have finished analyzing and the rest is fast
				if (Thread.currentThread().isInterrupted()) {
					// time is up
					return false;
				}
				 */
				Set<CompareInfo> currPathCond = (Set<CompareInfo>) iterCurrPathConds.next();

				// store to methodSummaries
				// unitSum is a map of unit to list of unitpathJNI that leads to it
				if (methodSummaries.containsKey(method)) {
					unitSum = methodSummaries.get(method);
				} else {
					unitSum = new HashMap<>();
				}
				Pair<String,List<UnitPath>> unitPathJNIs = null;
				if (unitSum.containsKey(startingUnit)) {
					// there are paths found previously for startingUnit
					unitPathJNIs = unitSum.get(startingUnit);
				} else {
					// first path found for startingUnit
					// found a new Intent-usage statement

					// identify component
					Component comp = androidProcessor.findComponent(currClassName);
					if (comp == null) {
						for (SootClass dynReceiver : dynRegReceivers) {
							if (dynReceiver.getName().equals(currClassName)) {
								comp = new Receiver(currClassName);
								comp.setExported(true);
							}
						}
					}
					String compName = null;
					if (comp instanceof Activity) {
						compName = "Activity";
						intentCatCountsA.put(attr, intentCatCountsA.get(attr)+1);
					} else if (comp instanceof Service) {
						compName = "Service";
						intentCatCountsS.put(attr, intentCatCountsS.get(attr)+1);
					} else if (comp instanceof Receiver) {
						compName = "Receiver";
						intentCatCountsR.put(attr, intentCatCountsR.get(attr)+1);
					} else if (Utils.extendFromActivity(currClassName)) {
						compName = "Activity";
						intentCatCountsA.put(attr, intentCatCountsA.get(attr)+1);
					} else {
						continue;
					}
					if (compName == null) {
						continue;
					}
					List<UnitPath> unitPaths = new ArrayList<UnitPath>();
					unitPathJNIs = new Pair<>(compName, unitPaths);
				}

				UnitPath up = new UnitPath(currPathCond, currPath);
				List<UnitPath> unitPaths = unitPathJNIs.getValue1();
				unitPaths.add(up);
				unitPathJNIs = unitPathJNIs.setAt1(unitPaths);
				unitSum.put(startingUnit, unitPathJNIs);
				methodSummaries.put(method, unitSum);
			}
		}

		// analysis of method is done
		return true;
	}

	private void handleSwitchStmt(int tabs, Unit currUnit, JLookupSwitchStmt switchStmt, Set<String> currPathCond, Set<String> currDecls, List<Unit> currPath, SootMethod method, SimpleLocalDefs defs) {
		int index = 0;
		Value key = switchStmt.getKey();

		Unit keyDefUnit = getDefOfValInPath(key, currUnit, currPath, defs);
		String opExpr1 = createZ3Expr(key, currUnit, keyDefUnit, method, currDecls, tabs);

		List<Integer> seen = new ArrayList<Integer>();
		for (Unit unit : switchStmt.getTargets()) {
			int val = switchStmt.getLookupValue(index);
			seen.add(val);
			if (currUnit.toString().equals(unit.toString())) {
				// create Z3 constraint
				String returnExpr = buildZ3CondExpr(tabs, opExpr1, Integer.toString(val), "==");
				currPathCond.add(returnExpr);
				return;
			}
			index += 1;
		}
		// default value
		for (Integer curSeen : seen) {
			String returnExpr = buildZ3CondExpr(tabs, opExpr1, Integer.toString(curSeen), "!=");
			currPathCond.add(returnExpr);
		}
		return;
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
								logger.debug(prIntentSymbol + " is a parameter of method " + prMethodName + " at index " + index + " of type " + type);
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

	protected String getConstant(IfStmt ifStmt) {
		for (ValueBox useBox : ifStmt.getCondition().getUseBoxes()) {
			Value val = useBox.getValue();
			if (val instanceof Constant) {
				if (val instanceof IntConstant) {
					IntConstant intConst = (IntConstant) val;
					return Integer.toString(intConst.value);
				} else if (val instanceof LongConstant) {
					LongConstant longConst = (LongConstant) val;
					return Long.toString(longConst.value);
				} else if (val instanceof FloatConstant) {
					FloatConstant floatConst = (FloatConstant) val;
					return Float.toString(floatConst.value);
				} else if (val instanceof DoubleConstant) {
					DoubleConstant doubleConst = (DoubleConstant) val;
					return Double.toString(doubleConst.value);
				} else if (val instanceof StringConstant) {
					StringConstant strConst = (StringConstant) val;
					return "\"" + strConst.value + "\"";
				}
			}
		}
		return null;
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


	private Boolean analyzeProgramPath(int tabs, SootMethod method, List<Unit> currPath, Set<Set<CompareInfo>> currPathConds, String currClassName, BriefUnitGraph ug) {
		Set<Set<CompareInfo>> wipCurrPathConds = new HashSet<Set<CompareInfo>>();  // constraints for multiple program paths
		List<Unit> currPathAsList = new ArrayList<Unit>(currPath);
		List<Unit> ifStmtSeen = new ArrayList<>();
		for (int i = currPathAsList.size()-1; i >= 0; i--) {
			if (pathInsensitiveEval) {
				if (i != 0) {
					continue;
				}
			}
			if(Thread.currentThread().isInterrupted()) {
				// time is up
				return true;
			}
			// iterating each instruction in path currPath
			Unit currUnitInPath = currPathAsList.get(i); // current unit under analysis for current path
			/*
			Unit succUnit = null; // successor of currUnitINPath
			if (i - 1 < currPathAsList.size() && i >= 1) {
				succUnit = currPathAsList.get(i - 1);
			}
			 */
			BriefUnitGraph unitGraph = null;
			SimpleLocalDefs defs = null;
			if (method.hasActiveBody()) {
				unitGraph = new BriefUnitGraph(method.getActiveBody());
				synchronized (method) {
					defs = new SimpleLocalDefs(unitGraph);
				}
			} else {
				throw new RuntimeException("method has no active body, which shouldn't happen: " + method.getName());
			}

			if (i != (currPathAsList.size()-1)) {
				// not last element
				//Stmt pred = (Stmt) currPathAsList.get(i+1);
				List<Unit> preds = ug.getPredsOf(currUnitInPath);
				Unit pred = null;
				for (Unit p : preds) {
					if (p instanceof IfStmt && currPathAsList.contains(p)) {
						if (!ifStmtSeen.contains(p)) {
							// first time seeing this if-statement
							// if seen again, this means it is a different path
							ifStmtSeen.add(p);
							pred = p;
							break;
						}
					}
				}
				boolean foundUsage = false;
				if (pred != null && pred instanceof IfStmt) {
					Boolean containsNullComp = isNullComparison((IfStmt) pred);
					IfStmt predIfStmt = (IfStmt) pred;
					String cmpConst = getConstant(predIfStmt);
					if (cmpConst == null && !containsNullComp) {
						// cannot get the constant the if=stmt compares against and not a null comparison
						continue;
					}
					for (ValueBox useBox : predIfStmt.getUseBoxes()) {
						if (useBox.getValue() instanceof Local) {
							Local useLocal = (Local) useBox.getValue();
							for (Unit defUnit : defs.getDefsOfAt(useLocal, predIfStmt)) {
								if(!isDefInPathAndLatest(currPath, defUnit, useLocal, currUnitInPath, defs)){
									continue;
								}
								// defUnit is the definition of useLocal at predIfStmt
								//*** do not actually use
								Pair debugInfo = new Pair<Integer, String>(currUnitInPath.getJavaSourceStartLineNumber(), currUnitInPath.toString());
								Pair compareInfo = new Pair<>(containsNullComp, cmpConst);
								StringBuilder messageType = new StringBuilder("");
								if (predIfStmt.getCondition() instanceof ConditionExpr) {
									ConditionExpr ce = (ConditionExpr) predIfStmt.getCondition();
									String branchCondition = getBranch(predIfStmt, currUnitInPath, useLocal, ce);
									Boolean defUnitUses = null;
									if (i == 0) {
										// for path-insensitive evaluation, only track the intent attribute at i=0
										defUnitUses = checkIfUnitUsesIntentPayload(defUnit, defs, messageType, compareInfo, method, currClassName, debugInfo, wipCurrPathConds, branchCondition, currUnitInPath.getJavaSourceStartLineNumber(), true);
									} else {
										defUnitUses = checkIfUnitUsesIntentPayload(defUnit, defs, messageType, compareInfo, method, currClassName, debugInfo, wipCurrPathConds, branchCondition, currUnitInPath.getJavaSourceStartLineNumber(), false);
									}
									if (defUnitUses != null) {
										if (defUnitUses.booleanValue()) {
											// pred of unit is an if-statement that contains usage of intent payload
											foundUsage = true;
											break;
										}
									}
								}
							}
							/*
							if (foundUsage){
								break;
							}
							 */
						}
					}
				}
			}

			// inter-procedural analysis
			Stmt currStmtInPath = (Stmt) currUnitInPath;
			if (currStmtInPath.containsInvokeExpr()) {
				InvokeExpr ie = currStmtInPath.getInvokeExpr();
				SootMethod calledMethod = ie.getMethod();
				if (Utils.isAndroidMethod(calledMethod)) {
					continue;
				}

				if (methodSummaries.containsKey(calledMethod)) {
					Map< Unit, Pair<String,List<UnitPath>> > unitSum = methodSummaries.get(calledMethod);
					for (Map.Entry<Unit, Pair<String,List<UnitPath>>> ue : unitSum.entrySet()) {
						Unit u = ue.getKey();
						List<Unit> calledMethodFullPaths = methodFinalPaths.get(calledMethod);
						if (calledMethodFullPaths != null) {
							if (calledMethodFullPaths.contains(u)) {
								// interprocedural constraint exists
								List<UnitPath> paths = ue.getValue().getValue1();
								if (!wipCurrPathConds.isEmpty()) {
									Set<Set<CompareInfo>> tmpCurrPathConds = new HashSet<Set<CompareInfo>>(wipCurrPathConds);
									wipCurrPathConds = new HashSet<Set<CompareInfo>>();
									for (Set<CompareInfo> wci : tmpCurrPathConds) {
										for (UnitPath p : paths) {
											Set<CompareInfo> calleeCi = p.getPathCond();
											Set<CompareInfo> tmp = new HashSet<>(wci);
											for (CompareInfo cci : calleeCi) {
												tmp.add(new CompareInfo(cci.attr, cci.arg, cci.method, cci.currClassName, cci.needsValue, cci.value, cci.branchCondition, cci.extraType, cci.strOp, cci.lineNum, false));
											}
											// back when CompareInfo does not have first field
//											tmp.addAll(calleeCi);
											wipCurrPathConds.add(tmp);
										}
									}
								} else {
									// TODO: no per path constraints
									for (UnitPath p : paths) {
										Set<CompareInfo> calleeCi = p.getPathCond();
										wipCurrPathConds.add(calleeCi);
									}
								}
							}
						}
					}
				}
			}
		}
		if (!wipCurrPathConds.isEmpty()) {
			currPathConds.addAll(wipCurrPathConds);
		}
		return false;
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

    public static boolean isBundleFromIntent(SimpleLocalDefs localDefs, Unit defUnit, InvokeExpr invokeExpr, StringBuilder messageType) {
        if (invokeExpr instanceof InstanceInvokeExpr) {
            InstanceInvokeExpr instanceInvokeExpr = (InstanceInvokeExpr)invokeExpr;
            if (instanceInvokeExpr.getBase() instanceof Local) {
                Local base = (Local)instanceInvokeExpr.getBase();
                List<Unit> baseDefs = localDefs.getDefsOfAt(base, defUnit);
                for (Unit baseDef : baseDefs) {
                    InvokeExpr baseInvokeExpr = Utils.getInvokeExprOfAssignStmt(baseDef);
                    if (baseInvokeExpr != null) {
                        if (Globals.getBundleMethodsSet.contains(baseInvokeExpr.getMethod().getName())) {
                            if (baseInvokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                                messageType.append(baseInvokeExpr.getMethod().getName()+".");
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    public Boolean isIntentPayloadExtractionMethod(SimpleLocalDefs localDefs,
                                                   Unit defUnit,
                                                   InvokeExpr invokeExpr,
                                                   StringBuilder messageType,
                                                   Pair compareInfo,
                                                   SootMethod method,
                                                   String currClassName,
                                                   Pair debugInfo,
												   Set<Set<CompareInfo>> currPathConds,
												   String branchCondition,
												   int lineNum,
												   Boolean isFirst) {

        String invokedMethodName = invokeExpr.getMethod().getName();
		Boolean containsNullComp = (Boolean) compareInfo.getValue0();
		String cmpConst = (String) compareInfo.getValue1();

        if (Pattern.matches("getData", invokedMethodName)) {
            // extracting URI. getData() returns URI
            // check: can the tool's corresponding intent have an URI field?
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                messageType.append(invokedMethodName+"().");
                if (containsNullComp) {
					CompareInfo ci = new CompareInfo("uri-nullness", null, method, currClassName, false, null, branchCondition, 0, null, lineNum, isFirst);
					if (ci != null) {
						if (!currPathConds.isEmpty()) {
							for (Set<CompareInfo> cip : currPathConds) {
								cip.add(ci);
							}
						} else {
							Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
							currPathCond.add(ci);
							currPathConds.add(currPathCond);
						}
					}
					//currPathCond.add(new CompareInfo("uri-nullness", null, method, currClassName, false));
                } else {
                    // we do not model uri in general
                    //intentCatCounts.put("uri", intentCatCounts.get("uri")+1);
                    //updateTotalCompare("uri");
                }
                return true;
            }
        }

// handled by stringOpsSet
		/*
        if (Pattern.matches("getDataString", invokedMethodName)) {
            // extracting URI as String. getDataString() returns URI
            // check: can the tool's corresponding intent have an URI field?
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                messageType.append(invokedMethodName+"().");
                if (containsNullComp) {
					CompareInfo ci = new CompareInfo("uri-nullness", null, method, currClassName, false, null, branchCondition, false, null, lineNum);
					if (!currPathConds.isEmpty()) {
						for(Set<CompareInfo> cip : currPathConds){
							cip.add(ci);
						}
					} else {
						Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
						currPathCond.add(ci);
						currPathConds.add(currPathCond);
					}
					//currPathCond.add(new CompareInfo("uri-nullness", null, method, currClassName, false));
                } else {
                    // TODO: we do not model uri in general
                    //intentCatCounts.put("uri", intentCatCounts.get("uri")+1);
                    //updateTotalCompare("uri");
                }
                return true;
            }
        }
		 */
       if (Pattern.matches("get.*Extra", invokedMethodName)) {
		   // model array variants now: nullness
		   /*
          if (Pattern.matches("get.*ArrayExtra", invokeExpr.getMethod().getName()) ||
               Pattern.matches("get.*ArrayListExtra", invokeExpr.getMethod().getName())) {
               // we do not model these
               return null;
           }
		    */
           // extracting extra data value
		   if (invokedMethodName.equals("getStringExtra")) {
			   // modelled later
			   return null;
		   }
           if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                String arg = getIeArg(invokeExpr, localDefs, defUnit);
                if (arg == null) {
                    // extra data arg not successfully retrieved
                    return null;
                }
				messageType.append(invokedMethodName+"("+arg+").");
				CompareInfo ci = null;
				if (invokedMethodName.equals("getBooleanExtra")) {
					ci = new CompareInfo("extras-value", arg, method, currClassName, true, "true", branchCondition, 2, null, lineNum, isFirst);  // branchCondition decides the value
				} else if (Pattern.matches("get.*Array*Extra", invokedMethodName)) {
					ci = new CompareInfo("extras-value", arg, method, currClassName, true, cmpConst, branchCondition, 4, null, lineNum, isFirst);
				} else if (Globals.numberExtrasSet.contains(invokedMethodName)) {
					ci = new CompareInfo("extras-value", arg, method, currClassName, true, cmpConst, branchCondition, 3, null, lineNum, isFirst);
				}
				if (ci != null) {
					if (!currPathConds.isEmpty()) {
						for (Set<CompareInfo> cip : currPathConds) {
							cip.add(ci);
						}
					} else {
						Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
						currPathCond.add(ci);
						currPathConds.add(currPathCond);
					}
				}
				//currPathCond.add(new CompareInfo("extras-value", arg, method, currClassName, true));
                return true;
            }
        }
        if (Pattern.matches("hasExtra", invokedMethodName)) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                String arg = getIeArg(invokeExpr, localDefs, defUnit);
                if (arg == null) {
                    // extra data arg not sucessfully retrieved
                    return null;
                }
				messageType.append(invokedMethodName+"("+arg+").");
				CompareInfo ci = new CompareInfo("extras-key", arg, method, currClassName, false, null, branchCondition, 0, null, lineNum, isFirst);
				if (ci != null) {
					if (!currPathConds.isEmpty()) {
						for (Set<CompareInfo> cip : currPathConds) {
							cip.add(ci);
						}
					} else {
						Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
						currPathCond.add(ci);
						currPathConds.add(currPathCond);
					}
				}
				//currPathCond.add(new CompareInfo("extras-key", arg, method, currClassName, false));
                return true;
            }
        }
        if (Globals.bundleExtraDataMethodsSet.contains(invokedMethodName)) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.os.Bundle")) {
                Boolean isFromIntent = isBundleFromIntent(localDefs, defUnit, invokeExpr, messageType);
                if (isFromIntent) {
                    String arg = getIeArg(invokeExpr, localDefs, defUnit);
                    if (arg == null) {
                        // extra data arg not sucessfully retrieved
                        return null;
                    }
                    messageType.append(invokedMethodName+"("+arg+").");

                    if (invokedMethodName.equals("containsKey")) {
						CompareInfo ci = new CompareInfo("bundleExtras-key", arg, method, currClassName, false, null, branchCondition, 0, null, lineNum, isFirst);
						if (ci != null) {
							if (!currPathConds.isEmpty()) {
								for (Set<CompareInfo> cip : currPathConds) {
									cip.add(ci);
								}
							} else {
								Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
								currPathCond.add(ci);
								currPathConds.add(currPathCond);
							}
						}
                    } else {
						if (invokedMethodName.equals("getString")) {
							return null;
						}
						CompareInfo ci = null;
						if (invokedMethodName.equals("getBoolean")) {
							ci = new CompareInfo("bundleExtras-value", arg, method, currClassName, true, "true", branchCondition, 2, null, lineNum, isFirst);
						} else if (Globals.numberBundleSet.contains(invokedMethodName)) {
							ci = new CompareInfo("bundleExtras-value", arg, method, currClassName, true, cmpConst, branchCondition, 3, null, lineNum, isFirst);
						}
						if (ci != null) {
							if (!currPathConds.isEmpty()) {
								for (Set<CompareInfo> cip : currPathConds) {
									cip.add(ci);
								}
							} else {
								Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
								currPathCond.add(ci);
								currPathConds.add(currPathCond);
							}
						}
						//currPathCond.add(new CompareInfo("bundleExtras-value", arg, method, currClassName, true));
                    }
                }
                return isFromIntent;
            }
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.os.BaseBundle")) {
                Boolean isFromIntent = isBundleFromIntent(localDefs, defUnit, invokeExpr, messageType);
                if (isFromIntent) {
                    String arg = getIeArg(invokeExpr, localDefs, defUnit);
                    if (arg == null) {
                        // extra data arg not sucessfully retrieved
                        return null;
                    }
                    messageType.append(invokedMethodName+"("+arg+").");

                    if (invokedMethodName.equals("containsKey")) {
						CompareInfo ci = new CompareInfo("bundleExtras-key", arg, method, currClassName, false, null, branchCondition, 0, null, lineNum, isFirst);
						if (ci != null) {
							if (!currPathConds.isEmpty()) {
								for (Set<CompareInfo> cip : currPathConds) {
									cip.add(ci);
								}
							} else {
								Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
								currPathCond.add(ci);
								currPathConds.add(currPathCond);
							}
						}
						//currPathCond.add(new CompareInfo("bundleExtras-key", arg, method, currClassName, false));
                    } else {
						if (invokedMethodName.equals("getString")) {
							return null;
						}
						CompareInfo ci = null;
						if (invokedMethodName.equals("getBoolean")) {
							ci = new CompareInfo("bundleExtras-value", arg, method, currClassName, true, "true", branchCondition, 2, null, lineNum, isFirst);
						} else if (Globals.numberBundleSet.contains(invokedMethodName)) {
							ci = new CompareInfo("bundleExtras-value", arg, method, currClassName, true, cmpConst, branchCondition, 3, null, lineNum, isFirst);
						}
						if (ci != null) {
							if (!currPathConds.isEmpty()) {
								for (Set<CompareInfo> cip : currPathConds) {
									cip.add(ci);
								}
							} else {
								Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
								currPathCond.add(ci);
								currPathConds.add(currPathCond);
							}
						}
						//currPathCond.add(new CompareInfo("bundleExtras-value", arg, method, currClassName, true));
                    }
                }
                return isFromIntent;
            }
        }
        if (Globals.categoryMethodsSet.contains(invokedMethodName)) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                if (invokeExpr.getMethod().getName().equals("hasCategory")) {
                    // hasCategory takes an argument
                    String arg = getIeArg(invokeExpr, localDefs, defUnit);
                    if (arg == null) {
                        // extra data arg not sucessfully retrieved
                        return null;
                    }
                    messageType.append(invokedMethodName+"("+arg+").");
					CompareInfo ci = new CompareInfo("category", arg, method, currClassName, false, null, branchCondition, 0, null, lineNum, isFirst);
					if (ci != null) {
						if (!currPathConds.isEmpty()) {
							for (Set<CompareInfo> cip : currPathConds) {
								cip.add(ci);
							}
						} else {
							Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
							currPathCond.add(ci);
							currPathConds.add(currPathCond);
						}
					}
					//currPathCond.add(new CompareInfo("category", arg, method, currClassName, false));
                } else {
                    messageType.append(invokedMethodName+"().");
					CompareInfo ci = new CompareInfo("category", null, method, currClassName, false, null, branchCondition, 0, null, lineNum, isFirst);
					if (ci != null) {
						if (!currPathConds.isEmpty()) {
							for (Set<CompareInfo> cip : currPathConds) {
								cip.add(ci);
							}
						} else {
							Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
							currPathCond.add(ci);
							currPathConds.add(currPathCond);
						}
					}
					//currPathCond.add(new CompareInfo("category", null, method, currClassName, false));
                }
                return true;
            }
        }
// handled by stringOpsSet
/*
        if (Pattern.matches("getAction", invokedMethodName)) {
            // redundant. also in stringReturningIntentMethodsSet
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
				messageType.append(invokedMethodName+"().");
				CompareInfo ci = new CompareInfo("action", null, method, currClassName, false, null);
				if (!currPathConds.isEmpty()) {
					for(Set<CompareInfo> cip : currPathConds){
						cip.add(ci);
					}
				} else {
					Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
					currPathCond.add(ci);
					currPathConds.add(currPathCond);
				}
				//currPathCond.add(new CompareInfo("action", null, method, currClassName , false));
                return true;
            }
        }
 */
        if (Globals.stringOpsSet.contains(invokeExpr.getMethod().getName())  && invokeExpr.getMethod().getDeclaringClass().getName().equals("java.lang.String")) {
			String strOpName = invokeExpr.getMethod().getName();
            if (invokeExpr instanceof VirtualInvokeExpr) {
                VirtualInvokeExpr vInvokeExpr = (VirtualInvokeExpr) invokeExpr;
                Value base = vInvokeExpr.getBase();
                if (base instanceof Local) {
                    List<Unit> baseDefs = localDefs.getDefsOfAt((Local) base, defUnit);
                    for (Unit baseDef : baseDefs) {
                        InvokeExpr baseInvokeExpr = Utils.getInvokeExprOfAssignStmt(baseDef);
                        if (baseInvokeExpr == null) {
                            continue;
                        }
                        if (Globals.stringReturningIntentMethodsSet.contains(baseInvokeExpr.getMethod().getName())) {
							if (baseInvokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")
									|| baseInvokeExpr.getMethod().getDeclaringClass().getName().equals("android.os.Bundle")
									|| baseInvokeExpr.getMethod().getDeclaringClass().getName().equals("android.os.BaseBundle")) {
                                // getStringExtra. Extracting extra data value
                                String arg = getIeArg(invokeExpr, localDefs, defUnit);
                                if (arg == null) {
                                    // extra data arg not successfully retrieved
                                    return null;
                                }
								messageType.append(invokedMethodName+"("+arg+").");
								String strOperatedMethod = baseInvokeExpr.getMethod().getName();
								CompareInfo ci = null;
								if (strOperatedMethod.equals("getStringExtra")) {
									String baseInvokeArg = getIeArg(baseInvokeExpr, localDefs, defUnit);
									if (baseInvokeArg == null) {
										// extra data arg not sucessfully retrieved
										return null;
									}
									ci = new CompareInfo("extras-value", baseInvokeArg, method, currClassName, true, arg, branchCondition, 1, strOpName, lineNum, isFirst);
								} else if (strOperatedMethod.equals("getAction")) {
									ci = new CompareInfo("action", null, method, currClassName, false, arg, branchCondition, 1, strOpName, lineNum, isFirst);  // arg = action name, cmpConst = 0 -> equal,
								} else if (strOperatedMethod.equals("getDataString")) {
									// uri is not null if getDataString attribute exists
									ci = new CompareInfo("uri-nullness", null, method, currClassName, false, null, "!=", 0, null, lineNum, isFirst);
								} else if (strOperatedMethod.equals("getString")) {
									String baseInvokeArg = getIeArg(baseInvokeExpr, localDefs, defUnit);
									if (baseInvokeArg == null) {
										// extra data arg not sucessfully retrieved
										return null;
									}
									ci = new CompareInfo("bundleExtras-value", baseInvokeArg, method, currClassName, true, arg, branchCondition, 1, strOpName, lineNum, isFirst);
								}
								if (ci != null) {
									if (!currPathConds.isEmpty()) {
										for (Set<CompareInfo> cip : currPathConds) {
											cip.add(ci);
										}
									} else {
										Set<CompareInfo> currPathCond = new HashSet<CompareInfo>();
										currPathCond.add(ci);
										currPathConds.add(currPathCond);
									}
								}
								//currPathCond.add(new CompareInfo("extras-value", arg, method, currClassName, true));
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    public Boolean checkIfUnitUsesIntentPayload(Unit inUnit,
                                                SimpleLocalDefs localDefs,
                                                StringBuilder messageType,
                                                Pair compareInfo,
                                                SootMethod method,
                                                String currClassName,
                                                Pair debugInfo,
												Set<Set<CompareInfo>> currPathConds,
												String branchCondition,
												int lineNum,
												Boolean isFirst) {
		// only check intent-controlled statements phenomenon model. Good for catching bugs
        Stmt inStmt = (Stmt)inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            Boolean x = isIntentPayloadExtractionMethod(localDefs, inUnit, ie, messageType, compareInfo, method, currClassName, debugInfo, currPathConds, branchCondition, lineNum, isFirst);
            if (x != null && x == true) {
                // inUnit is an intent extraction instruction
                return x;
            }
        }

		// not an invoke expr
		List<ValueBox> uses = inUnit.getUseBoxes();  // list of Boxes containing Values in unit `inUnit`
		for (ValueBox use : uses) {
			if (use.getValue() instanceof Local) {
				Local local = (Local) use.getValue();
				List<Unit> defUnits = localDefs.getDefsOfAt(local, inUnit);
				for (Unit defUnit : defUnits) {
					InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
					if (invokeExpr == null) {
						continue;
					}
					Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, compareInfo, method, currClassName, debugInfo, currPathConds, branchCondition, lineNum, isFirst);
					if (x != null && x == true)
						return x;
				}
			}
		}
        return null;
    }

	/*
    public Boolean checkIfUnitUsesIntentPayloadNew(Unit inUnit,
                                                SimpleLocalDefs localDefs,
                                                StringBuilder messageType,
                                                Boolean containsNullComp,
                                                SootMethod method,
                                                String currClassName,
                                                Pair debugInfo,
												Set<Set<CompareInfo>> currPathConds) {
		// only check intent-controlled statements phenomenon model. Good for catching bugs
        Stmt inStmt = (Stmt)inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            Boolean x = isIntentPayloadExtractionMethod(localDefs, inUnit, ie, messageType, containsNullComp, method, currClassName, debugInfo, currPathConds);
            if (x != null && x == true) {
                // inUnit is an intent extraction instruction
                return x;
            }
        }

        // for invoke expr:
        // check if any arg is an intent payload.
        // check if base is an intent payload. If base is. Only return true for base operations that we model: str.len, str.equals
        // for others:
        // use original approach
        if (inUnit instanceof AssignStmt && ((AssignStmt) inUnit).getRightOp() instanceof InvokeExpr) {
            AssignStmt as = (AssignStmt) inUnit;
            InvokeExpr ie = (InvokeExpr) as.getRightOp();

            boolean isModel = false;
            // TODO: compare action value and not just action
            // only return true for base operation we model
            // even if base is an intent payload, if we do not model the operation then we do not model it
            // NOTE: implement differently in ExtraDataUseTransformerSp. In ExtraDataUseTransfomerSp, the check
            //       for modelled operation is performed after the defUnits loop. Here it is performed before
            //       so our intentCatCounts do not increment when operation on the payload is not modelled
            if (ie.getMethod().getDeclaringClass().toString().equals("java.lang.String")) {
                if (ie.getMethod().getName().equals("length")) {
                    isModel = true;
                } else if (ie.getMethod().getName().equals("equals")) {
                    isModel = true;
                }
            }

            // check args
            if (isModel) {
                // ex: "action.ex".equals(x) where x is the action string
                List<Value> args = ie.getArgs();
                for (Value arg : args) {
                    if (arg instanceof Local) {
                        List<Unit> defUnits = localDefs.getDefsOfAt((Local) arg, inUnit);
                        for (Unit defUnit : defUnits) {
                            InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
                            if (invokeExpr == null) {
                                continue;
                            }
                            Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp, method, currClassName, debugInfo, currPathConds);
                            if (x != null && x == true)
                                return x;
                        }
                    }
                }
            }
            // check base
            if (ie instanceof InstanceInvokeExpr) {
                // base exists
                InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
                if (iie.getBase() instanceof Local) {
                    Local base = (Local) iie.getBase();
                    List<Unit> defUnits = localDefs.getDefsOfAt(base, inUnit);
                    for (Unit defUnit : defUnits) {
                        InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
                        if (invokeExpr == null) {
                            continue;
                        }
                        if (isModel) {
                            Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp, method, currClassName, debugInfo, currPathConds);
                            if (x != null && x == true) {
                                return x;
                            }
                        }

                    }
                }
            }
        } else {
            // not an invoke expr
            List<ValueBox> uses = inUnit.getUseBoxes();  // list of Boxes containing Values in unit `inUnit`
            for (ValueBox use : uses) {
                if (use.getValue() instanceof Local) {
                    Local local = (Local) use.getValue();
                    List<Unit> defUnits = localDefs.getDefsOfAt(local, inUnit);
                    for (Unit defUnit : defUnits) {
                        InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
                        if (invokeExpr == null) {
                            continue;
                        }
                        Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp, method, currClassName, debugInfo, currPathConds);
                        if (x != null && x == true)
                            return x;
                    }
                }
            }
        }
        return null;
    }
	 */

	private void buildParamRefExpressions(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls, Unit intentDef, String intentSymbol) {
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
				currPathCond.add("(assert (= (hasParamRef " + intentSymbol + " " + prSymbol + ") true))");
			}
		}
	}

	private Intent getIntentForPath(List<Unit> currPath) {
		Intent currIntent = null;
		if (pathIntents.containsKey(currPath)) {
			currIntent = pathIntents.get(currPath);
		} else {
			currIntent = new Intent();
		}
		return currIntent;
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

	private Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> findStringValuesOfBoolType(SootMethod method, SimpleLocalDefs defs, Unit inUnit, Value value, List<Unit> currPath) {
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
					logger.debug("Found potential string equal comparison statement: " + pseUnit);
					if (pseUnit instanceof DefinitionStmt) {
						DefinitionStmt defStmt = (DefinitionStmt) pseUnit;
						if (defStmt.getRightOp() instanceof JVirtualInvokeExpr) {
							JVirtualInvokeExpr jviExpr = (JVirtualInvokeExpr) defStmt.getRightOp();
							if (jviExpr.getMethod().getName().equals("equals") && jviExpr.getMethod().getDeclaringClass().getName().equals("java.lang.String")) {
								logger.debug("Identified actual string equals comparison statement");
								leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath);
								rightVal = findOriginalVal(method, defs, pseUnit, jviExpr.getArg(0), currPath);
							}
							/*if (Pattern.matches("get.*Extra",jviExpr.getMethod().getName())) {
								logger.debug("Found extra data getter method");
								leftVal = findOriginalVal(method, defs,pseUnit,jviExpr.getBase(),currPath);
								rightVal = findOriginalVal(method, defs,pseUnit,jviExpr.getArg(0),currPath);
							}*/
							if (Pattern.matches("hasExtra", jviExpr.getMethod().getName())) {
								logger.debug("Found hasExtra invocation");
								leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath);
								rightVal = findOriginalVal(method, defs, pseUnit, jviExpr.getArg(0), currPath);

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
		return new Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>>(leftVal, rightVal);
	}

	private Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> findCategories(SootMethod method, SimpleLocalDefs defs, Unit inUnit, Value value, List<Unit> currPath) {
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
					logger.debug("Found potential string equal comparison statement: " + pseUnit);
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

	private Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> findBundleValues(SootMethod method, SimpleLocalDefs defs, Unit inUnit, Value value, List<Unit> currPath) {
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
																		//System.out.println("~~~~~~~~~~ GOT INTENT DEFINITION:"+intentLocalSymbol);
																		String newDecl = "(declare-const " + intentLocalSymbol + " Object )";
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
					key = extractKeyFromIntentExtra(coiStmt, defs, currPath);
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
		if (key != null){
			valueKeyMap.put(origVal, key);
		}
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

	public String unitNeedsAnalysis(SootMethod method, String currClassName, Unit unit) {
		if (unit instanceof InvokeStmt) {
			InvokeStmt stmt = (InvokeStmt) unit;
			if (stmt.getInvokeExpr().getMethod().getName().equals("d")) {
				return "";
			}
		}
		return null;
	}

	public synchronized Pair<Intent,Boolean> findSolutionForPath(Integer sumUpIdx,
													Set<String> currPathCond,
													SootMethod method,
													Set<String> decls,
													List<Unit> currPath,
													Unit startingUnit) {
		Set<Triplet<String,String,String>> extraData = new LinkedHashSet<Triplet<String,String,String>>();
		String action = null;
		String uri = null;
		Set<String> categories = new LinkedHashSet<String>();
		boolean isPathFeasible = false;

		try {
			Pair<Map<String, String>,Boolean> ret = returnSatisfyingModel(sumUpIdx, decls, currPathCond, startingUnit, method);
			Map<String,String> model = ret.getValue0();
			Boolean isSat = ret.getValue1();
			if (!isSat) {
				logger.debug("path is infeasible");
				isPathFeasible=false;
			} else {
				logger.debug("path is feasible---here is a solution");
				isPathFeasible=true;

				// from path constraints identify the attributes we modelled

				Map<String,String> intentActionSymbols = new ConcurrentHashMap<>();
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(= \\(getAction (.+)\\) (.+)\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String intentSymbol = m.group(1);
						logger.info("intent symbol for action: " + intentSymbol);

						String actionStrSymbol = m.group(2);
						logger.info("action symbol: " + actionStrSymbol);

						intentActionSymbols.put(intentSymbol,actionStrSymbol);
					}
				}

				Map<String,String> intentUriSymbols = new ConcurrentHashMap<>();
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(= \\(getUri (.+)\\) (.+)\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String intentSymbol = m.group(1);
						logger.info("intent symbol for uri: " + intentSymbol);

						String uriStrSymbol = m.group(2);
						logger.info("action symbol: " + uriStrSymbol);

						intentUriSymbols.put(intentSymbol,uriStrSymbol);
					}
				}

				Map<String,String> extraLocalKeys = new ConcurrentHashMap<>();
				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(= \\(containsKey (.+) \\\"(.+)\\\"\\) true\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String extraLocalSymbol = m.group(1);
						logger.info("Found extra local symbol: " + extraLocalSymbol);

						String key = m.group(2);
						logger.info("Found key for extra: " + key);

						extraLocalKeys.put(extraLocalSymbol,key);
					}
				}

				for (Map.Entry<String,String> entry : model.entrySet()) {
					String symbol = entry.getKey();
					String generatedValue = entry.getValue();
					logger.debug(symbol + ": " + generatedValue);

					Triplet<String, String, String> genDatum = generateDatum(symbol, generatedValue, extraLocalKeys);
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

					for (String uriSymbol : intentUriSymbols.values()) {
						if (uriSymbol.equals(symbol)) {
							uri = generatedValue.replaceAll("^\"|\"$", "");
						}
					}

				}

				for (String expr : currPathCond) {
					Pattern p = Pattern.compile("\\(assert \\(exists \\(\\(index Int\\)\\) \\(= \\(select cats index\\) \\\"(.+)\\\"\\)\\)\\)");
					Matcher m = p.matcher(expr);
					while (m.find()) {
						String category = m.group(1);
						logger.info("Found category: " + category);
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
						logger.info(("Found extra key: " + key));
						// TODO: TYPE CANNOT BE NULL
						//		So we just assume it is String, just need to bypass the if/else statement
						Triplet<String,String,String> extraDatum = new Triplet("String",key,null);
						extraData.add(extraDatum);
					}
				}

				logger.debug("");
			}
		} catch (Z3Exception e) {
			e.printStackTrace();
		}

		Intent genIntent = new Intent();
		genIntent.extras = new LinkedHashSet<>(extraData);
		genIntent.action = action;
		//genIntent.uri = uri;
		genIntent.categories = categories;
		genIntent.targetComponent = method.getDeclaringClass().getName();
		genIntent.targetMethod = method.getName();

		Intent modIntent = modifyGeneratedIntent(genIntent, startingUnit);

		if (pathIntents.containsKey(currPath)) {
			Intent prevIntent = pathIntents.get(currPath);
			logger.debug("Replacing " + prevIntent + " with " + modIntent);
		}
		pathIntents.put(currPath,modIntent);

		return new Pair<Intent,Boolean>(modIntent,isPathFeasible);
	}

	protected Intent modifyGeneratedIntent(Intent genIntent, Unit startingUnit) {
		return genIntent;
	}

	public Triplet<String, String, String> generateDatum(String symbol, String generatedValue, Map<String, String> extraLocalKeys) {
		Triplet<String, String, String> extraDatum = null;

		Local local = symbolLocalMap.get(symbol);
		String key = extraLocalKeys.get(symbol);

		if (local != null && key != null) {
			logger.debug(symbol.toString() + "'s key: " + key);
			extraDatum = new Triplet<String, String, String>(local.getType().toString(), key, generatedValue.toString().replaceAll("^\"|\"$", ""));
		}
		else {
			extraDatum = null;
		}
		return extraDatum;
	}

	public synchronized Pair<Map<String,String>,Boolean> returnSatisfyingModel(Integer sumUpIdx, Set<String> decls, Set<String> pathCond, Unit startingUnit, SootMethod method) throws Z3Exception {
		return returnSatisfyingModelForZ3(sumUpIdx, decls,pathCond,startingUnit,method);
	}

	public synchronized Pair<Map<String,String>,Boolean> returnSatisfyingModelForZ3(Integer sumUpIdx, Set<String> decls, Set<String> pathCond, Unit startingUnit, SootMethod method) throws Z3Exception {
		String pathCondFileName = null;
		try {
			pathCondFileName = Z3_RUNTIME_SPECS_DIR + File.separator + method.getDeclaringClass().getName() + "_" + startingUnit.getJavaSourceStartLineNumber() + "_z3_path_cond" + sumUpIdx.toString();
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
		logger.debug(pb.command().toString());
		/*Map<String,String> env = pb.environment();
		for (Map.Entry<String,String> e : env.entrySet()) {
			logger.debug(e.getKey() + "=" + e.getValue());
		}*/
		logger.debug("Running z3 solver");
		Process p = null;
		String returnedOutput = null;
		try {
			p = pb.start();
			if(!p.waitFor(3, TimeUnit.SECONDS)) {
				//timeout - kill the process.
				p.destroy(); // consider using destroyForcibly instead
				Boolean isSat = false;
				Map<String,String> model = new ConcurrentHashMap<String,String>();
				return new Pair<Map<String,String>,Boolean>(model,isSat);
			}
			logger.debug("Returned input stream as string:");
			returnedOutput = convertStreamToString(p.getInputStream());
			logger.debug(returnedOutput);
			logger.debug("Returned error stream as string:");
			String errorOut = convertStreamToString(p.getErrorStream());
			logger.debug(errorOut);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
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
		return new Pair<Map<String,String>,Boolean>(model,isSat);

	}

	static String convertStreamToString(InputStream is) {
		Scanner s = new Scanner(is).useDelimiter("\\A");
		return s.hasNext() ? s.next() : "";
	}

	public Set<String> handleIfStmt(int tabs, IfStmt currIfStmt, Unit succUnit, SootMethod method, SimpleLocalDefs defs, Set<String> decls, List<Unit> currPath) {
		logger.debug("currUnit: " + currIfStmt);
		String returnExpr = "";
		String opVal1Assert = null;
		String opVal2Assert = null;

		Unit opVal1DefUnit = null;
		Unit opVal2DefUnit = null;

		ConditionExpr condition = (ConditionExpr) currIfStmt.getCondition();
		logger.debug(Utils.createTabsStr(tabs) + "Handling if stmt: " + currIfStmt);
		logger.debug(Utils.createTabsStr(tabs) + "\thandling symbol: " + condition.getSymbol());
		Value opVal1 = condition.getOp1();
		Value opVal2 = condition.getOp2();

		Value opVal1Org = opVal1;
		//Value opVal2Org = opVal2;

		boolean generateCondExpr = true;
		if (opVal1.getType() instanceof ByteType) {
			logger.debug("opVal1.getType() instanceof ByteType");
			Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> condValuesPair = findLeftAndRightValuesOfByteVal(method, defs, currIfStmt, opVal1, currPath);
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
			logger.debug("opVal1.getType() instanceof BooleanType");
			Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> condValuesPair = findStringValuesOfBoolType(method, defs, currIfStmt, opVal1, currPath);
			Quartet<Value, String, String, Unit> left = condValuesPair.getValue0();
			Quartet<Value, String, String, Unit> right = condValuesPair.getValue1();

			if (left == null) {
				condValuesPair = findBundleValues(method, defs, currIfStmt, opVal1, currPath);
				left = condValuesPair.getValue0();
				right = condValuesPair.getValue1();

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
					findKeysForLeftAndRightValues(currIfStmt, opVal1, opVal2, defs, currPath);
				} else {
					opVal1 = left.getValue0();
					opVal2 = right.getValue0();
					AssignOpVals assignOpVals = new AssignOpVals(decls, opVal1Assert, opVal2Assert, opVal1, opVal2, left, right).invoke();
					opVal1DefUnit = assignOpVals.getOpVal1DefUnit();
					opVal2DefUnit = assignOpVals.getOpVal2DefUnit();
					opVal1Assert = assignOpVals.getOpVal1Assert();
					opVal2Assert = assignOpVals.getOpVal2Assert();
				}
			}

			if (left == null && right == null) {
				condValuesPair = findCategories(method, defs, currIfStmt, opVal1, currPath);
				left = condValuesPair.getValue0();
				right = condValuesPair.getValue1();

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
		} else {
			logger.debug("else branch, simply invoking findKeysForLeftAndRightValues(...)");
			findKeysForLeftAndRightValues(currIfStmt, opVal1, opVal2, defs, currPath);
			opVal1DefUnit = getDefOfValInPath(opVal1, currIfStmt, currPath, defs);
			opVal2DefUnit = getDefOfValInPath(opVal2, currIfStmt, currPath, defs);
			Stmt opVal1DefStmt = (Stmt) opVal1DefUnit;
			Stmt opVal2DefStmt = (Stmt) opVal2DefUnit;
			// sharetobrowser has a intent string extra that checks what it starts with
			if (opVal1DefStmt != null && opVal1DefStmt.containsInvokeExpr()) {
				InvokeExpr ie = opVal1DefStmt.getInvokeExpr();
				if (ie.getMethod().getName().equals("length") && ie.getMethod().getDeclaringClass().toString().equals("java.lang.String")) {
					// String length method is called
					String opExpr1 = createZ3Expr(opVal1, currIfStmt, opVal1DefUnit, method, decls, tabs);
					Local opStr = (Local) ((JVirtualInvokeExpr) ie).getBase();
					Unit opStrDefUnit = getDefOfValInPath(opStr, currIfStmt, currPath, defs);
					String opExpr2 = "(str.len " + createZ3Expr(opStr, currIfStmt, opStrDefUnit, method, decls, tabs) + ")";

					String condExpr = "(assert (= " + opExpr1 + " " + opExpr2 + "))";
					opVal1Assert = condExpr;
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
			logger.debug("No new information from this if stmt, so returning empty set of expressions");
			return returnExprs;
		}

		// create z3 variable
		String opExpr1 = null;
		String opExpr2 = null;
		try {
			if (opVal1 == null) {
				logger.debug("Could not resolve opVal1, so setting it to true");
				opExpr1 = "";
			} else {
				opExpr1 = createZ3Expr(opVal1, currIfStmt, opVal1DefUnit, method, decls, tabs);
			}

			if (opVal2 == null) {
				logger.debug("Could not resolve opVal2, so setting it to true");
				opExpr2 = "";
			} else {
				opExpr2 = createZ3Expr(opVal2, currIfStmt, opVal2DefUnit, method, decls, tabs);
			}
		} catch (RuntimeException e) {
			logger.warn("caught exception: ", e);
			return null;
		}

		if (opExpr1 == opExpr2 && opExpr1 == null) {
			logger.debug("op1 and op2 are both null, so just returning true expression");
			return Collections.singleton(returnExpr);
		}

		// if the curr unit to convert is an ifStmt ensure the symbol is not negated
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

		if (opVal1Assert != null) {
			if (opVal1Assert.contains("select keys index") && opVal2Assert == null) { // handling a hasExtra statement, so do not create additional expressions
				generateCondExpr = false;
			}
		}

		// get z3 constraints
		if (generateCondExpr) {
			// generatedCondExpr is initially set to true
			// at different points, can be set to false
			returnExpr = buildZ3CondExpr(tabs, opExpr1, opExpr2, branchSensitiveSymbol);
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

	private String buildZ3CondExpr(int tabs, String opExpr1, String opExpr2, String branchSensitiveSymbol) {
		String returnExpr;
		String condExpr = null;

		switch (branchSensitiveSymbol.trim()) {
			case "==":
				if (opExpr2.equals("Null"))
					condExpr = "(assert (= (isNull " + opExpr1 + ") true))";
				else if (isObjectEquals(opExpr1,opExpr2))
					condExpr = "(assert (= (oEquals " + opExpr1 + " "  + opExpr2 + ") true))";
				else
					condExpr = "(assert (= " + opExpr1 + " " + opExpr2 + "))";
				break;
			case "!=":
				if (opExpr2.equals("Null"))
					condExpr = "(assert (= (isNull " + opExpr1 + ") false))";
				else if (isObjectEquals(opExpr1,opExpr2))
					condExpr = "(assert (= (oEquals " + opExpr1 + " "  + opExpr2 + ") false))";
				else
					condExpr = "(assert (not (= " + opExpr1 + " " + opExpr2 + ")))";
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
		logger.debug(Utils.createTabsStr(tabs) + "z3 conditional expr: " + condExpr);

		if (condExpr == null) {
            logger.error("currExpr should not be null");
            logger.debug("opExpr1: " + opExpr1);
            logger.debug("opExpr2: " + opExpr2);
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
					String key = extractKeyFromIntentExtra(defStmt,defs,currPath);
					if(key != null) {
						valueKeyMap.put(opVal, key);
					}
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

	private String createZ3Expr(Value opVal, Unit currUnit, Unit defUnit, SootMethod method, Set<String> decls, int tabs) {
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
			JimpleLocal opLocal = (JimpleLocal) opVal;
			logger.debug(Utils.createTabsStr(tabs + 1) + "opLocal type: " + opLocal.getType());

			String symbol = null;

			DefinitionStmt defStmt = (DefinitionStmt) defUnit;
			if (defStmt.getLeftOp() == opVal) {
				symbol = createSymbol(opVal, method, defStmt);
				symbolLocalMap.put(symbol, opLocal);
				localSymbolMap.put(opLocal, symbol);
			}

			symbol = localSymbolMap.get(opLocal);
			if (symbol == null) {
				symbol = createSymbol(opVal, method, defUnit);
				symbolLocalMap.put(symbol, opLocal);
				localSymbolMap.put(opLocal, symbol);
			}

			switch (opLocal.getType().toString().trim()) {
				case "short":
					newDecl = "(declare-const " + symbol + " Int )";
					opExpr = symbol;
					break;
				case "int":
					newDecl = "(declare-const " + symbol + " Int )";
					opExpr = symbol;
					break;
				case "long":
					newDecl = "(declare-const " + symbol + " Int )";
					opExpr = symbol;
					break;
				case "float":
					newDecl = "(declare-const " + symbol + " Real )";
					opExpr = symbol;
					break;
				case "double":
					newDecl = "(declare-const " + symbol + " Real )";
					opExpr = symbol;
					break;
				case "boolean":
					newDecl = "(declare-const " + symbol + " Int )";
					opExpr = symbol;
					break;
				case "byte":
					newDecl = "(declare-const " + symbol + " Int )";
					opExpr = symbol;
					break;
				case "java.lang.String":
					newDecl = "(declare-const " + symbol + " String )";
					opExpr = symbol;
					break;
				default:
					// object is an arbitrary type so we'll mark it as null or not null
					logger.debug("Creating object with symbol: " + symbol + " for Local " + opLocal + " in " + method);
					newDecl = "(declare-const " + symbol + " Object )";
					opExpr = symbol;
			}
			decls.add(newDecl);
		} else {
			throw new RuntimeException("I don't know what to do with this Value's type: " + opVal.getType());
		}


		return opExpr;
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