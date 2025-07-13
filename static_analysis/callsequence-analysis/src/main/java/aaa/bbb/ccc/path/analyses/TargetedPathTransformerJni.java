package aaa.bbb.ccc.path.analyses;

import com.google.common.base.Joiner;
import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonWriter;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import aaa.bbb.ccc.android.model.*;
import aaa.bbb.ccc.path.analyses.getnatives.FullPathIntra;
import aaa.bbb.ccc.path.analyses.getnatives.JniCallsSummaries;
import org.javatuples.Pair;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.toolkits.graph.BriefBlockGraph;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;
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

public class TargetedPathTransformerJni {

	private static String ADB_TARGETED_INTENT_CMDS = "adb_targeted_intent_cmds_";

	static Logger logger = LoggerFactory.getLogger(TargetedPathTransformerJni.class);

	/**
	 * tracking JNI call sequences across whole program
	 */
	//Set<JniCallsSummaries> callsSummaries = new LinkedHashSet<JniCallsSummaries>();

	private ExecutorService executor;

	// Map<Unit,List<UnitPath>>: given an unit, return all paths in method that can lead to that unit
	Map<String, Pair<Boolean,Map<Unit, List<UnitPathJNI>>>> methodSummaries = new ConcurrentHashMap<>();
	Map<SootMethod, List<Unit>> methodFinalPaths = new ConcurrentHashMap<SootMethod, List<Unit>>();

	public Map<List<Unit>, Intent> getPathIntents() {
		return pathIntents;
	}

	Map<List<Unit>, Intent> pathIntents = new ConcurrentHashMap<List<Unit>, Intent>();

	public class UnitPathJNI {
		List<Unit> pathJNI;  // list of JNI call units
		List<Unit> path;

		String className;

		boolean initApplied;

		public UnitPathJNI(List<Unit> currPathJNI, List<Unit> currPath, String className) {
			this.pathJNI = currPathJNI;
			this.path = currPath;
			this.initApplied = false;
			this.className = className;
		}

		public UnitPathJNI(List<Unit> currPathJNI, List<Unit> currPath, boolean initApplied, String className) {
			this.pathJNI = currPathJNI;
			this.path = currPath;
			this.initApplied = initApplied;
			this.className = className;
		}

		public boolean appliedConstructorSum() {
			return initApplied;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			UnitPathJNI unitPath = (UnitPathJNI) o;

			if (!path.equals(unitPath.path)) return false;
			return pathJNI.equals(unitPath.pathJNI);
		}

		@Override
		public int hashCode() {
			int result = pathJNI.hashCode();
			result = 31 * result + path.hashCode();
			return result;
		}

		public List<Unit> getPathJNI() {
			return pathJNI;
		}

		public String getClassName() {
			return className;
		}

		public void addPathJNI(List<Unit> newPathJNI) {
			pathJNI.addAll(newPathJNI);
		}

		public void addPathJNIBefore(List<Unit> newPathJNI) {
			List<Unit> tmpPath = new ArrayList<Unit>(newPathJNI);
			tmpPath.addAll(pathJNI);
			pathJNI = tmpPath;
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

	public TargetedPathTransformerJni(String apkFilePath) {
		HashMap<String, String> config = new HashMap<String, String>();
		config.put("model", "true"); // turn on model generation for z3
		pathsAnalyzedCount = 0;
		this.apkFilePath = apkFilePath;
	}

	public static boolean isApplicationMethod(SootMethod method) {
		Chain<SootClass> applicationClasses = Scene.v().getApplicationClasses();
		for (SootClass appClass : applicationClasses) {
			if (appClass.getMethods().contains(method)) {
				return true;
			}
		}
		return false;
	}

	public Set<JniCallsSummaries> main(SootMethod method) {
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
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			});
		}

		Set<JniCallsSummaries> callsSummaries = new LinkedHashSet<JniCallsSummaries>();
		final BriefBlockGraph bug = new BriefBlockGraph(method.getActiveBody());
		if (bug.getBlocks().size() > basicBlockSize) {
			logger.debug("method " + method.getName() + " has block size that is too big: " + String.valueOf(bug.getBlocks().size()));
			return callsSummaries;
		}
		doPathAnalysis(method, true);

		System.out.println("Finishing executor...");
		executor.shutdown();
		System.out.println("Executor shutdown...");
		try {
			if (!executor.awaitTermination(timeout, TimeUnit.SECONDS)) {
				executor.shutdownNow();
			}
		} catch (InterruptedException e) {
			executor.shutdownNow();

		}

		for (Map.Entry<String, Pair<Boolean,Map<Unit, List<UnitPathJNI>>>> e : methodSummaries.entrySet()) {
			String methodSig = e.getKey();
			Pair<Boolean,Map<Unit, List<UnitPathJNI>>> p = e.getValue();
			Map<Unit, List<UnitPathJNI>> unitSum = p.getValue1();
			for (Map.Entry<Unit, List<UnitPathJNI>> ue : unitSum.entrySet()) {
				Unit u = ue.getKey();
				List<UnitPathJNI> paths = ue.getValue();
				callsSummaries.add(new JniCallsSummaries(methodSig, String.valueOf(u.getJavaSourceStartLineNumber()), u.toString(), paths));
			}
		}

		return callsSummaries;
	}

	public Set<JniCallsSummaries> main(List<SootMethod> rtoMethods, boolean isODCG) throws InterruptedException {

		if (!isODCG) {
			Runtime.getRuntime().addShutdownHook(new Thread() {
				@Override
				public void run() {
					//System.out.println("Shutdown hook ran!");
					Set<JniCallsSummaries> callsSummaries = new HashSet<JniCallsSummaries>();

					//System.out.println("CREATE callsSummaries");

					for (Map.Entry<String, Pair<Boolean,Map<Unit, List<UnitPathJNI>>>> e : methodSummaries.entrySet()) {
						String methodSig = e.getKey();
						Pair<Boolean,Map<Unit, List<UnitPathJNI>>> p = e.getValue();
						Boolean summaryApplied = p.getValue0();
						if (summaryApplied) {
							continue;
						}
						Map<Unit, List<UnitPathJNI>> unitSum = p.getValue1();
						for (Map.Entry<Unit, List<UnitPathJNI>> ue : unitSum.entrySet()) {
							Unit u = ue.getKey();
							List<UnitPathJNI> paths = ue.getValue();
							callsSummaries.add(new JniCallsSummaries(methodSig, String.valueOf(u.getJavaSourceStartLineNumber()), u.toString(), paths));
						}
					}

					// write methodSummaries as JSON to disk
					String apkName = Utils.getApkJsonNameFromPath(apkFilePath);
					try {
						JsonWriter writer = new JsonWriter(new FileWriter("nativesAnalysis" + File.separator + "CS_" + apkName));
						Gson gson = new GsonBuilder().disableHtmlEscaping().create();
						writer.beginArray();

						for (JniCallsSummaries callSum : callsSummaries) {
							gson.toJson(callSum, JniCallsSummaries.class, writer);
						}

						writer.endArray();
						writer.flush();
						writer.close();
					} catch (IOException e) {
						throw new RuntimeException(e);
					}
				}
			});
		}

		// dynamic registration
		if (!isODCG) {
			List<SootMethod> newEntryPoints = new ArrayList<SootMethod>(Scene.v().getEntryPoints());
			Scene.v().setEntryPoints(newEntryPoints);
			Hierarchy h = Scene.v().getActiveHierarchy();
			List<SootMethod> dynRegReceiverEntryPoints = new ArrayList<SootMethod>();
			for (SootClass sc : Scene.v().getApplicationClasses()) {
				if (Utils.androidPrefixPkgNames.stream().filter(pkg -> sc.getFilePath().startsWith(pkg)).count() != 0) {
					continue;
				}
				for (SootMethod m : sc.getMethods()) {
					Body b;
					try {
						b = m.retrieveActiveBody();
					} catch (Exception e) {
						continue;
					}
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
										if (ie.getArgCount() == 0) {
											continue;
										}
										String registeredType = ie.getArg(0).getType().toString();


										logger.debug("Type registered here: " + registeredType);
										SootClass receiverClass = Scene.v().getSootClass(registeredType);
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
		}

		int currMethodCount = 1;

		executor = null;
		//executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());  //thread switching can be avoided
		executor = Executors.newSingleThreadExecutor();
		/*
		if (parallelEnabled)
			executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());  //thread switching can be avoided
		else
			executor = Executors.newSingleThreadExecutor();
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


		List<String> visitedConstructors = new ArrayList<>();
		for (SootMethod method : rtoMethods) {
			//System.out.println("~ " + method.getDeclaringClass().getFilePath() + "~" + method.getSignature());

			if (!Utils.isUserMethodAndrolib(method)) {
				continue;
			}
			//System.out.println("- " + method.getSignature());
			if (!method.getDeclaringClass().getName().startsWith("android.support")) {
				if (method.hasActiveBody()) {
					// analyze method
					// will update MethodSummaries (sub sub sub call..)
					// will write the ...z3_path_cond file
					// will generate intents to data/ if encountered
					Collection<Future<?>> futures = new LinkedList<Future<?>>();
					//List futures = new ArrayList<>();
					doPathAnalysis(method, false, futures);
					for (Future<?> future : futures) {
						try {
							future.get(timeout, TimeUnit.MINUTES);
							//future.get();  // make timeout not a constant
						} catch (Exception e) {
							future.cancel(true);  // send interrupt to thread
						}
					}
					//executor.invokeAll(futures, 1, TimeUnit.MINUTES);  // TODO: how long you want analysis of each method?
					//executor.invokeAll(futures);  // TODO: how long you want analysis of each method?
					// method is not a constructor
					// post-dominator analysis
					// perform intraprocedural analysis to mark the units in methodSummaries[method] that
					// will always be called by another unit that is also in methodSummaries[method] for
					// applying summary
					UnitGraph ug = new BriefUnitGraph(method.getActiveBody());
					if (!methodSummaries.containsKey(method.getSignature())) {
						// no summary were created for method just analyzed
						continue;
					}
					Pair<Boolean,Map<Unit, List<UnitPathJNI>>> pair = methodSummaries.get(method.getSignature());
					Map<Unit, List<UnitPathJNI>> unitSum = pair.getValue1();
					Set<Unit> unitSumKeys = unitSum.keySet();
					FullPathIntra intraAnalysis = new FullPathIntra(ug, unitSumKeys);
					List<Unit> fullPaths = new ArrayList<Unit>();
					for (Map.Entry<Unit, List<UnitPathJNI>> ue : unitSum.entrySet()) {
						Unit u = ue.getKey();
						if (intraAnalysis.getFlowAfter(u).isEmpty()) {
							// get paths where it ends at a JNI call that will not be followed by another JNI
							fullPaths.add(u);
						}
					}
					methodFinalPaths.put(method, fullPaths);

					// whole-program mode
					if (method.isConstructor() && !isODCG) {
						// method is a constructor
						// no need for post-dominator analysis
						// instead, expand all JNI methods found with the sequences in method in the same class
						if (visitedConstructors.contains(method.getSignature())) {
							// constructor already visited
							continue;
						}
						if (!methodSummaries.containsKey(method.getSignature())) {
							// no summary were created for method just analyzed
							continue;
						}
						if (fullPaths.isEmpty()) {
							continue;
						}
						unitSum = methodSummaries.get(method.getSignature()).getValue1();
						CallGraph cg = Scene.v().getCallGraph();
						Iterator<Edge> edges = cg.edgesInto(method);
						boolean directDummyCallee = true;
						while (edges.hasNext()) {
							Edge edge = edges.next();
							if (!edge.kind().name().equals("SPECIAL")) {
								directDummyCallee = false;
							}
						}
						if (!directDummyCallee) {
							// another constructor calls it
							continue;
						}
						visitedConstructors.add(method.getSignature());
						// get all methods in constructor's class if constructor summary is not empty
						List<SootMethod> constructorMethods = method.getDeclaringClass().getMethods();
						for (SootMethod cm : constructorMethods) {
							if (!methodSummaries.containsKey(cm.getSignature())) {
								continue;
							}
							if (cm.isConstructor()) {
								// is itself
								continue;
							}
							boolean publicFacing = false;  // if next if-stmt is false, cm is a lifecycle method
							if (!cg.isEntryMethod(cm)) {
								// not a lifecycle entry
								// check if it is a user-facing method
								// public facing methods can be called in another component without lifecycle
								// entry point executing first
								String scSig = cm.getDeclaringClass().getName();
								edges = cg.edgesInto(cm);
								publicFacing = true;
								while (edges.hasNext()) {
									Edge edge = edges.next();
									SootMethod srcMethod = edge.getSrc().method();
									String cmSrcSig = srcMethod.getDeclaringClass().getName();
									if (cmSrcSig.equals(scSig)) {
										// method not completely public facing
										publicFacing = false;
									}
								}
								if (!publicFacing) {
									continue;
								}
							}
							// extract call sequences for method `cm`
							Map<Unit, List<UnitPathJNI>> cmUnitSum = methodSummaries.get(cm.getSignature()).getValue1();
							for (Map.Entry<Unit, List<UnitPathJNI>> ue : cmUnitSum.entrySet()) {
								List<UnitPathJNI> newCallSequences = new ArrayList<UnitPathJNI>();
								Unit u = ue.getKey();
								List<UnitPathJNI> paths = ue.getValue();
								for (Map.Entry<Unit, List<UnitPathJNI>> cue : unitSum.entrySet()) {
									Unit cu = cue.getKey();
									if (!fullPaths.contains(cu)) {
										continue;
									}
									List<UnitPathJNI> cpaths = cue.getValue();  // constructor call sequences
									for (UnitPathJNI cp : cpaths) {
										for (UnitPathJNI path : paths) {
											if (!path.appliedConstructorSum()) {
												// only apply current constructor paths to paths with no constructor paths
												// else, multiple constructor paths can be applied
												UnitPathJNI tmpPath = new UnitPathJNI(new ArrayList<>(path.getPathJNI()), new ArrayList<>(path.getPath()), true, cm.getDeclaringClass().getName());
												tmpPath.addPathJNIBefore(cp.getPathJNI());  // add constructor call sequences
												newCallSequences.add(tmpPath);
											}
										}
									}
								}
								if (!newCallSequences.isEmpty()) {
									// UPDATE method call sequence
									// there are updates to call sequences with call sequences in constructor
									newCallSequences.addAll(paths); // original paths
							/*
							if (publicFacing) {
								// if cm is a lifecycle entry, only cm's constructor will be called prior
								// not another method's constructor
								// to avoid applying constructor call sequences multiple times, track
								// the original `paths` so we can apply paths instead for summary if
								// the constructor call sequences are already applied by a prior method
								// call
								newCallSequences.addAll(paths); // original paths
							}
							 */
									cmUnitSum.put(u, newCallSequences);
								}
							}
						}
					}

				} else {
					logger.debug("method " + method + " has no active body, so it won't be analyzed.");
				}
			}
			logger.debug("Finished path analysis on method: " + method);
			logger.debug("Number of methods analyzed: " + currMethodCount);
			currMethodCount++;
			//System.out.println("DONE ANALYZING ONE METHOD");
		}

		// paused executor since we need executor to finish for each method after doPathAnalysis
		System.out.println("Finishing executor...");
		executor.shutdown();  // stop allowing new task to be added
		System.out.println("Executor shutdown...");
		executor.shutdownNow();  // stop all tasks. Analysis is done
		System.out.println("Executor shutdownNow() finished...");


		// TODO: Creating JSON can be slow!
		// ran smoothly
		Set<JniCallsSummaries> callsSummaries = new LinkedHashSet<JniCallsSummaries>();

		System.out.println("CREATE callsSummaries");
		for (Map.Entry<String, Pair<Boolean,Map<Unit, List<UnitPathJNI>>>> e : methodSummaries.entrySet()) {
			String methodSig = e.getKey();
			Pair<Boolean,Map<Unit, List<UnitPathJNI>>> pair = e.getValue();
			Boolean summaryApplied = pair.getValue0();
			if (summaryApplied) {
				continue;
			}
			Map<Unit, List<UnitPathJNI>> unitSum = pair.getValue1();
			for (Map.Entry<Unit, List<UnitPathJNI>> ue : unitSum.entrySet()) {
				Unit u = ue.getKey();
				List<UnitPathJNI> paths = ue.getValue();
				callsSummaries.add(new JniCallsSummaries(methodSig, String.valueOf(u.getJavaSourceStartLineNumber()), u.toString(), paths));
			}
		}

		/*
		// write methodSummaries as JSON to disk
		if (!isODCG) {
			String apkName = Utils.getApkJsonNameFromPath(apkFilePath);
			try {
				JsonWriter writer = new JsonWriter(new FileWriter("nativesAnalysis" + File.separator + "CS_" + apkName));
				Gson gson = new GsonBuilder().disableHtmlEscaping().create();
				writer.beginArray();

				for (JniCallsSummaries callSum : callsSummaries) {
					gson.toJson(callSum, JniCallsSummaries.class, writer);
				}

				writer.endArray();
				writer.flush();
				writer.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
		 */

		return callsSummaries;
	}


	private void doPathAnalysis(final SootMethod method, boolean isIntra) {
		Body b = method.getActiveBody();
		PatchingChain<Unit> units = b.getUnits();
		final BriefUnitGraph ug = new BriefUnitGraph(b);
		final String currClassName = method.getDeclaringClass().getName();
		int totalUnitsToAnalyzeCount = 0;

		int currUnitToAnalyzeCount = 0;
		for (final Unit unit : units) {
			boolean performPathAnalysis = false;

			synchronized (method) {
				performPathAnalysis = unitNeedsAnalysis(method, currClassName, unit, methodSummaries, isIntra);
			}

			if (performPathAnalysis) {
				logger.debug("Performing path analysis for unit: " + unit + " in method: " + method.getSignature());
				logger.debug("Currently analyzing unit " + currUnitToAnalyzeCount + " of " + totalUnitsToAnalyzeCount);
				StopWatch stopWatch = new StopWatch();
				stopWatch.start();

				// unit becomes startingUnit in callees
				doPathAnalysisOnUnitUsingExecutor(method, ug, currClassName, unit, isIntra);
				//doPathAnalysisOnUnit(0, method, ug, currClassName, unit, isIntra);
				totalUnitsToAnalyzeCount++;
				stopWatch.stop();
				logger.debug("Time to compute unit " + currUnitToAnalyzeCount + ": " + stopWatch.getElapsedTime());

				Pair<Unit, SootMethod> unitMethod = new Pair<Unit, SootMethod>(unit, method);
				//targetedUnits.add(unitMethod);

				currUnitToAnalyzeCount++;
			}
		}
	}

	private void doPathAnalysis(final SootMethod method, boolean isIntra, Collection<Future<?>> futures) {
	//private void doPathAnalysis(final SootMethod method, boolean isIntra, List<Callable> futures) {
		Body b = method.getActiveBody();
		PatchingChain<Unit> units = b.getUnits();
		final BriefUnitGraph ug = new BriefUnitGraph(b);
		final String currClassName = method.getDeclaringClass().getName();
		int totalUnitsToAnalyzeCount = 0;

		int currUnitToAnalyzeCount = 0;
		for (final Unit unit : units) {
			boolean performPathAnalysis = false;

			synchronized (method) {
				performPathAnalysis = unitNeedsAnalysis(method, currClassName, unit, methodSummaries, isIntra);
			}

			if (performPathAnalysis) {
				logger.debug("Performing path analysis for unit: " + unit + " in method: " + method.getSignature());
				logger.debug("Currently analyzing unit " + currUnitToAnalyzeCount + " of " + totalUnitsToAnalyzeCount);
				StopWatch stopWatch = new StopWatch();
				stopWatch.start();

				// unit becomes startingUnit in callees
				doPathAnalysisOnUnitUsingExecutor(method, ug, currClassName, unit, isIntra, futures);
				totalUnitsToAnalyzeCount++;
				stopWatch.stop();
				logger.debug("Time to compute unit " + currUnitToAnalyzeCount + ": " + stopWatch.getElapsedTime());

				Pair<Unit, SootMethod> unitMethod = new Pair<Unit, SootMethod>(unit, method);
				//targetedUnits.add(unitMethod);

				currUnitToAnalyzeCount++;
			}
		}
	}

	public void doPathAnalysisOnUnitUsingExecutor(final SootMethod method,
												  final BriefUnitGraph ug,
												  final String currClassName,
												  final Unit unit,
												  final boolean isIntra) {
		executor.execute(new Runnable() {
			@Override
			public void run() {
				Options.v().set_time(false);

				logger.debug("begin path analysis on unit " + unit + " of method " + method);
				doPathAnalysisOnUnit(0, method, ug, currClassName, unit, isIntra);
				logger.debug("end path analysis on unit " + unit + " of method " + method);

			}
		});
	}

	public void doPathAnalysisOnUnitUsingExecutor(final SootMethod method,
												  final BriefUnitGraph ug,
												  final String currClassName,
												  final Unit unit,
												  final boolean isIntra,
												  Collection<Future<?>> futures) {
		futures.add(executor.submit(new Runnable() {
			@Override
			public void run() {
				Options.v().set_time(false);

				logger.debug("begin path analysis on unit " + unit + " of method " + method);
				doPathAnalysisOnUnit(0, method, ug, currClassName, unit, isIntra);
				logger.debug("end path analysis on unit " + unit + " of method " + method);

			}
		}));
		/*
		executor.execute(() -> {
			Options.v().set_time(false);

			logger.debug("begin path analysis on unit " + unit + " of method " + method);
			doPathAnalysisOnUnit(0, method, ug, currClassName, unit, isIntra);
			logger.debug("end path analysis on unit " + unit + " of method " + method);

		});
		 */
		/*
		futures.add(new Callable<Integer>() {
			@Override
			public Integer call() {
				Options.v().set_time(false);

				logger.debug("begin path analysis on unit " + unit + " of method " + method);
				doPathAnalysisOnUnit(0, method, ug, currClassName, unit, isIntra);
				logger.debug("end path analysis on unit " + unit + " of method " + method);
				return 0;
			}
		});
		 */
	}

	public Boolean isFuncCall(Unit unit) {
		Stmt inStmt = (Stmt) unit;
		if (inStmt.containsInvokeExpr()) {
			InvokeExpr ie = inStmt.getInvokeExpr();
			SootMethod calledMethod = ie.getMethod();
			if (Utils.isAndroidMethodAndroLib(calledMethod)) {
				return false;
			}
			return true;
		}

		return false;
	}

	public void doPathAnalysisOnUnit(int tabs, SootMethod method, BriefUnitGraph ug, String currClassName, Unit startingUnit, boolean isIntra) {

/*
		BloomFilter<String> visitedUnits
				= BloomFilter.create(
				Funnels.stringFunnel(
						Charset.forName("UTF-8")),
				10000, 0.005);
*/
		Stack<Unit> workUnits = new Stack<Unit>(); // working stack for units to start or continue path analysis from
		workUnits.push(startingUnit);

		Stack<List<Unit>> workPaths = new Stack<List<Unit>>(); // working stack for paths under analysis
		List<Unit> initialPath = new ArrayList<Unit>();
		initialPath.add(startingUnit); // startingUnit is always a native method call
		workPaths.push(initialPath);

		Set<List<Unit>> finalPaths = new LinkedHashSet<List<Unit>>();

		boolean hitPathsLimit = false;
		/*
		if (!pathLimitEnabled) {
			finalPathsLimit = Integer.MAX_VALUE;
		}
		 */

		// Perform backward analysis to fill in finalPaths with all paths that can lead to unit
		// No "actual" analysis is performed yet, just paths extraction
		//Map<Unit, List<UnitPathJNI>> unitSum = null;
		Pair<Boolean,Map<Unit, List<UnitPathJNI>>> pair = null;
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
//			visitedUnits.put(startUnitOfCurrPath.toString());

			if (ug.getPredsOf(startUnitOfCurrPath).isEmpty()) { // if there are no more predecessors than we reached the end of the path
				if (logger.isTraceEnabled()) {
					logger.trace("A final path:");
					logger.trace("\n" + Joiner.on("\n").join(currPath));
				}
				if (startUnitOfCurrPath instanceof IdentityStmt) {
					// Reach the beginning of the function
					IdentityStmt idStmt = (IdentityStmt) startUnitOfCurrPath;
					if (idStmt.getRightOp() instanceof CaughtExceptionRef) {
						logger.trace("Exceptional path is not being analyzed for now");
					} else {
						if (finalPaths.size() < finalPathsLimit) {
							// add currPath to path to analyze if it reaches the beginning and is less than a pre-set limit
							finalPaths.add(currPath);
							continue;
						} else {
							System.out.println("PATH LIMITS HIT");
							hitPathsLimit = true;
							break;
						}
					}
				}
			}

			// traversing in reverse
			for (Unit pred : ug.getPredsOf(startUnitOfCurrPath)) { // update paths based on predecessors
/*
				if (visitedUnits.mightContain(pred.toString())) {
					logger.trace(Utils.createTabsStr(tabs) + "loop detected---already followed this edge!");
					continue;
				}
*/
				if (currPath.contains(pred)) {
					logger.trace(Utils.createTabsStr(tabs) + "loop detected---already followed this edge!");
					continue;
				}

				if (logger.isTraceEnabled()) {
					logger.trace("Forking the following path on predecessor unit " + pred);
					logger.trace(Joiner.on("\n").join(currPath) + "\n");
				}

				List<Unit> newPath = new ArrayList<Unit>(currPath);
				if (isFuncCall(pred)) {
					newPath.add(pred); // add to end of list, so path is reverse
				} else if (ug.getPredsOf(pred).size() > 1) {
					newPath.add(pred); // may contain backedge
				}

				// if there are two preds, two new paths will be created
				workPaths.push(newPath);
				workUnits.push(pred);
				logger.trace(Utils.createTabsStr(tabs) + "workUnits size: " + workUnits.size());

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
			final BriefBlockGraph bug = new BriefBlockGraph(method.getActiveBody());
			logger.debug("Path limit hit for unit " + startingUnit + " in method " + method + String.valueOf(bug.getBlocks().size()));
		}

		// finalPaths contain all possible paths in the function
		// each element of finalPaths is a possible path in the function based on CFG
		// each path is in reverse
		logger.debug("Path Extraction Done. Total finalPaths: " + String.valueOf(finalPaths.size()));
		for (List<Unit> currPath : finalPaths) { // analyzed fully-determined relevant program paths
			if(Thread.currentThread().isInterrupted()) {
				// time is up
				return;
			}
			//this.pathsAnalyzedCount++;
			//List<Unit> currPathJNI = new ArrayList<Unit>();
			Set<List<Unit>> currPathJNIs = new HashSet<List<Unit>>();

			// perform intra-procedural analysis
			// updates currPathJNI with JNI call sequence
			// make currPathJNI a list of list of units (in case for expanding method call's JNI call sequences)
			// problem - when expanding, an unit in the unitSum hashtable may not be the final JNI unit reached,
			// so if expand based on that unit's JNI call sequence, it will be incomplete.
			// ~ for every unit in unitSum, which ones will not be in the path of another unit in unitSum
			// create methodIntraSummaries that only track intraprocedural JNI call sequences.
			// what about a method that contains two methods that eventually call JNI methods

			// if currPath has a method call in methodSummaries, multiple
			// curPathJNIs may be generated
			Boolean isInterrupted = analyzeProgramPath(tabs, method, currPath, currPathJNIs, isIntra);
			if (isInterrupted) {
				return;
			}

			// current intraprocedural path
			// currPathJNI contains the number of encountered JNI calls in currPath
			Iterator iterCurrPathJNIs = currPathJNIs.iterator();
			while (iterCurrPathJNIs.hasNext()) {
				List<Unit> currPathJNI = (List<Unit>) iterCurrPathJNIs.next();
				UnitPathJNI up = new UnitPathJNI(currPathJNI, currPath, method.getDeclaringClass().getName());

				// store to methodSummaries
				// unitSum is a map of unit to list of unitpathJNI that leads to it
				if (methodSummaries.containsKey(method.getSignature())) {
					pair = methodSummaries.get(method.getSignature());
				} else {
					pair = new Pair<Boolean,Map<Unit, List<UnitPathJNI>>>(false, new ConcurrentHashMap<Unit, List<UnitPathJNI>>());
				}
				Map<Unit, List<UnitPathJNI>> unitSum = pair.getValue1();
				List<UnitPathJNI> unitPathJNIs = null;
				if (unitSum.containsKey(startingUnit)) {
					// there are paths found previously for startingUnit
					unitPathJNIs = unitSum.get(startingUnit);
				} else {
					// first path found for startingUnit
					unitPathJNIs = new ArrayList<UnitPathJNI>();
				}
				unitPathJNIs.add(up);
				unitSum.put(startingUnit, unitPathJNIs);
				pair = pair.setAt1(unitSum);
				methodSummaries.put(method.getSignature(), pair);
			}

		}
	}

	private SootMethod findSummaries(String subSignature, String declaringClass) {
		for (Map.Entry<String, Pair<Boolean,Map<Unit, List<UnitPathJNI>>>> e : methodSummaries.entrySet()) {
			String methodSig = e.getKey();
			if (methodSig.startsWith("<"+declaringClass) && methodSig.contains(subSignature)) {
				return Scene.v().getMethod(methodSig);
			}
		}
		return null;
	}

	private Set<List<Unit>> applySummary(Set<List<Unit>> wipCurrPathJNIs, List<String> initsApplied, SootMethod calledMethod, SootMethod method) {
		// make methodSummaries Map<Pair<Integer,Unit>, List<UnitPathJNI>> where the Integer
		// is used to indicate if Unit will always be called by another unit in methodSummaries
		// 1 means yes and 0 means no
		// create a new unitPathJNI that is current unitPathJNI + current iteration of unitPathJNI
		Boolean summaryApplied = false;
		Pair<Boolean, Map<Unit, List<UnitPathJNI>>> pair = methodSummaries.get(calledMethod.getSignature());
		Map<Unit, List<UnitPathJNI>> unitSum = pair.getValue1();
		String calledClass = calledMethod.getDeclaringClass().getName();
		Set<List<Unit>> calleeFullSeqs = new HashSet<>();
		// extract full callee call sequences
		for (Map.Entry<Unit, List<UnitPathJNI>> ue : unitSum.entrySet()) {
			Unit u = ue.getKey();
			List<Unit> calledMethodFullPaths = methodFinalPaths.get(calledMethod);
			if (calledMethodFullPaths == null) {
				// no full path JNI call sequence in callee's summary
				continue;
			}
			if (!calledMethodFullPaths.contains(u)) {
				// unit in callee summary is post-dominated by another callee call sequence
				continue;
			}
			// interprocedural constraint exists at this point
			List<UnitPathJNI> paths = ue.getValue();
			for (UnitPathJNI p : paths) {
				// only apply constructor summary once along the path
				if (!initsApplied.contains(calledClass)) {
					if (p.getClassName().startsWith(method.getDeclaringClass().getName())) {
						// current path's class is the same class as callee's class
						if (!p.appliedConstructorSum()) {
							// if current path's class is the same class as callee's class, then
							// use callee summary without constructor
							summaryApplied = true;
							calleeFullSeqs.add(p.pathJNI);
						}
					} else {
						// current path's class is a different class than callee's class
						if (p.appliedConstructorSum()) {
							// only apply callee summary with constructor if current path is in a
							// different class than callee's class
							summaryApplied = true;
							calleeFullSeqs.add(p.pathJNI);
						}
					}
				} else {
					if (!p.appliedConstructorSum()) {
						summaryApplied = true;
						calleeFullSeqs.add(p.pathJNI);
					}
				}
			}
		}
		initsApplied.add(calledClass);
		// apply callee call sequences summary
		if (!wipCurrPathJNIs.isEmpty()) {
			Set<List<Unit>> tmpCurrPathJNIs = new HashSet<List<Unit>>(wipCurrPathJNIs);
			wipCurrPathJNIs = new HashSet<List<Unit>>();
			// new paths = each original JNI path X interprocedural JNI paths
			for (List<Unit> currPathJNI : tmpCurrPathJNIs) {
				for (List<Unit> calleePath : calleeFullSeqs) {
					// each `up` is a full callee call sequence
					List<Unit> wipCurrPathJNI = new ArrayList<Unit>(currPathJNI);
					wipCurrPathJNI.addAll(calleePath);
					wipCurrPathJNIs.add(wipCurrPathJNI);
				}
			}
		} else {
			// wipCurrPathJNIs is empty
			for (List<Unit> calleePath : calleeFullSeqs) {
				List<Unit> wipCurrPathJNI = new ArrayList<Unit>();
				wipCurrPathJNI.addAll(calleePath);
				wipCurrPathJNIs.add(wipCurrPathJNI);
			}
		}
		if (summaryApplied) {
			pair = pair.setAt0(true);
			methodSummaries.put(calledMethod.getSignature(), pair);
		}
		return wipCurrPathJNIs;
	}

	private Boolean analyzeProgramPath(int tabs, SootMethod method, List<Unit> currPath, Set<List<Unit>> currPathJNIs, boolean isIntra) {
		Set<List<Unit>> wipCurrPathJNIs = new HashSet<List<Unit>>();
		List<Unit> currPathAsList = new ArrayList<Unit>(currPath);
		List<String> initsApplied = new ArrayList<>();
		for (int i = currPathAsList.size()-1; i >= 0; i--) {
			if(Thread.currentThread().isInterrupted()) {
				// time is up
				return true;
			}
			// iterating each instruction in path currPath
			// iterate in execution order
			Unit currUnitInPath = currPathAsList.get(i); // current unit under analysis for current path
			if (!method.hasActiveBody()) {
				throw new RuntimeException("method has no active body, which shouldn't happen: " + method.getName());
			}

			Stmt currStmtInPath = (Stmt) currUnitInPath;
			if (!currStmtInPath.containsInvokeExpr()) {
				continue;
			}

			InvokeExpr ie = currStmtInPath.getInvokeExpr();
			SootMethod calledMethod = ie.getMethod();
			// check if unit is a JNI call
			if (Utils.isAndroidMethodAndroLib(calledMethod)) {
				// skip non-JNI methods
				continue;
			}
			if (calledMethod.getDeclaration().contains(" native ")) {
				if (!wipCurrPathJNIs.isEmpty()) {
					for (List<Unit> currPathJNI : wipCurrPathJNIs) {
						currPathJNI.add(currUnitInPath);
					}
				} else {
					// wipCurrPathJNIs is empty
					List<Unit> wipCurrPathJNI = new ArrayList<Unit>();
					wipCurrPathJNI.add(currUnitInPath);
					wipCurrPathJNIs.add(wipCurrPathJNI);
				}
			}

			if (!isIntra) {
				// also add to currPathJNI if it's to a method call that transitively calls a JNI method
				// this may result in multiple currPathJNIs
				if (!methodSummaries.containsKey(calledMethod.getSignature())
						&& !calledMethod.getSubSignature().startsWith("android.os.AsyncTask execute(")
						&& !calledMethod.getSignature().equals("<java.lang.Runnable: void run()>")
						&& !calledMethod.getSignature().startsWith("<android.os.AsyncTask: void publishProgress(")) {
					// no summary for callee (direct or indirect through AsyncTask)
					continue;
				}

				if (calledMethod.getSubSignature().startsWith("android.os.AsyncTask execute(")) {
					// model AsyncTask
					if (ie.getArgCount() != 1) {
						continue;
					}
					Value calledMethodArg = ie.getArg(0);
					String calledMethodArgType = calledMethodArg.getType().toString();
					if (ie instanceof InstanceInvokeExpr) {
						InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
						String asyncImplClass = iie.getBase().getType().toString();
						SootMethod onPreExecute = findSummaries("void onPreExecute()", asyncImplClass);
						SootMethod doInBackground = findSummaries("doInBackground("+calledMethodArgType+")", asyncImplClass);  // return type is parameterized
						SootMethod onPostExecute = findSummaries("void onPostExecute(", asyncImplClass);
						if (onPreExecute == null && doInBackground == null && onPostExecute == null) {
							continue;
						}
						if (onPreExecute != null) {
							wipCurrPathJNIs = applySummary(wipCurrPathJNIs, initsApplied, onPreExecute, method);
						}
						if (doInBackground != null) {
							wipCurrPathJNIs = applySummary(wipCurrPathJNIs, initsApplied, doInBackground, method);
						}
						if (onPostExecute != null) {
							wipCurrPathJNIs  = applySummary(wipCurrPathJNIs, initsApplied, onPostExecute, method);
						}
					}
				} else if (calledMethod.getSignature().equals("<java.lang.Runnable: void run()>")) {
					SootMethod runnableRun = findSummaries("void run()", method.getDeclaringClass().getName());
					if (runnableRun != null) {
						wipCurrPathJNIs = applySummary(wipCurrPathJNIs, initsApplied, runnableRun, method);
					}
				} else if (calledMethod.getSignature().startsWith("<android.os.AsyncTask: void publishProgress(")) {
					if (ie.getArgCount() != 1) {
						continue;
					}
					Value calledMethodArg = ie.getArg(0);
					String calledMethodArgType = calledMethodArg.getType().toString();
					if (ie instanceof InstanceInvokeExpr) {
						InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
						String asyncImplClass = iie.getBase().getType().toString();
						SootMethod onProgressUpdate = findSummaries("void onProgressUpdate("+calledMethodArgType, asyncImplClass);
						if (onProgressUpdate != null) {
							wipCurrPathJNIs = applySummary(wipCurrPathJNIs, initsApplied, onProgressUpdate, method);
						}
					}
				} else {
					wipCurrPathJNIs = applySummary(wipCurrPathJNIs, initsApplied, calledMethod, method);
				}
			}
		}
		if (!wipCurrPathJNIs.isEmpty()) {
			currPathJNIs.addAll(wipCurrPathJNIs);
		}
		return false;
	}

	public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit unit, Map<String, Pair<Boolean,Map<Unit, List<UnitPathJNI>>>> methodSummaries, boolean isIntra) {
		if (unit instanceof InvokeStmt) {
			InvokeStmt stmt = (InvokeStmt) unit;
			if (stmt.getInvokeExpr().getMethod().getName().equals("d")) {
				return true;
			}
		}
		return false;
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
