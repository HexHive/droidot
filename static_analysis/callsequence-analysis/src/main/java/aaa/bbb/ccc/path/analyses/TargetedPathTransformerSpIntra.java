package aaa.bbb.ccc.path.analyses;

import com.google.common.base.Joiner;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonWriter;
import com.microsoft.z3.Z3Exception;
import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import aaa.bbb.ccc.android.model.*;
import aaa.bbb.ccc.path.analyses.getnatives.JniCallsSummaries;
import org.javatuples.Pair;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import polyglot.ast.Assign;
import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.collect.ConcurrentHashSet;
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
import soot.toolkits.scalar.FlowSet;
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

public class TargetedPathTransformerSpIntra {

    public Boolean reducedFlag = false;

    protected static final String DROZER_TARGETED_INTENT_CMDS = "drozer_targeted_intent_cmds_";
    private static String ADB_TARGETED_INTENT_CMDS = "adb_targeted_intent_cmds_";

    static Logger logger = LoggerFactory.getLogger(TargetedPathTransformerSp.class);
    private final String Z3_RUNTIME_SPECS_DIR = "z3_runtime_specs";
    private Set<SootClass> dynRegReceivers;

    /**
     * to track total number of intents generated
     */
    public Set<Intent> totalIntents = ConcurrentHashMap.newKeySet();;

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
    //private Map<Value, String> valueKeyMap = new ConcurrentHashMap<Value, String>();

    protected JimpleBasedInterproceduralCFG icfg;

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
    Set<Pair<Unit, SootMethod>> unitsWithGenData = new LinkedHashSet<Pair<Unit, SootMethod>>();
    Set<Pair<Unit, SootMethod>> unitsWithoutGenData = new LinkedHashSet<Pair<Unit, SootMethod>>();
    Set<Pair<Unit, SootMethod>> targetedUnits = new LinkedHashSet<Pair<Unit, SootMethod>>();
    Set<Pair<Unit, SootMethod>> infeasibleTargets = new LinkedHashSet<Pair<Unit, SootMethod>>();
    Set<Pair<Unit, SootMethod>> possiblyFeasibleNoGenTargets = new LinkedHashSet<Pair<Unit, SootMethod>>();
    Map<SootMethod, Map<Unit, List<UnitPath>>> methodSummaries = new ConcurrentHashMap<SootMethod, Map<Unit, List<UnitPath>>>();

    public Map<List<Unit>, Intent> getPathIntents() {
        return pathIntents;
    }

    Map<List<Unit>, Intent> pathIntents = new ConcurrentHashMap<List<Unit>, Intent>();

    class UnitPath {
        Set<String> pathCond;
        Set<String> decl;
        List<Unit> path;

        public UnitPath(Set<String> currPathCond, Set<String> currDecls, List<Unit> currPath) {
            this.pathCond = currPathCond;
            this.decl = currDecls;
            this.path = currPath;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            UnitPath unitPath = (UnitPath) o;

            if (!pathCond.equals(unitPath.pathCond)) return false;
            if (!decl.equals(unitPath.decl)) return false;
            return path.equals(unitPath.path);
        }

        @Override
        public int hashCode() {
            int result = pathCond.hashCode();
            result = 31 * result + decl.hashCode();
            result = 31 * result + path.hashCode();
            return result;
        }

        public Set<String> getPathCond() {
            return pathCond;
        }

        public void setPathCond(Set<String> pathCond) {
            this.pathCond = pathCond;
        }

        public Set<String> getDecl() {
            return decl;
        }

        public void setDecl(Set<String> decl) {
            this.decl = decl;
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

    TargetedPathTransformerSpIntra() {
        HashMap<String, String> config = new HashMap<String, String>();
        config.put("model", "true"); // turn on model generation for z3
        pathsAnalyzedCount = 0;
    }

    public String apkFilePath;

    public TargetedPathTransformerSpIntra(String apkFilePath) {
        this();
        G.reset();
        this.apkFilePath = apkFilePath;
        Config.apkFilePath = apkFilePath;
    }

    // Inter-procedural analysis
    public void main(boolean isODCG){

        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                // write intents as JSON to disk
                Path p = Paths.get(apkFilePath);
                String apkName = p.getFileName().toString();
                if (reducedFlag && parallelEnabled) {
                    apkName = apkName.substring(0, apkName.lastIndexOf('.')) + "_F_.json";
                } else if (reducedFlag) {
                    apkName = apkName.substring(0, apkName.lastIndexOf('.')) + "_R_.json";
                }else {
                    apkName = apkName.substring(0, apkName.lastIndexOf('.')) + "_P_.json";
                }
                try {
                    Writer iWriter = new FileWriter("intents"+File.separator+"intents_"+apkName);
                    Gson gsson = new GsonBuilder().create();
                    gsson.toJson(totalIntents, iWriter);
                    iWriter.flush();
                    iWriter.close();
                    logger.debug("Native analysis and Intent files generated");
                    //System.exit(0);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

        });

        logger.debug("Extracting data from manifest");
        androidProcessor.extractApkMetadata();

        logger.debug("Constructing entry points");
        Hierarchy h = Scene.v().getActiveHierarchy();
        List<SootMethod> nonLifeCycleEntryPoints = new ArrayList<SootMethod>();
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

		/*
		for (SootMethod m : rtoMethods) {
			if (m.getDeclaringClass().getName().contains("PackageIntentReceiver")) {
				logger.debug("Found method of PackageIntentReceiver: " + m);
			}
		}
		 */

        dynRegReceivers = new LinkedHashSet<SootClass>();  // EX: BroadcastReceivers
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
            final String baseDrozerIntentCmdsPath = "data" + File.separator + DROZER_TARGETED_INTENT_CMDS + androidProcessor.mainPackageName;
            //final String baseAdbIntentCmdsPath = "data" + File.separator + ADB_TARGETED_INTENT_CMDS + androidProcessor.mainPackageName;

            if (reducedFlag && parallelEnabled) {
                activityCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_activities_F_.sh");
                serviceCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_services_F_.sh");
                receiverCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_receivers_F_.sh");
            } else if (reducedFlag) {
                activityCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_activities_R_.sh");
                serviceCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_services_R_.sh");
                receiverCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_receivers_R_.sh");
            } else {
                activityCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_activities_P_.sh");
                serviceCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_services_P_.sh");
                receiverCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_receivers_P_.sh");
            }

            //activityCmdsAdbFileWriter = setupIntentCmdsWriter(baseAdbIntentCmdsPath,"_activities.sh");
            //serviceCmdsAdbFileWriter = setupIntentCmdsWriter(baseAdbIntentCmdsPath,"_services.sh");
            //receiverCmdsAdbFileWriter = setupIntentCmdsWriter(baseAdbIntentCmdsPath,"_receivers.sh");


            int currMethodCount = 1;
            logger.debug("total number of possible methods to analyze: " + rtoMethods.size());

            executor = null;
            logger.debug(">>> parallism on: " + String.valueOf(parallelEnabled));
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
            System.out.println("before rtoMethods iteration");
            for (SootMethod method : rtoMethods) {
                //logger.debug("Checking if I should analyze method: " + method);
                if (Utils.isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
                    if (method.hasActiveBody()) {
                        // analyze method
                        // will update MethodSummaries (sub sub sub call..)
                        // will write the ...z3_path_cond file
                        // will generate intents to data/ if encountered
                        Collection<Future<?>> futures = new LinkedList<Future<?>>();
                        doPathAnalysis(method, futures, 0);  // inter-procedural
                        for (Future<?> future : futures) {
                            try {
                                future.get(3, TimeUnit.MINUTES);
                            } catch (TimeoutException e) {
                                future.cancel(true);  // send interrupt to thread
                            }
                        }
                    } else {
                        logger.debug("method " + method + " has no active body, so it won't be analyzed.");
                    }
                }
                logger.debug("Finished path analysis on method: " + method);
                logger.debug("Number of methods analyzed: " + currMethodCount);
                currMethodCount++;
            }
            // paused executor since we need executor to finish for each method after doPathAnalysis
            System.out.println("Finishing executor...");
            executor.shutdown();  // stop allowing new task to be added
            System.out.println("Executor shutdown...");
            executor.shutdownNow();  // stop all tasks. Analysis is done
            System.out.println("Executor shutdownNow() finished...");

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

			/*
			if (numOtherNonGeneratedTargets != possiblyFeasibleNoGenTargets.size()) {
				throw new RuntimeException("numOtherNonGeneratedTargets != otherNoGenTargets.size()");
			}
			 */

            logger.debug("Targets with generated data: ");
            printUnitMethods(unitsWithGenData);

            logger.debug("Targets withOUT generated data: ");
            printUnitMethods(unitsWithoutGenData);

			/*
			if (unitsWithGenData.size() + unitsWithoutGenData.size() != targetedUnits.size()) {
				// Debug guide:
				// If this statement is reached, it might be because the timeout has been reached by some executors.
				// The way to check is to see whether logs around where "doPathAnalysisOnUnit" can be matched.
				// ("begin path analysis on unit" and "end path analysis on unit"
				String errorMsg = "unitsWithGenData.size() + unitsWithoutGenData.size() != targetedUnits.size()";
				logger.error(errorMsg);
				System.err.print(errorMsg);
			}
			 */


        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ExecutionException|InterruptedException e) {
            throw new RuntimeException(e);
        }

    }

    // Intra-procedural analysis (v2)
    public Set<Intent> mainIntra(SootMethod method, Collection<Future<?>> futures, ExecutorService executor){
        try {
            synchronized (DROZER_TARGETED_INTENT_CMDS) {
                if (!outInitialization) {
                    logger.debug("Extracting data from manifest");
                    androidProcessor.extractApkMetadata();

                    final String baseDrozerIntentCmdsPath = "data" + File.separator + DROZER_TARGETED_INTENT_CMDS + androidProcessor.mainPackageName;
                    //final String baseAdbIntentCmdsPath = "data" + File.separator + ADB_TARGETED_INTENT_CMDS + androidProcessor.mainPackageName;

                    activityCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_activities_K_.sh");
                    serviceCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_services_K_.sh");
                    receiverCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_receivers_K_.sh");

                    outInitialization = true;
                }

				/*
				if (parallelEnabled) {
					executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
				} else {
					executor = Executors.newSingleThreadExecutor();
				}
				 */
                // by default (unfortunately) the ThreadPoolExecutor will throw an
                // exception
                // when you submit the job that fills the queue, to have it block you
                // do:

                long mainAnalysisStartTime = System.currentTimeMillis();

                if (Utils.isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
                    if (method.hasActiveBody()) {
                        //System.out.println("method: " + method.getSignature());
                        // analyze method
                        // will update MethodSummaries (sub sub sub call..)
                        // will write the ...z3_path_cond file
                        // will generate intents to data/ if encountered
                        //doPathAnalysis(method, true);
                        doPathAnalysis(method, futures, 2, executor);
                    } else {
                        logger.debug("method " + method + " has no active body, so it won't be analyzed.");
                    }
                }
                logger.debug("Finished path analysis on method: " + method);
                System.out.println("Finishing executor...");


                long mainAnalysisEndTime = System.currentTimeMillis();
                mainAnalysisRuntime = mainAnalysisEndTime - mainAnalysisStartTime;

                // Done writing so close them
                //flushIntentCmdsWriters(activityCmdsDrozerFileWriter, serviceCmdsDrozerFileWriter, receiverCmdsDrozerFileWriter);
                //flushIntentCmdsWriters(activityCmdsAdbFileWriter,serviceCmdsAdbFileWriter,receiverCmdsAdbFileWriter);

                //int numOtherNonGeneratedTargets = unitsWithoutGenData.size() - infeasibleTargets.size();
                //logger.debug("Number of units with generated data: " + unitsWithGenData.size());
                //logger.debug("Number of units without generated data: " + unitsWithoutGenData.size());
                //logger.debug("Number of infeasible targets: " + infeasibleTargets.size());
                //logger.debug("Number of other non-generated targets: " + numOtherNonGeneratedTargets);
                //logger.debug("Total number of targeted units: " + targetedUnits.size());
            }
        } catch(IOException e){
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return totalIntents;
    }

    // Intra-procedural analysis
    public Set<Intent> main(SootMethod method){
        try {
            synchronized (DROZER_TARGETED_INTENT_CMDS) {
                if (!outInitialization) {
                    logger.debug("Extracting data from manifest");
                    androidProcessor.extractApkMetadata();

                    final String baseDrozerIntentCmdsPath = "data" + File.separator + DROZER_TARGETED_INTENT_CMDS + androidProcessor.mainPackageName;
                    //final String baseAdbIntentCmdsPath = "data" + File.separator + ADB_TARGETED_INTENT_CMDS + androidProcessor.mainPackageName;

                    activityCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_activities_I_.sh");
                    serviceCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_services_I_.sh");
                    receiverCmdsDrozerFileWriter = setupIntentCmdsWriter(baseDrozerIntentCmdsPath, "_receivers_I_.sh");

                    outInitialization = true;
                }

                executor = null;
                executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
/*
				if (parallelEnabled) {
					executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
				} else {
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

                if (Utils.isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
                    if (method.hasActiveBody()) {
                        //System.out.println("method: " + method.getSignature());
                        // analyze method
                        // will update MethodSummaries (sub sub sub call..)
                        // will write the ...z3_path_cond file
                        // will generate intents to data/ if encountered
                        //doPathAnalysis(method, true);
                        StopWatch stopWatch = new StopWatch();
                        stopWatch.start();
                        Collection<Future<?>> futures = new LinkedList<Future<?>>();
                        doPathAnalysis(method, futures, 1);
                        for (Future<?> future : futures) {
                            try {
                                future.get(3, TimeUnit.MINUTES);
                            } catch (TimeoutException e) {
                                future.cancel(true);  // send interrupt to thread
                            } catch (ExecutionException | InterruptedException e) {
                                throw new RuntimeException(e);
                            }
                        }
                        stopWatch.stop();
                        System.out.println("Time to compute method: " + stopWatch.getElapsedTime());

                    } else {
                        logger.debug("method " + method + " has no active body, so it won't be analyzed.");
                    }
                }
                logger.debug("Finished path analysis on method: " + method);
                System.out.println("Finishing executor...");

                System.out.println("Finishing executor...");
                executor.shutdown();  // stop allowing new task to be added
                System.out.println("Executor shutdown...");
                executor.shutdownNow();  // stop all tasks. Analysis is done
                System.out.println("Executor shutdownNow() finished...");

                long mainAnalysisEndTime = System.currentTimeMillis();
                mainAnalysisRuntime = mainAnalysisEndTime - mainAnalysisStartTime;

                // Done writing so close them
                //flushIntentCmdsWriters(activityCmdsDrozerFileWriter, serviceCmdsDrozerFileWriter, receiverCmdsDrozerFileWriter);
                //flushIntentCmdsWriters(activityCmdsAdbFileWriter,serviceCmdsAdbFileWriter,receiverCmdsAdbFileWriter);

                //int numOtherNonGeneratedTargets = unitsWithoutGenData.size() - infeasibleTargets.size();
                //logger.debug("Number of units with generated data: " + unitsWithGenData.size());
                //logger.debug("Number of units without generated data: " + unitsWithoutGenData.size());
                //logger.debug("Number of infeasible targets: " + infeasibleTargets.size());
                //logger.debug("Number of other non-generated targets: " + numOtherNonGeneratedTargets);
                //logger.debug("Total number of targeted units: " + targetedUnits.size());
            }
        } catch(IOException e){
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return totalIntents;
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

    // for intra-procedural
    private void doPathAnalysis(final SootMethod method, Collection<Future<?>> futures, Integer analysisMode, ExecutorService executor) {
        // analysisMode: 0 -> inter-procedural, 1 -> intra-procedural, 2 -> intra-procedural v2
        Body b = method.getActiveBody();
        PatchingChain<Unit> units = b.getUnits();
        final BriefUnitGraph ug = new BriefUnitGraph(b);
        final String currClassName = method.getDeclaringClass().getName();
        int totalUnitsToAnalyzeCount = 0;

        int currUnitToAnalyzeCount = 0;
        List<Unit> onDemandApproved = new ArrayList<>();
        for (final Unit unit : units) {
            boolean performPathAnalysis = false;
            synchronized (method) {
                performPathAnalysis = unitNeedsAnalysis(method, currClassName, unit);
                if (performPathAnalysis) {
                    onDemandApproved.add(unit);
                }
            }

			if (performPathAnalysis) {
				logger.debug("Performing path analysis for unit: " + unit);
				//System.out.println("Performing path analysis for unit: " + unit);
				logger.debug("Currently analyzing unit " + currUnitToAnalyzeCount + " of " + totalUnitsToAnalyzeCount);
				//StopWatch stopWatch = new StopWatch();
				//stopWatch.start();
				// unit becomes startingUnit in callees
				doPathAnalysisOnUnitUsingExecutor(method, ug, currClassName, unit, futures, analysisMode, executor);
				totalUnitsToAnalyzeCount++;
				//stopWatch.stop();
				//logger.debug("Time to compute unit " + currUnitToAnalyzeCount + ": " + stopWatch.getElapsedTime());

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

    // for inter-procedural
    private void doPathAnalysis(final SootMethod method, Collection<Future<?>> futures, Integer analysisMode) {
        Body b = method.getActiveBody();
        PatchingChain<Unit> units = b.getUnits();
        final BriefUnitGraph ug = new BriefUnitGraph(b);
        final String currClassName = method.getDeclaringClass().getName();
        int totalUnitsToAnalyzeCount = 0;

        int currUnitToAnalyzeCount = 0;
        List<Unit> onDemandApproved = new ArrayList<>();
        for (final Unit unit : units) {
            boolean performPathAnalysis = false;
            synchronized (method) {
                performPathAnalysis = unitNeedsAnalysis(method, currClassName, unit);
                if (performPathAnalysis) {
                    onDemandApproved.add(unit);
                }
            }

			if (performPathAnalysis) {
				logger.debug("Performing path analysis for unit: " + unit);
				//System.out.println("Performing path analysis for unit: " + unit);
				logger.debug("Currently analyzing unit " + currUnitToAnalyzeCount + " of " + totalUnitsToAnalyzeCount);
				//StopWatch stopWatch = new StopWatch();
				//stopWatch.start();
				// unit becomes startingUnit in callees
				doPathAnalysisOnUnitUsingExecutor(method, ug, currClassName, unit, futures, analysisMode);
				totalUnitsToAnalyzeCount++;
				//stopWatch.stop();
				//logger.debug("Time to compute unit " + currUnitToAnalyzeCount + ": " + stopWatch.getElapsedTime());

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

    // for inter-procedural
    public void doPathAnalysisOnUnitUsingExecutor(final SootMethod method,
                                                  final BriefUnitGraph ug,
                                                  final String currClassName,
                                                  final Unit unit,
                                                  Collection<Future<?>> futures,
                                                  Integer analysisMode
    ) {
        futures.add(executor.submit(new Runnable() {
            @Override
            public void run() {
                Options.v().set_time(false);

                logger.debug("begin path analysis on unit " + unit + " of method " + method);
                boolean isFeasible = doPathAnalysisOnUnit(0, method, ug, currClassName, unit, pathAnalyses, analysisMode);
                logger.debug("end path analysis on unit " + unit + " of method " + method);
                logger.debug("Was path feasible for unit " + unit + " of method " + method + "? " + (isFeasible ? " Yes." : " No."));

                Pair<Unit, SootMethod> unitMethod = new Pair<Unit, SootMethod>(unit, method);
                if (!isFeasible) {
                    unitsWithoutGenData.add(unitMethod);
                } else {
                    unitsWithGenData.add(unitMethod);
                }
            }
        }));
    }

    // for intra-procedural analysis
    public void doPathAnalysisOnUnitUsingExecutor(final SootMethod method,
                                                  final BriefUnitGraph ug,
                                                  final String currClassName,
                                                  final Unit unit,
                                                  Collection<Future<?>> futures,
                                                  Integer analysisMode,
                                                  ExecutorService executor
    ) {
        futures.add(executor.submit(new Runnable() {
            @Override
            public void run() {
                Options.v().set_time(false);

                logger.debug("begin path analysis on unit " + unit + " of method " + method);
                boolean isFeasible = doPathAnalysisOnUnit(0, method, ug, currClassName, unit, pathAnalyses, analysisMode);
                logger.debug("end path analysis on unit " + unit + " of method " + method);
                logger.debug("Was path feasible for unit " + unit + " of method " + method + "? " + (isFeasible ? " Yes." : " No."));

                Pair<Unit, SootMethod> unitMethod = new Pair<Unit, SootMethod>(unit, method);
                if (!isFeasible) {
                    unitsWithoutGenData.add(unitMethod);
                } else {
                    unitsWithGenData.add(unitMethod);
                }
            }
        }));
    }

    public boolean doPathAnalysisOnUnit(int tabs, SootMethod method, BriefUnitGraph ug, String currClassName, Unit startingUnit, PathAnalysis pathAnalyses, Integer analysisMode) {

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

        int finalPathsLimit = 10000;
//		int finalPathsLimit = Integer.MAX_VALUE;
        boolean hitPathsLimit = false;
        if (!pathLimitEnabled) {
            finalPathsLimit = Integer.MAX_VALUE;
        }

        // Perform backward analysis to fill in finalPaths with all paths that can lead to unit
        // No "actual" analysis is performed yet, just paths extraction
        Map<Unit, List<UnitPath>> unitSum = null;
        while (!workUnits.isEmpty()) {
            if(Thread.currentThread().isInterrupted()) {
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

        // finalPaths contain all possible paths in the function
        // each element of finalPaths is a possible path in the function based on CFG
        // each path is in reverse
        List<UnitPath> intraUnitPaths = new ArrayList<UnitPath>();

        for (List<Unit> currPath : finalPaths) { // analyzed fully-determined relevant program paths
            if(Thread.currentThread().isInterrupted()) {
                // time is up
                return false;
            }
            //this.pathsAnalyzedCount++;
            Set<String> currPathCond = new LinkedHashSet<String>();
            Set<String> currDecls = new LinkedHashSet<String>();

            // perform intra-procedural analysis
            // updates currPathCond and currDecls
            Boolean isInterrupted = analyzeProgramPath(tabs, method, currPath, currPathCond, currDecls);
            if (isInterrupted) {
                return false;
            }

            // FIXME: Not sure whether it is ok.
//			pathAnalyses.updatePaths(icfg, startingUnit, currPath, currPathCond, method, currClassName, tabs);

            // current intraprocedural path
            UnitPath up = new UnitPath(currPathCond, currDecls, currPath);
            intraUnitPaths.add(up);

            // unitSum is a map of unit to list of unitpath that leads to it
            if (methodSummaries.containsKey(method)) {
                unitSum = methodSummaries.get(method);
            } else {
                unitSum = new ConcurrentHashMap<Unit, List<UnitPath>>();
            }

            List<UnitPath> unitPaths = null;
            if (unitSum.containsKey(startingUnit)) {
                // there are paths found previously for startingUnit
                unitPaths = unitSum.get(startingUnit);
            } else {
                // first path found for startingUnit
                unitPaths = new ArrayList<UnitPath>();
            }
            unitPaths.add(up);
            unitSum.put(startingUnit, unitPaths);
            methodSummaries.put(method, unitSum);
        }
        // analysis of method is done


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
        // perform interprocedural analysis
        // find inter-function intent
        List<UnitPath> invokedUnitPaths = new ArrayList<UnitPath>();
        Map<List<Unit>, Set<UnitPath>> sumUnitPathMap = new ConcurrentHashMap<List<Unit>, Set<UnitPath>>();
        if (analysisMode == 0) {  // inter-procedural
            for (List<Unit> currIntraPath : finalPaths) { // analyzed fully-determined relevant program paths
                if(Thread.currentThread().isInterrupted()) {
                    // time is up
                    return false;
                }
                // establish dependencies with callees in currIntraPath
                //this.pathsAnalyzedCount++;
                List<Unit> currPathAsList = new ArrayList<Unit>(currIntraPath);

                Stack<Set<String>> workDecls = new Stack<Set<String>>();
                Stack<Set<String>> workPathConds = new Stack<Set<String>>();
                Stack<Integer> workUnitsIdx = new Stack<Integer>();
                Set<List<Unit>> discoveredPaths = new LinkedHashSet<List<Unit>>();
                Stack<List<Unit>> workSumPaths = new Stack<List<Unit>>();

                workDecls.add(new LinkedHashSet<String>());
                workPathConds.add(new LinkedHashSet<String>());
                workUnitsIdx.add(0); // updated by updateInterWorkStacks()
                workSumPaths.add(new ArrayList<Unit>());

                Set<String> currPathCond = new LinkedHashSet<String>();
                Set<String> currDecls = new LinkedHashSet<String>();
                List<Unit> currSumPath = new ArrayList<Unit>();

                while (!workPathConds.isEmpty()) {
                    currPathCond = workPathConds.pop();  // inter-procedural path conditions
                    currDecls = workDecls.pop();  // inter-procedural declarations
                    int currUnitIdx = workUnitsIdx.pop(); // updated in updateInterWorkStacks()
                    currSumPath = workSumPaths.pop();  // inter-procedural path
                    if(Thread.currentThread().isInterrupted()) {
                        // time is up
                        return false;
                    }
                    if (currUnitIdx >= currPathAsList.size()) {
                        // reached the end of current intraprocedural path
                        // end while loop
                        logger.debug("Final inter-procedural declarations:");
                        logger.debug(Joiner.on("\n").join(currDecls));

                        logger.debug("Final inter-procedural path conditions:");
                        logger.debug(Joiner.on("\n").join(currPathCond));

                        logger.debug("For path:");
                        logger.debug(Joiner.on("\n").join(currSumPath));
                        logger.debug("");

                        Set<UnitPath> sumUnitPaths = null;
                        if (sumUnitPathMap.containsKey(currIntraPath)) {
                            sumUnitPaths = sumUnitPathMap.get(currIntraPath);
                        } else {
                            sumUnitPaths = new LinkedHashSet<UnitPath>();
                        }
                        // create UnitPath corresponding to the inter-procedural path
                        UnitPath up = new UnitPath(currPathCond, currDecls, currSumPath);
                        sumUnitPaths.add(up);
                        // to preserve context-sensitivity on a path-sensitive basis
                        // add inter-procedural dependencies to current intra-procedural path
                        sumUnitPathMap.put(currIntraPath, sumUnitPaths);

                        continue;
                    }

                    Unit currUnitInPath = currPathAsList.get(currUnitIdx); // current unit under analysis for current summarized path
                    try {
                        Stmt currStmtInPath = (Stmt) currUnitInPath;
                        // Perform interprocedural analysis on intent
                        if (currStmtInPath.containsInvokeExpr()) {
                            // Add all z3 expressions from summarized method
                            InvokeExpr ie = currStmtInPath.getInvokeExpr();
                            if (methodSummaries.containsKey(ie.getMethod())) {
                                // there is interprocedural constraints!!
                                Map<Unit, List<UnitPath>> unitMap = methodSummaries.get(ie.getMethod());
                                // will only loop once since only the return statement is analyzed
                                // unless the method has multiple return statements
                                for (Map.Entry<Unit, List<UnitPath>> e : unitMap.entrySet()) {
                                    if(Thread.currentThread().isInterrupted()) {
                                        // time is up
                                        return false;
                                    }
                                    Unit sumUnit = e.getKey();
                                    logger.debug("Adding summarized z3 expressions for unit " + sumUnit + " of method " + ie.getMethod());
                                    List<UnitPath> unitPaths = e.getValue();
                                    List<Set<String>> conds = unitPaths.stream().map(p -> p.getPathCond()).collect(Collectors.toList());
                                    List<Set<String>> decls = unitPaths.stream().map(p -> p.getDecl()).collect(Collectors.toList());
                                    List<List<Unit>> paths = unitPaths.stream().map(p -> p.getPath()).collect(Collectors.toList());

                                    // unitPaths are interprocedural
                                    // each unit in unitMap has multiple paths that can reach it
                                    // along each path of the callee
                                    for (int exprIdx = 0; exprIdx < conds.size(); exprIdx++) {
                                        if(Thread.currentThread().isInterrupted()) {
                                            // time is up
                                            return false;
                                        }
                                        Set<String> cond = conds.get(exprIdx);
                                        Set<String> decl = decls.get(exprIdx);
                                        List<Unit> path = paths.get(exprIdx);
                                        if (discoveredPaths.contains(path)) {
                                            continue;
                                        }

                                        // join the set of strings into one string separated from each other with a newline
                                        String condsCombined = cond.stream().map(d -> d.trim()).reduce("", (a, b) -> a + "\n" + b).trim();

                                        Set<String> newAsserts = new LinkedHashSet<String>();
                                        if (condsCombined.contains("fromIntent")) {
                                            // identify same intent name in callee
                                            generateIntentExprForSumMethod(method, defs, currIntraPath, currUnitInPath, ie, condsCombined, newAsserts);
                                        }

                                        if (!newAsserts.isEmpty()) {
                                            // new interprocedural constraints!
                                            discoveredPaths.add(path);
                                            Set<String> newDecls = new LinkedHashSet<String>(currDecls);
                                            newDecls.addAll(decl);
                                            Set<String> newPathCond = new LinkedHashSet<String>(currPathCond);
                                            newPathCond.addAll(cond);
                                            newPathCond.addAll(newAsserts); // establish same intent under different names
                                            // add new information
                                            // perform MFP
                                            // Meet operator is set union
                                            // update workDecls, workPathConds, and workSumPaths with new constraints from callee
                                            // workUnitsIdx++
                                            updateInterWorkStacks(workDecls, workPathConds, workUnitsIdx, workSumPaths, newPathCond, newDecls, path, currUnitIdx);
                                        } else {
                                            // no interprocedural constraints
                                            // invoke statement with method in methodSummaries but no new information
                                            // intent used in current method is not passed to callee as argument
                                            // workUnitsIdx++
                                            updateInterWorkStacks(workDecls, workPathConds, workUnitsIdx, workSumPaths, currPathCond, currDecls, currSumPath, currUnitIdx);
                                        }
                                    }
                                }
                            } else {
                                // no interprocedural constraints
                                // invoke statement but not a function in methodSummaries
                                // workUnitsIdx++
                                updateInterWorkStacks(workDecls, workPathConds, workUnitsIdx, workSumPaths, currPathCond, currDecls, currSumPath, currUnitIdx);
                            }
                        } else {
                            // no interprocedural constraints
                            // not an invoke statement
                            // workUnitsIdx++
                            updateInterWorkStacks(workDecls, workPathConds, workUnitsIdx, workSumPaths, currPathCond, currDecls, currSumPath, currUnitIdx);
                        }
                    } catch (NullPointerException e) {
                        e.printStackTrace();
                    }
                }

                UnitPath up = new UnitPath(currPathCond, currDecls, currIntraPath);
                invokedUnitPaths.add(up);
            }
        }

        // running the solver
        List<List<Unit>> finalPathsList = new ArrayList<List<Unit>>(finalPaths);
        for (int fpIdx = 0; fpIdx < finalPathsList.size(); fpIdx++) { // analyzed fully-determined relevant program paths
            if(Thread.currentThread().isInterrupted()) {
                // time is up
                return false;
            }
            List<Unit> currPath = finalPathsList.get(fpIdx);
            UnitPath intraUnitPath = intraUnitPaths.get(fpIdx);  // the constraints corresponding to currPath
            //this.pathsAnalyzedCount++;
            Set<String> currPathCond = intraUnitPath.getPathCond();
            Set<String> currDecls = intraUnitPath.getDecl();

            Set<UnitPath> sumUnitPaths = null;
            if (sumUnitPathMap.containsKey(currPath)) {
                // contain constraints with different levels of interprocedural constraints
                // if you can solve the most precise one, perfect
                // if not, the less precise one is fine too
                sumUnitPaths = sumUnitPathMap.get(currPath);
            }

            if (sumUnitPaths != null) {
                int sumUpIdx = 0;
                boolean sumIsFeasible = false;
                for (UnitPath sumUp : sumUnitPaths) {
                    if(Thread.currentThread().isInterrupted()) {
                        // time is up
                        return false;
                    }
                    logger.debug("Running solving phase on intER-procedural path " + sumUpIdx + " of " + (sumUnitPaths.size() - 1) + " for intra-procedural path " + fpIdx);
                    Set<String> interPathCond = new LinkedHashSet<String>(currPathCond);
                    interPathCond.addAll(sumUp.getPathCond());
                    Set<String> interDecls = new LinkedHashSet<String>(currDecls);
                    interDecls.addAll(sumUp.getDecl());
                    // inter-procedural paths are added to the end of the intra-procedural path, not where the methods are called
                    List<Unit> interPath = new ArrayList<Unit>(currPath);
                    interPath.addAll(sumUp.getPath());
                    // adding extra argument (sumUpIdx) to runSolvingPhase so filename is unique
                    // runSolvingPhase will update methodSummaries with interprocedural dependencies
                    boolean intraFeasible = runSolvingPhase(tabs, sumUpIdx, method, currClassName, startingUnit, pathAnalyses, interPath, interPathCond, interDecls, analysisMode);
                    if (intraFeasible) {
                        sumIsFeasible = true;
                    }
                    sumUpIdx++;
                }
                if (sumIsFeasible) {
                    isFeasible = true;
                }
            } else {
                logger.debug("Running solving phase on intRA-procedural path");
                isFeasible = runSolvingPhase(tabs, 0, method, currClassName, startingUnit, pathAnalyses, currPath, currPathCond, currDecls, analysisMode);
            }

        }

        if (!isFeasible) {
            infeasibleTargets.add(new Pair<Unit, SootMethod>(startingUnit, method));
        }
        return isFeasible;

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
                String returnExpr = buildZ3CondExpr(tabs, opExpr1, Integer.toString(val), "==", null);
                currPathCond.add(returnExpr);
                return;
            }
            index += 1;
        }
        // default value
        for (Integer curSeen : seen) {
            String returnExpr = buildZ3CondExpr(tabs, opExpr1, Integer.toString(curSeen), "!=", null);
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

    protected boolean runSolvingPhase(int tabs, int sumUpIdx, SootMethod method, String currClassName, Unit startingUnit, PathAnalysis pathAnalyses, List<Unit> currPath, Set<String> interPathCond, Set<String> interDecls, Integer analysisMode) {
		/*
		if(!isIntra){
			pathAnalyses.updatePaths(icfg, startingUnit, currPath, interPathCond, method, currClassName, tabs);  // pathAnalyses unused?
			                                                                                                     // for debugging
		}
		 */
        //logCurrentSpecToSolve(interPathCond, interDecls);
        storeSummary(method, startingUnit, currPath, interPathCond, interDecls);
        this.pathsAnalyzedCount++;
        Pair<Intent, Boolean> soln = findSolutionForPath(sumUpIdx, interPathCond, method, interDecls, currPath, startingUnit, analysisMode);
        boolean feasible = soln.getValue1();
        Intent genIntent = soln.getValue0();

        if (feasible) {
            storeGeneratedData(currClassName, genIntent);
        }
        return feasible;
    }

    protected void logCurrentSpecToSolve(Set<String> interPathCond, Set<String> interDecls) {
        logger.debug("Current z3 specification to solve:");
        for (String decl : interDecls) {
            logger.debug(decl);
        }
        for (String expr : interPathCond) {
            logger.debug(expr);
        }
    }

    /**
     * add interprocedural constraints to methodSummaries
     */
    protected void storeSummary(SootMethod method,
                                Unit startingUnit,
                                List<Unit> currPath,
                                Set<String> interPathCond,
                                Set<String> interDecls) {
        Map<Unit, List<UnitPath>> unitSum;
        if (methodSummaries.containsKey(method)) {
            unitSum = methodSummaries.get(method);
        } else {
            unitSum = new ConcurrentHashMap<Unit, List<UnitPath>>();
        }

        List<UnitPath> unitPaths = null;
        if (unitSum.containsKey(startingUnit)) {
            unitPaths = unitSum.get(startingUnit);
        } else {
            unitPaths = new ArrayList<UnitPath>();
        }
        UnitPath up = new UnitPath(interPathCond, interDecls, currPath);
        unitPaths.add(up);
        unitSum.put(startingUnit, unitPaths);
        methodSummaries.put(method, unitSum);
    }

    protected synchronized void storeGeneratedData(String currClassName, Intent genIntent) {
        try {
            logger.debug("Storing generated data...");

            if (!wasPreviouslyWrittenIntentData(currClassName, genIntent)) {
                storeGeneratedDataToWriter(currClassName, genIntent);
            }

        } catch (RuntimeException e) {
            // will throw Exception for int extra intent
            logger.warn("caught exception", e);
        }
    }

    private Boolean analyzeProgramPath(int tabs, SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls) {
        // will fill in currPathCond and currDecls
        List<Unit> currPathAsList = new ArrayList<Unit>(currPath);
        for (int i = 0; i < currPathAsList.size(); i++) {
            if(Thread.currentThread().isInterrupted()) {
                // time is up
                return true;
            }
            // iterating each instruction in path currPath
            Unit currUnitInPath = currPathAsList.get(i); // current unit under analysis for current path
            Unit succUnit = null; // successor of currUnitINPath
            if (i - 1 < currPathAsList.size() && i >= 1) {
                succUnit = currPathAsList.get(i - 1);
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
                if (currUnitInPath instanceof IfStmt) {
                    // newExprs are z3 path constraints
                    Set<String> newExprs = handleIfStmt(tabs, (IfStmt) currUnitInPath, succUnit, method, defs, currDecls, currPath);
                    if (newExprs != null) {
                        currExprs.addAll(newExprs);
                    }
                }

                // check if current unit follows from a switch case
                if ((i + 1 < currPathAsList.size()) && (currPathAsList.get(i + 1) instanceof JLookupSwitchStmt)) {
                    JLookupSwitchStmt switchCase = (JLookupSwitchStmt) currPathAsList.get(i + 1);
                    // can update currDecls (new variables) and currPathCond (new constraints)
                    // current unit follows a switch case
                    handleSwitchStmt(tabs, currUnitInPath, switchCase, currPathCond, currDecls, currPath, method, defs);
                }

                if (currStmtInPath.containsInvokeExpr() && currStmtInPath instanceof DefinitionStmt) {
                    handleGetUriOfIntent(method, currPath, currPathCond, currDecls, defs, currStmtInPath);
                    handleGetActionOfIntent(method, currPath, currPathCond, currDecls, defs, currStmtInPath);
                    handleGetExtraOfIntent(method, currPath, currPathCond, currDecls, defs, (DefinitionStmt) currStmtInPath);
                }

                if (currExprs == null) {
                    logger.warn("Not including condition for " + currUnitInPath + " to path constraint");
                } else {
                    //synchronized(method) {
                    currPathCond.addAll(currExprs);
                    //}
                }
            } catch (NullPointerException e) {
                e.printStackTrace();
            }
        }
        return false;
    }

    private void handleGetExtraOfIntent(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls, SimpleLocalDefs defs, DefinitionStmt currStmtInPath) {
        DefinitionStmt defStmt = currStmtInPath;
        if (defStmt.containsInvokeExpr() && defStmt.getInvokeExpr() instanceof InstanceInvokeExpr) {
            InstanceInvokeExpr ie = (InstanceInvokeExpr) defStmt.getInvokeExpr();
            if (Pattern.matches("get.*Extra", ie.getMethod().getName())) {
                if (ie.getMethod().getDeclaringClass().toString().equals("android.content.Intent")) {
                    Pair<Set<String>, Set<String>> exprPair = buildGetExtraData(defStmt, defs, ie, method, currPath);
                    currDecls.addAll(exprPair.getValue0());
                    currPathCond.addAll(exprPair.getValue1());
                }
            }
            if (Pattern.matches("get.*", ie.getMethod().getName())) {
                if (ie.getMethod().getDeclaringClass().toString().equals("android.os.Bundle")) {
                    Pair<Set<String>, Set<String>> exprPair = buildGetBundleData(defStmt, defs, ie, method, currPath);
                    currDecls.addAll(exprPair.getValue0());
                    currPathCond.addAll(exprPair.getValue1());
                } else if (ie.getMethod().getDeclaringClass().toString().equals("android.os.BaseBundle")) {
                    Pair<Set<String>, Set<String>> exprPair = buildGetBundleData(defStmt, defs, ie, method, currPath);
                    currDecls.addAll(exprPair.getValue0());
                    currPathCond.addAll(exprPair.getValue1());
                } else if (ie.getMethod().getDeclaringClass().toString().equals("android.os.PersistableBundle")) {
                    Pair<Set<String>, Set<String>> exprPair = buildGetBundleData(defStmt, defs, ie, method, currPath);
                    currDecls.addAll(exprPair.getValue0());
                    currPathCond.addAll(exprPair.getValue1());
                }
            }
        }
    }

    private void handleGetUriOfIntent(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls, SimpleLocalDefs defs, Stmt currStmtInPath) {
        DefinitionStmt currDefStmt = (DefinitionStmt) currStmtInPath;
        InvokeExpr ie = currStmtInPath.getInvokeExpr();
        if (ie.getMethod().getName().equals("getData")) {
            if (ie.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                logger.debug("Perform path sensitive analysis for URI");
                if (ie instanceof InstanceInvokeExpr) {
                    InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
                    String uriRefSymbol = null;
                    if (currDefStmt.getLeftOp() instanceof Local) {
                        Local leftLocal = (Local) currDefStmt.getLeftOp();
                        uriRefSymbol = createSymbol(currDefStmt.getLeftOp(), method, currStmtInPath);
                        //symbolLocalMap.put(actionRefSymbol,leftLocal);
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
                                    //String getActionSymbol = createSymbol(leftLocal, method, intentDef);
                                    //symbolLocalMap.put(getActionSymbol, intentLocal);
                                    String intentSymbol = createSymbol(intentLocal, method, intentDef);
                                    //symbolLocalMap.put(intentSymbol, intentLocal);
                                    String intentDecl = "(declare-const " + intentSymbol + " Object )";
                                    String actionRefDecl = "(declare-const " + uriRefSymbol + " Object )";
                                    //String getActionDecl = "(declare-const " + actionRefSymbol + " String )";
                                    currDecls.add(intentDecl);
                                    currDecls.add(actionRefDecl);
                                    //currDecls.add(getActionDecl);
                                    String getUriAssert2 = "(assert (= (getUri " + intentSymbol + ") " + uriRefSymbol + "))";
                                    String newFromIntent = "(assert (= (fromIntent " + uriRefSymbol + ") " + intentSymbol + "))";
                                    currPathCond.add(getUriAssert2);
                                    currPathCond.add(newFromIntent);

                                    //addIntentActionForPath(currPath, actionRefSymbol);

                                    //buildParamRefExpressions(method, currPath, currPathCond, currDecls, intentDef, intentSymbol);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private void handleGetActionOfIntent(SootMethod method, List<Unit> currPath, Set<String> currPathCond, Set<String> currDecls, SimpleLocalDefs defs, Stmt currStmtInPath) {
        DefinitionStmt currDefStmt = (DefinitionStmt) currStmtInPath;
        InvokeExpr ie = currStmtInPath.getInvokeExpr();
        if (ie.getMethod().getName().equals("getAction")) {
            if (ie.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                logger.debug("Perform path sensitive analysis for getAction");
                if (ie instanceof InstanceInvokeExpr) {
                    InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
                    String actionRefSymbol = null;
                    if (currDefStmt.getLeftOp() instanceof Local) {
                        Local leftLocal = (Local) currDefStmt.getLeftOp();
                        actionRefSymbol = createSymbol(currDefStmt.getLeftOp(), method, currStmtInPath);
                        //symbolLocalMap.put(actionRefSymbol,leftLocal);
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
                                    //String getActionSymbol = createSymbol(leftLocal, method, intentDef);
                                    //symbolLocalMap.put(getActionSymbol, intentLocal);
                                    String intentSymbol = createSymbol(intentLocal, method, intentDef);
                                    //symbolLocalMap.put(intentSymbol, intentLocal);
                                    String intentDecl = "(declare-const " + intentSymbol + " Object )";
                                    String actionRefDecl = "(declare-const " + actionRefSymbol + " String )";
                                    //String getActionDecl = "(declare-const " + actionRefSymbol + " String )";
                                    currDecls.add(intentDecl);
                                    currDecls.add(actionRefDecl);
                                    //currDecls.add(getActionDecl);
                                    String getActionAssert = "(assert (= (getAction " + intentSymbol + ") " + actionRefSymbol + "))";
                                    String newFromIntent = "(assert (= (fromIntent " + actionRefSymbol + ") " + intentSymbol + "))";
                                    currPathCond.add(getActionAssert);
                                    currPathCond.add(newFromIntent);

                                    //addIntentActionForPath(currPath, actionRefSymbol);

                                    buildParamRefExpressions(method, currPath, currPathCond, currDecls, intentDef, intentSymbol);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private void addIntentActionForPath(List<Unit> currPath, String actionRefSymbol) {
        Intent currIntent = getIntentForPath(currPath);
        currIntent.action = actionRefSymbol;
        pathIntents.put(currPath, currIntent);
    }

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

    private Pair<Set<String>, Set<String>> buildGetExtraData(Unit currUnit, SimpleLocalDefs defs, InstanceInvokeExpr ie, SootMethod method, List<Unit> currPath) {
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
                            symbolLocalMap.put(extraLocalSymbol, extraLocal);
                            String intentSymbol = createSymbol(intentLocal, method, intentDef);
                            symbolLocalMap.put(intentSymbol, intentLocal);
                            String newExtraType = getZ3Type(extraLocal.getType());
                            String newIntentType = getZ3Type(intentLocal.getType());
                            newDecls.add("(declare-const " + extraLocalSymbol + " " + newExtraType + " )");
                            newDecls.add("(declare-const " + intentSymbol + " " + newIntentType + " )");
                            newAsserts.add("(assert (= (containsKey " + extraLocalSymbol + " \"" + keyStrConst.value + "\") true))");
                            newAsserts.add("(assert (= (fromIntent " + extraLocalSymbol + ") " + intentSymbol + "))");

                            //addIntentExtraForPath(currPath, keyStrConst.value, newExtraType);


                            buildParamRefExpressions(method, currPath, newAsserts, newDecls, intentDef, intentSymbol);
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

    private void addIntentExtraForPath(List<Unit> currPath, String extraLocalSymbol, String newExtraType) {
        Intent currIntent = getIntentForPath(currPath);
        Triplet<String, String, String> extra = new Triplet<String, String, String>(newExtraType, extraLocalSymbol, "");
        currIntent.extras.add(extra);
        pathIntents.put(currPath, currIntent);
    }

    private void addIntentCategoryForPath(List<Unit> currPath, String category) {
        Intent currIntent = getIntentForPath(currPath);
        currIntent.categories.add(category);
        pathIntents.put(currPath, currIntent);
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

    private Pair<Set<String>, Set<String>> buildGetBundleData(Unit currUnit, SimpleLocalDefs defs, InstanceInvokeExpr ie, SootMethod method, List<Unit> currPath) {
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
                                                symbolLocalMap.put(extraLocalSymbol, extraLocal);
                                                String intentSymbol = createSymbol(intentLocal, method, intentDef);
                                                symbolLocalMap.put(intentSymbol, intentLocal);
                                                String newExtraType = getZ3Type(extraLocal.getType());
                                                String newIntentType = getZ3Type(intentLocal.getType());
                                                newDecls.add("(declare-const " + extraLocalSymbol + " " + newExtraType + " )");
                                                newDecls.add("(declare-const " + intentSymbol + " " + newIntentType + " )");
                                                newAsserts.add("(assert (= (containsKey " + extraLocalSymbol + " \"" + keyStrConst.value + "\") true))");
                                                newAsserts.add("(assert (= (fromIntent " + extraLocalSymbol + ") " + intentSymbol + "))");

                                                //addIntentExtraForPath(currPath, keyStrConst.value, newExtraType);

                                                buildParamRefExpressions(method, currPath, newAsserts, newDecls, intentDef, intentSymbol);
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
            logger.error("Unsupported component type: " + comp);
            logger.error("Won't write new intent command files for this component");
            return;
        }
        try {
            logger.debug("<<< writeIntentCmdsForDrozer");
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

    private Triplet<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>, String> findStringValuesOfBoolType(SootMethod method, SimpleLocalDefs defs, Unit inUnit, Value value, List<Unit> currPath) {
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
                    logger.debug("Found potential string equal comparison statement: " + pseUnit);
                    if (pseUnit instanceof DefinitionStmt) {
                        DefinitionStmt defStmt = (DefinitionStmt) pseUnit;
                        if (defStmt.getRightOp() instanceof JVirtualInvokeExpr) {
                            JVirtualInvokeExpr jviExpr = (JVirtualInvokeExpr) defStmt.getRightOp();
                            if (jviExpr.getMethod().getDeclaringClass().getName().equals("java.lang.String")) {
                                if (jviExpr.getMethod().getName().equals("equals")) {
                                    logger.debug("Identified actual string equals comparison statement");
                                    leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath);
                                    rightVal = findOriginalVal(method, defs, pseUnit, jviExpr.getArg(0), currPath);
                                } else if (jviExpr.getMethod().getName().equals("startsWith")) {
                                    leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath);
                                    rightVal = findOriginalVal(method, defs, pseUnit, jviExpr.getArg(0), currPath);
                                    strOp = "startsWith";
                                } else if (jviExpr.getMethod().getName().equals("endsWith")) {
                                    leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath);
                                    rightVal = findOriginalVal(method, defs, pseUnit, jviExpr.getArg(0), currPath);
                                    strOp = "endsWith";
                                } else if (jviExpr.getMethod().getName().equals("contains")) {
                                    leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath);
                                    rightVal = findOriginalVal(method, defs, pseUnit, jviExpr.getArg(0), currPath);
                                    strOp = "contains";
                                } else if (jviExpr.getMethod().getName().equals("isEmpty")) {
                                    leftVal = findOriginalVal(method, defs, pseUnit, jviExpr.getBase(), currPath);
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
                                                            logger.debug("Found hasExtra invocation");
                                                            leftVal = findOriginalVal(method, defs, defUnit2, jInvokeExpr2.getBase(), currPath);
                                                            rightVal = findOriginalVal(method, defs, defUnit2, jInvokeExpr2.getArg(0), currPath);

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
        return new Triplet<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>, String>(leftVal, rightVal, strOp);
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

    public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit unit) {
        if (unit instanceof InvokeStmt) {
            InvokeStmt stmt = (InvokeStmt) unit;
            if (stmt.getInvokeExpr().getMethod().getName().equals("d")) {
                return true;
            }
        }
        return false;
    }

    public synchronized Pair<Intent,Boolean> findSolutionForPath(Integer sumUpIdx,
                                                                 Set<String> currPathCond,
                                                                 SootMethod method,
                                                                 Set<String> decls,
                                                                 List<Unit> currPath,
                                                                 Unit startingUnit,
                                                                 Integer analysisMode) {
        Set<Triplet<String,String,String>> extraData = new LinkedHashSet<Triplet<String,String,String>>();
        String action = null;
        String uri = null;
        Set<String> categories = new LinkedHashSet<String>();
        boolean isPathFeasible = false;

        try {
            Pair<Map<String, String>,Boolean> ret = returnSatisfyingModel(sumUpIdx, decls, currPathCond, startingUnit, method, analysisMode);
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
                        logger.info("uri symbol: " + uriStrSymbol);

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

                Set<String> nullExtraKeys = new HashSet<>();
                for (String expr : currPathCond) {
                    Pattern p = Pattern.compile("\\(assert \\(= \\(isNull (.+)\\) true\\)\\)");
                    Matcher m = p.matcher(expr);
                    while (m.find()) {
                        String extraNullSymbol = m.group(1);
                        logger.info("Found extra null check: " + extraNullSymbol);
                        nullExtraKeys.add(extraNullSymbol);
                    }
                }
                for (String expr : currPathCond) {
                    Pattern p = Pattern.compile("\\(assert \\(= \\(isNull (.+)\\) true\\)\\)");
                    Matcher m = p.matcher(expr);
                    while (m.find()) {
                        String extraNullSymbol = m.group(1);
                        logger.info("Found extra null check: " + extraNullSymbol);
                        nullExtraKeys.add(extraNullSymbol);
                    }
                }

                for (Map.Entry<String,String> entry : model.entrySet()) {
                    String symbol = entry.getKey();
                    String generatedValue = entry.getValue();
                    logger.debug(symbol + ": " + generatedValue);

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

/*
		if (uri == null) {
			genIntent.uri = "Null";
		} else {
			genIntent.uri = uri;
		}
 */

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
        if (generatedValue.equals("Null")) {
            // to reach this path, this extra datum cannot exist
            return null;
        }
        Triplet<String, String, String> extraDatum = null;

        Local local = symbolLocalMap.get(symbol);
        String key = extraLocalKeys.get(symbol);

        if (local != null && key != null) {
            logger.debug(symbol.toString() + "'s key: " + key);
            if (!generatedValue.equals("NotNull")) {
                // extra datum value has a particular value it needs to be set to
                extraDatum = new Triplet<String, String, String>(local.getType().toString(), key, generatedValue.toString().replaceAll("^\"|\"$", ""));
            } else {
                // extra datum value just has to exist
                // create "random" extra datum value for the extra datum  type
                String newGen;
                switch (local.getType().toString().trim()) {
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
                extraDatum = new Triplet<String, String, String>(local.getType().toString(), key, newGen);
            }
        }
        else {
            extraDatum = null;
        }
        return extraDatum;
    }

    public synchronized Pair<Map<String,String>,Boolean> returnSatisfyingModel(Integer sumUpIdx, Set<String> decls, Set<String> pathCond, Unit startingUnit, SootMethod method, Integer analysisMode) throws Z3Exception {
        return returnSatisfyingModelForZ3(sumUpIdx, decls, pathCond, startingUnit, method, analysisMode);
    }

    public synchronized Pair<Map<String,String>,Boolean> returnSatisfyingModelForZ3(Integer sumUpIdx, Set<String> decls, Set<String> pathCond, Unit startingUnit, SootMethod method, Integer analysisMode) throws Z3Exception {
        String pathCondFileName = null;
        try {
            if (reducedFlag && parallelEnabled) {
                pathCondFileName = Z3_RUNTIME_SPECS_DIR + File.separator + method.getDeclaringClass().getName() + "_" + startingUnit.getJavaSourceStartLineNumber() + "_z3_path_cond_F_" + sumUpIdx.toString();
            } else if (reducedFlag) {
                pathCondFileName = Z3_RUNTIME_SPECS_DIR + File.separator + method.getDeclaringClass().getName() + "_" + startingUnit.getJavaSourceStartLineNumber() + "_z3_path_cond_R_" + sumUpIdx.toString();
            } else if (analysisMode == 1) {  // intra-procedural
                pathCondFileName = Z3_RUNTIME_SPECS_DIR + File.separator + method.getDeclaringClass().getName() + "_" + startingUnit.getJavaSourceStartLineNumber() + "_z3_path_cond_I_" + sumUpIdx.toString();
            } else if (analysisMode == 2) {  // intra-procedural v2
                pathCondFileName = Z3_RUNTIME_SPECS_DIR + File.separator + method.getDeclaringClass().getName() + "_" + startingUnit.getJavaSourceStartLineNumber() + "_z3_path_cond_K_" + sumUpIdx.toString();
            } else {
                pathCondFileName = Z3_RUNTIME_SPECS_DIR + File.separator + method.getDeclaringClass().getName() + "_" + startingUnit.getJavaSourceStartLineNumber() + "_z3_path_cond_P_" + sumUpIdx.toString();
            }
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
            //timeout - kill the process.
            p.destroy(); // consider using destroyForcibly instead
            Boolean isSat = false;
            Map<String,String> model = new ConcurrentHashMap<String,String>();
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

        Boolean isSpecialStrOp = false;  // ex: .startsWith

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
            Triplet<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>, String> condValuesPair = findStringValuesOfBoolType(method, defs, currIfStmt, opVal1, currPath);
            Quartet<Value, String, String, Unit> left = condValuesPair.getValue0();
            Quartet<Value, String, String, Unit> right = condValuesPair.getValue1();
            String strOp = condValuesPair.getValue2();

            if (left == null) {
                Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> valuesPair = findBundleValues(method, defs, currIfStmt, opVal1, currPath);
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
                        String opExpr1 = createZ3Expr(opVal1, currIfStmt, opVal1DefUnit, method, decls, tabs);
                        //String opExpr2 = "(str.substr " + opExpr1 + " 0 "+ opVal2Const.value.length() +")";
                        //String opExpr2 = "(str.prefixof \"" + opVal2Const.value + "\" " + opExpr1 + ")";
                        //String condExpr = "(assert (= \"" + opVal2Const.value + "\" " + opExpr2 + "))";
                        String condExpr = buildZ3CondExpr(tabs, "\""+opVal2Const.value+"\"", opExpr1, getBranch(currIfStmt, succUnit, opVal1Org, condition), "str.prefixof");
                        opVal1Assert = condExpr;
                        isSpecialStrOp = true;
                    } else if (strOp != null && strOp.equals("endsWith") && opVal2 instanceof StringConstant) {
                        StringConstant opVal2Const = (StringConstant) opVal2;
                        String opExpr1 = createZ3Expr(opVal1, currIfStmt, opVal1DefUnit, method, decls, tabs);
                        String condExpr = buildZ3CondExpr(tabs, "\""+opVal2Const.value+"\"", opExpr1, getBranch(currIfStmt, succUnit, opVal1Org, condition), "str.suffixof");
                        opVal1Assert = condExpr;
                        isSpecialStrOp = true;
                    } else if (strOp != null && strOp.equals("contains") && opVal2 instanceof StringConstant) {
                        StringConstant opVal2Const = (StringConstant) opVal2;
                        String opExpr1 = createZ3Expr(opVal1, currIfStmt, opVal1DefUnit, method, decls, tabs);
                        String condExpr = buildZ3CondExpr(tabs, opExpr1, "\""+opVal2Const.value+"\"", getBranch(currIfStmt, succUnit, opVal1Org, condition), "str.contains");
                        opVal1Assert = condExpr;
                        isSpecialStrOp = true;
                    }
                }
            }

            if (left == null && right == null) {
                Pair<Quartet<Value, String, String, Unit>, Quartet<Value, String, String, Unit>> valuesPair = findCategories(method, defs, currIfStmt, opVal1, currPath);
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
            logger.debug("else branch, simply invoking findKeysForLeftAndRightValues(...)");
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

		/*
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
		 */

        if (opVal1Assert != null) {
            if (opVal1Assert.contains("select keys index") && opVal2Assert == null) { // handling a hasExtra statement, so do not create additional expressions
                generateCondExpr = false;
            }
        }

        // get z3 constraints
        if (generateCondExpr && !isSpecialStrOp) {
            // generatedCondExpr is initially set to true
            // at different points, can be set to false
            returnExpr = buildZ3CondExpr(tabs, opExpr1, opExpr2, getBranch(currIfStmt, succUnit, opVal1Org, condition), null);
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

    private String buildZ3CondExpr(int tabs, String opExpr1, String opExpr2, String branchSensitiveSymbol, String z3func) {
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