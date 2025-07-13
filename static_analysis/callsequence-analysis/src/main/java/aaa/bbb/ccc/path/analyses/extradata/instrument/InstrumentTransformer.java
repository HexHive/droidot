package aaa.bbb.ccc.path.analyses.extradata.instrument;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Array;
import java.util.*;
import java.util.regex.Pattern;

import com.google.common.base.Joiner;
import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.path.analyses.Globals;
import aaa.bbb.ccc.path.analyses.extradata.ExtraDataUseTransformerSp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.extradata.ExtraDataUseTransformer;
import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.options.Options;
import soot.tagkit.BytecodeOffsetTag;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;

import static aaa.bbb.ccc.path.analyses.extradata.ExtraDataUseTransformerSp.isBundleFromIntent;
import static soot.SootClass.SIGNATURES;

/*
 * This class allows you to instrument the apk
 */
public class InstrumentTransformer extends SceneTransformer{

	Map<Unit,Boolean> doesUnitNeedAnalysisSummary = new LinkedHashMap<Unit,Boolean>();
	static Set<String> methodsToFilter = new HashSet<String>(Arrays.asList("onNewIntent"));
	static Logger logger = LoggerFactory.getLogger(InstrumentTransformer.class);
	protected int instrumentStatementCnt=0;
	protected int intentControlledStatementCnt=0;
	protected JimpleBasedInterproceduralCFG icfg;
	public Set<Unit> instrumentedUnitsSeen = new HashSet<>();

	public int getInstrumentStmtCount() {
		return instrumentStatementCnt;
	}

	public int getIntentControlledStatementCnt() {
		return intentControlledStatementCnt;
	}

	public InstrumentTransformer(String apkFilePath, String folderName) {
		G.reset();
		Config.apkFilePath = apkFilePath;
		Config.folderName = folderName;
		// TODO Auto-generated constructor stub
	}

	public InstrumentTransformer(String apkFilePath) {
		G.reset();
		Config.apkFilePath = apkFilePath;
		Config.folderName = null;
		// TODO Auto-generated constructor stub
	}

	public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit inUnit, Set<Unit> ifUnitsUsingIntents) {
        if (Utils.isAndroidMethod(method)) {
            return false;
        }
        if (method.getName().startsWith("access$")) {
            return false;
        }
        if (method.getName().startsWith("<init>")) {
            // constructor
            return false;
        }
        if (method.getName().startsWith("<clinit>")) {
            // static initializer
            return false;
        }

        if (doesUnitNeedAnalysisSummary.containsKey(inUnit)) {
            // previously has already computed whether unit `inUnit` needs analysis or not
            return doesUnitNeedAnalysisSummary.get(inUnit);
        }

		/*
		if (inUnit instanceof IfStmt) {
			// ignore if current unit is an if-condition
			doesUnitNeedAnalysisSummary.put(inUnit, false);
			return false;
		}
		 */

        BriefUnitGraph ug = new BriefUnitGraph(method.getActiveBody());
        SimpleLocalDefs localDefs = new SimpleLocalDefs(ug);
        for (Unit pred : ug.getPredsOf(inUnit)) {
            if (pred instanceof IfStmt) {
				if (!(isFallThrough(pred, inUnit) || isBranch(pred, inUnit))) {
					// pred is not an if-statement that directly control inUnit
					continue;
				}
                IfStmt predIfStmt = (IfStmt) pred;
                for (ValueBox useBox : predIfStmt.getUseBoxes()) {
                    if (useBox.getValue() instanceof Local) {
                        Local useLocal = (Local)useBox.getValue();
                        for (Unit defUnit : localDefs.getDefsOfAt(useLocal, predIfStmt)) {
                            // defUnit is the definition of useLocal at predIfStmt
                            Boolean defUnitUses = checkIfUnitUsesIntentPayload(defUnit,localDefs);
                            if (defUnitUses!=null) {
                                if (defUnitUses.booleanValue()) {
                                    // pred of unit is an if-statement that contains usage of intent payload
									// track if-stmt that passes unitNeedsAnalysis
									ifUnitsUsingIntents.add(pred);
									//doesUnitNeedAnalysisSummary.put(inUnit, true);
									//logger.debug("UNIT: " + inUnit.toString() + " at line " + String.valueOf(inUnit.getJavaSourceStartLineNumber()) + " of method " + method.getName() + " and class " +method.getDeclaringClass().getName() );
                                    return true;
                                }
                            }
                        }
                    }
                }
				// return value of getPredsOf is sorted by scope. First element is the outermost scope
                doesUnitNeedAnalysisSummary.put(inUnit, false);
                return false;
            }
       }

        doesUnitNeedAnalysisSummary.put(inUnit,false);
        return false;
	}
	private Boolean isIntentPayloadExtractionMethod(SimpleLocalDefs localDefs, Unit defUnit, InvokeExpr invokeExpr) {

		if (Pattern.matches("get.*Extra", invokeExpr.getMethod().getName())) {
			if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
				return true;
			}
		}
		if (Pattern.matches("hasExtra", invokeExpr.getMethod().getName())) {
			if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
				return true;
			}
		}
		if (Globals.bundleExtraDataMethodsSet.contains(invokeExpr.getMethod().getName())) {
			if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.os.Bundle")) {
				return isBundleFromIntent(localDefs, defUnit, invokeExpr);
			}
			if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.os.BaseBundle")) {
				return isBundleFromIntent(localDefs, defUnit, invokeExpr);
			}
		}
		if (Globals.categoryMethodsSet.contains(invokeExpr.getMethod().getName())) {
			if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
				return true;
			}
		}
		if (Pattern.matches("getAction", invokeExpr.getMethod().getName())) {
			if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
				return true;
			}
		}
		if (invokeExpr.getMethod().getName().equals("equals") && invokeExpr.getMethod().getDeclaringClass().getName().equals("java.lang.String")) {
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
							if (baseInvokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
								return true;
							}
						}
					}
				}
			}
		}
		return null;
	}

	private Boolean checkIfUnitUsesIntentPayload(Unit inUnit, SimpleLocalDefs localDefs) {
		Stmt inStmt = (Stmt)inUnit;
		if (inStmt.containsInvokeExpr()) {
			InvokeExpr ie = inStmt.getInvokeExpr();
			Boolean x = isIntentPayloadExtractionMethod(localDefs,inUnit,ie);
			if (x != null && x == true) {
				// current unit extracts intent payload
				return x;
			}
		}

		List<ValueBox> uses = inUnit.getUseBoxes();  // list of Boxes containing Values in unit `inUnit`
		for (ValueBox use : uses) {
			if (use.getValue() instanceof Local) {
				Local local = (Local)use.getValue();
				List<Unit> defUnits = localDefs.getDefsOfAt(local, inUnit);
				for (Unit defUnit : defUnits) {
					InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
					if (invokeExpr == null) {
						continue;
					}
					Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr);
					if (x != null && x == true)
						// current unit uses an intent payload
						return x;
				}
			}
		}
		return null;
	}

	public Boolean controlDepsIntentOnly(SootMethod method, BriefUnitGraph ug, Unit startingUnit, Set<Unit> ifUnitsUsingIntents) {
		// uses ifUnitsUsingIntents to identify fully intent-controlled path

		boolean isFeasible = false;
		boolean enumeratePathsOnly = false;

		Set<Unit> discoveredUnits = new LinkedHashSet<Unit>(); // units for which paths have begun enumeration
		discoveredUnits.add(startingUnit);

		Stack<Unit> workUnits = new Stack<Unit>(); // working stack for units to start or continue path analysis from
		workUnits.push(startingUnit);

		Stack<List<Unit>> workPaths = new Stack<List<Unit>>(); // working stack for paths under analysis
		List<Unit> initialPath = new ArrayList<Unit>();
		initialPath.add(startingUnit);
		workPaths.push(initialPath);

		//Set<List<Unit>> finalPaths = new LinkedHashSet<List<Unit>>();
		Integer finalPaths = 0;

		int finalPathsLimit = 100;
		boolean hitPathsLimit = false;

		while (!workUnits.isEmpty()) {
			if (workPaths.size() != workUnits.size()) {
				throw new RuntimeException("workUnits size is different from workPaths size");
			}

			Unit startUnitOfCurrPath = workUnits.pop(); // starting unit in current path
			List<Unit> currPath = workPaths.pop(); // current path to work on
			discoveredUnits.add(startUnitOfCurrPath);

			if (ug.getPredsOf(startUnitOfCurrPath).isEmpty()) { // if there are no more predecessors than we reached the end of the path
				if (startUnitOfCurrPath instanceof IdentityStmt) {
					// Reach the beginning of the function
					IdentityStmt idStmt = (IdentityStmt) startUnitOfCurrPath;
					if (idStmt.getRightOp() instanceof CaughtExceptionRef) {
						logger.trace("Exceptional path is not being analyzed for now");
					} else {
						// increase finalPathsLimit will get more paths?
						if (finalPaths < finalPathsLimit) {
							// add currPath to path to analyze if it reaches the beginning and is less than a pre-set limit
							finalPaths += 1;
						} else {
							hitPathsLimit = true;
							break;
						}
					}
				}
			}

			// there are more predecessors
			// traversing in reverse
			for (Unit pred : ug.getPredsOf(startUnitOfCurrPath)) { // update paths based on predecessors
				if (currPath.contains(pred)) {
					logger.trace("loop detected---already followed this edge!");
					continue;
				}

				if (pred instanceof IfStmt) {
					if (!ifUnitsUsingIntents.contains(pred)) {
						// pred is a conditional stmt that does not use intent
						// FOUND control dependency not related to Intent
						return false;
					}
				}

				List<Unit> newPath = new ArrayList<Unit>(currPath);
				newPath.add(pred); // add to end of list, so path is reverse

				// if there are two preds, two new paths will be created
				workPaths.push(newPath);
				workUnits.push(pred);

			}

		}

		if (hitPathsLimit) {
			logger.debug("Path limit hit for unit " + startingUnit + " in method " + method);
		}

		// path to startingUnit's control dependencies are all intent-related
		return true;
	}

	public Boolean controlDepsIntentOnlyCaller(SootMethod caller, SootMethod callee) {
		if (caller.hasActiveBody()) {
			List<Unit> callsites = new ArrayList<Unit>();
			PatchingChain<Unit> units = caller.getActiveBody().getUnits();
			// find all call sites of callee
			// and fill up ifUnitsUsingIntents
			Set<Unit> ifUnitsUsingIntents = new LinkedHashSet<Unit>();
			for (Unit u : units) {
				unitNeedsAnalysis(caller, caller.getDeclaringClass().getName(), u, ifUnitsUsingIntents);
				Stmt s = (Stmt) u;
				if (s.containsInvokeExpr()) {
					InvokeExpr ie = s.getInvokeExpr();
					if (ie.getMethod().equals(callee)) {
						// found an unit that calls callee
						callsites.add(u);
					}
				}
			}
			// find one fully Intent dependent path to callee
			Body b = caller.getActiveBody();
			final BriefUnitGraph ug = new BriefUnitGraph(b);
			for (Unit u : callsites) {
				if (controlDepsIntentOnly(caller, ug, u, ifUnitsUsingIntents)) {
					// found a fully Intent dependent path to callee
					return true;
				}
			}
			return false;
		} else {
			// caller cannot be analyzed
			return false;
		}
	}

	private boolean isFallThrough(Unit inUnit, Unit succ) {
		return (succ == null && inUnit instanceof IfStmt) ? true : icfg.isFallThroughSuccessor(inUnit, succ);
	}

	private boolean isBranch(Unit inUnit, Unit succ) {
		if (icfg.isBranchTarget(inUnit, succ)) {
			return true;
		}
		return false;
	}

//	@Override
	protected void internalTransform(String phaseName,
									 Map<String, String> options) {

		logger.debug("Setting up dummy main method");
		//List<SootMethod> rtoMethods = Utils.setupDummyMainMethodWithCallGraph();
		logger.debug("CHA call graph built");
		CallGraph cg = Scene.v().getCallGraph();
		List<SootMethod> rtoMethods = Utils.getMethodsInReverseTopologicalOrder();

		icfg = new JimpleBasedInterproceduralCFG();

		String newLine = System.getProperty("line.separator");
		FileWriter iFile;  // instrumentation file
		try {
			String apkFileName = Config.apkFilePath.substring(Config.apkFilePath.lastIndexOf("/")+1);
			if (Config.folderName != null) {
				iFile = new FileWriter("apksOut/" + Config.folderName + "_" + apkFileName + ".txt");
				iFile.close();
				iFile = new FileWriter("apksOut/" + Config.folderName + "_" + apkFileName + ".txt", true);
			} else {
				iFile = new FileWriter("apksOut/" + apkFileName + ".txt");
				iFile.close();
				iFile = new FileWriter("apksOut/" + apkFileName + ".txt", true);
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		int currMethodCount=0;
		for (SootMethod method : rtoMethods) {
			logger.debug("Checking if I should analyze method: " + method);
			if (Utils.isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
				if (method.hasActiveBody()) {

					if (methodsToFilter.contains(method.getName())) {
						continue;
					}

					// get intent-controlled statements, regardless if it is fully-controlled or not
					Set<Unit> ifUnitsUsingIntents = new LinkedHashSet<Unit>();
					PatchingChain<Unit> units = method.getActiveBody().getUnits();
					boolean methodNeedsAnalysis = false;
					List<Unit> unitsGuardedByIntents = new ArrayList<Unit>();
					for (Unit unit : units) {
						if (unitNeedsAnalysis(method, method.getDeclaringClass().getName(), unit, ifUnitsUsingIntents)) {
							// ifUnitsUsingIntents : if-statements that are Intent-controlled statements
							// debugging purpose
							//System.out.println("UNIT: " + unit.toString() + " at line " + String.valueOf(unit.getJavaSourceStartLineNumber()) + " of method " + method.getName() + " and class " +method.getDeclaringClass().getName() );
							intentControlledStatementCnt += 1;
							methodNeedsAnalysis = true;
							unitsGuardedByIntents.add(unit);
						}
					}

					if (!methodNeedsAnalysis) {
						// method does not contain intent usage
						continue;
					}

					// walk up call graph to immediate caller
					Iterator<Edge> edges = cg.edgesInto(method);
					SootMethod caller = null;
					Edge curEdge = null;
					Boolean hasCaller = false;
					Boolean reachableFromACaller = false;
					List<SootMethod> callers = new ArrayList<SootMethod>();
					while (edges.hasNext()) {
						curEdge = edges.next();
						caller = (SootMethod) curEdge.getSrc();
						if (caller.getDeclaringClass().getName().contains("dummyMainClass") || Utils.isAndroidMethod(caller)) {
							continue;
						}
						if (methodsToFilter.contains(caller.getName())) {
							// cannot directly call onNewIntent from adb
							continue;
						}
						hasCaller = true;
						callers.add(caller);
						// analyze caller body
						// perform path extraction at each call sites
						// for all call sites, we just need one path
						// fully control-dependent on intent
						// otherwise ignore method
						// above needs to be true for one caller
						if (controlDepsIntentOnlyCaller(caller, method)) {
							reachableFromACaller = true;
						}
					}

					if (hasCaller && !reachableFromACaller) {
						// not entry method AND not fully intent-controlled dependent by one of its callers
						// method NOT fully dependent on intents inter-procedurally
						continue;
					}

					units = method.getActiveBody().getUnits();
					List<Unit> listToInsert = null;
					logger.debug("Analzying method: " + method);
					Map<Unit, List<Unit>> unitInstrumentsMap = new HashMap<Unit, List<Unit>>();

					Set<Unit> discoveredUnits = new LinkedHashSet<Unit>(); // units for which paths have begun enumeration

					if (!unitsGuardedByIntents.isEmpty()) {
						Body b = method.getActiveBody();
						final BriefUnitGraph ug = new BriefUnitGraph(b);
						for (Unit unit : unitsGuardedByIntents) {
							if (discoveredUnits.contains(unit)) {
								continue;
							}
							// perform back symbolic execution
							// unit fully dependent on intents intra-procedurally
							if (controlDepsIntentOnly(method, ug, unit, ifUnitsUsingIntents)) {
								// add instrumentation
								//logger.debug(unit + " needs analysis");
								logger.debug("UNIT: " + unit.toString() + " at line " + String.valueOf(unit.getJavaSourceStartLineNumber()) + " of method " + method.getName() + " and class " +method.getDeclaringClass().getName() );
								discoveredUnits.add(unit);
								this.addInstrumentStatement(method,unit,iFile,newLine);
								/*
								if (listToInsert!=null) {
									logger.debug("Instrument> check if listToInsert.size = " + listToInsert.size());
									if (listToInsert.size() > 0) {
										logger.debug("Instrument> insert " + listToInsert.size() + " instrument(s) statement to method " + method.getName());
										unitInstrumentsMap.put(unit, listToInsert);
									}
								}
								else {
									logger.error("Why is this unit not getting an instrument statement?");
									logger.error("problematic unit: `" + unit);
								}
								 */
							}
						}
					}

					// adding the instrumentation statements after the for-each loop to
					// prevent the concurrency problem
					for (Unit u : unitInstrumentsMap.keySet()) {
						logger.debug("Instrument> insert instrument(s) statement to method " + method.getName());
						//method.getActiveBody().getUnits().insertBefore(unitInstrumentsMap.get(u), u);
						method.getActiveBody().getUnits().insertBefore(unitInstrumentsMap.get(u), u);
					}
					method.getActiveBody().validate();
				}
				else {
					logger.debug("method " + method + " has no active body, so it's won't be analyzed.");
				}
			}
			logger.debug("Finished path analysis on method: " + method);
			logger.debug("Number of methods analyzed: " + currMethodCount);
			logger.debug("Number of units added for method: " + instrumentStatementCnt);
			currMethodCount++;
		}
	}


//	public List<Unit> addInstrumentStatement(SootMethod method, Unit inUnit, FileWriter iFile, String newLine){
	public void addInstrumentStatement(SootMethod method, Unit inUnit, FileWriter iFile, String newLine){
		BytecodeOffsetTag bytecodeOffset = Utils.extractByteCodeOffset(inUnit);

		//insert a log.i instrument statement
		//Scene.v().addBasicClass("android.util.Log",SIGNATURES);
//		Scene.v().forceResolve("android.util.Log",SIGNATURES);
		instrumentStatementCnt += 1;
		//SootClass logClass = Scene.v().loadClassAndSupport("android.util.Log");
//		SootMethod log = Scene.v().getMethod("<android.util.Log: int i(java.lang.String,java.lang.String)>");
//		Value logMessage = StringConstant.v("#InstrumentNumber#"+ instrumentStatementCnt +
//				" #method#"+method.getSignature()+" #lineNumber#"+inUnit.getJavaSourceStartLineNumber()+"#bytecodeOffset#"+bytecodeOffset);
//		Value logType = StringConstant.v("Instrument");
//		Value logMsg = logMessage;
//		//make new static invokement
//		StaticInvokeExpr newInvokeExpr = Jimple.v().newStaticInvokeExpr(log.makeRef(), logType, logMsg);
//		// turn it into an invoke statement
//		List<Unit> listToInsert = new ArrayList<Unit>();
//		listToInsert.add(Jimple.v().newInvokeStmt(newInvokeExpr));

		// insert into smali code
		if (instrumentedUnitsSeen.contains(inUnit)) {
			return;
		}

		try {
			iFile.write(method.getDeclaringClass().getName()+"#"+method.getSubSignature()+"#"+method.getName()+"#"+method.getParameterCount()+"#"+inUnit.getJavaSourceStartLineNumber()+"#"+instrumentStatementCnt+newLine);
			iFile.flush();
			System.out.println(method.getDeclaringClass().getName()+"#"+method.getSubSignature()+"#"+method.getName()+"#"+method.getParameterCount()+"#"+inUnit.getJavaSourceStartLineNumber()+"#"+instrumentStatementCnt+newLine);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		instrumentedUnitsSeen.add(inUnit);
		return;
	}

//	@Override
	public void run() {
		// resolve the PrintStream and System soot-classes
		Scene.v().addBasicClass("java.io.PrintStream", SIGNATURES);
		Scene.v().addBasicClass("java.lang.System", SIGNATURES);
		Scene.v().addBasicClass("android.util.Log", SIGNATURES);
		//Options.v().set_whole_program(true);
		//Options.v().setPhaseOption("jb", "use-original-names:true");

		Utils.setupDummyMainMethod();
		// original
		PackManager.v().getPack("wjtp").add(new Transform("wjtp.pathexec", this));
		PackManager.v().getPack("wjtp").apply();


//		PackManager.v().getPack("jtp").add(new Transform("jtp.pathexec", this));
//		Utils.applyWholeProgramSootOptions(Config.apkFilePath);

//		Utils.initializeSoot();

//		Options.v().set_output_format(Options.output_format_dex);
//		Options.v().set_force_overwrite(true); // allows the PackManager to override the existing apk file BUT it's not working :(
		//Options.v().set_android_api_version(23);
//		PackManager.v().writeOutput(); //write instrumented apk to sootOutputDir

	}
}