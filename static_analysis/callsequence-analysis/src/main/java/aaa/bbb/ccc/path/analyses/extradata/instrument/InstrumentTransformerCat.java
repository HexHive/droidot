package aaa.bbb.ccc.path.analyses.extradata.instrument;

import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.Globals;
import aaa.bbb.ccc.path.analyses.extradata.ExtraDataUseTransformerSp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.options.Options;
import soot.tagkit.BytecodeOffsetTag;
import soot.tagkit.StringConstantValueTag;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.util.*;
import java.util.regex.Pattern;

import static soot.SootClass.SIGNATURES;

/*
 * This class allows you to instrument the apk
 */
public class InstrumentTransformerCat extends SceneTransformer {

	Map<Unit,Boolean> doesUnitNeedAnalysisSummary = new LinkedHashMap<Unit,Boolean>();
	static Logger logger = LoggerFactory.getLogger(InstrumentTransformerCat.class);
	protected int instrumentStatementCnt=0;

    int controlDepPaths = 0;
    int intentControlDepPaths = 0;
    Map<String,Integer> intentCatCounts = new LinkedHashMap<String,Integer>();

    // profiling
    Map<String,Integer> noModelStrOps = new LinkedHashMap<String,Integer>();
    Map<String,Integer> noModelAttrs = new LinkedHashMap<String,Integer>();

	public int getInstrumentStmtCount() {
		return instrumentStatementCnt;
	}

	public InstrumentTransformerCat(String apkFilePath) {
        G.reset();
        Config.apkFilePath = apkFilePath;

        intentCatCounts.put("action", 0);
        intentCatCounts.put("uri", 0);
        intentCatCounts.put("uri-nullness", 0);
        intentCatCounts.put("extras-key", 0);
        intentCatCounts.put("extras-value", 0);
        intentCatCounts.put("bundleExtras-key", 0);
        intentCatCounts.put("bundleExtras-value", 0);
        intentCatCounts.put("category", 0);
        intentCatCounts.put("array-extras-value", 0);
	}

    public void addToProfileMap(Map<String,Integer> map, String key) {
        if (!map.containsKey(key)) {
            // new key
            map.put(key, 1);
        } else {
            // existing key
            map.put(key, map.get(key)+1);
        }
    }

    public Boolean checkIfUnitUsesIntentPayloadNew(Unit inUnit, SimpleLocalDefs localDefs, StringBuilder messageType, Boolean containsNullComp) {
        // only check intent-controlled statements phenomenon model. Good for catching bugs
        Stmt inStmt = (Stmt)inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            Boolean x = isIntentPayloadExtractionMethod(localDefs, inUnit, ie, messageType, containsNullComp);
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
                List<Value> args = ie.getArgs();
                for (Value arg : args) {
                    if (arg instanceof Local) {
                        List<Unit> defUnits = localDefs.getDefsOfAt((Local) arg, inUnit);
                        for (Unit defUnit : defUnits) {
                            InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
                            if (invokeExpr == null) {
                                continue;
                            }
                            Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp);
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
                            Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp);
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
                        Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp);
                        // TODO: tmp fix for charAt
                        /*
                        if (invokeExpr.getMethod().getName().equals("charAt") && invokeExpr.getMethod().getDeclaringClass().toString().equals("java.lang.String")) {
                            addToProfileMap(noModelStrOps, "charAt");
                        }
                         */
                        if (x != null && x == true)
                            return x;
                    }
                }
            }
        }
        return null;
    }

    public Boolean checkIfUnitUsesIntentPayload(Unit inUnit, SimpleLocalDefs localDefs, StringBuilder messageType, Boolean containsNullComp) {
        Stmt inStmt = (Stmt)inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            Boolean x = isIntentPayloadExtractionMethod(localDefs,inUnit,ie, messageType, containsNullComp);
            if (x != null && x == true) {
                // inUnit is an intent extraction instruction
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
                    Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp);
                    if (x != null && x == true)
                        return x;
                }
            }
        }
        return null;
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

    public Boolean isIntentPayloadExtractionMethod(SimpleLocalDefs localDefs, Unit defUnit, InvokeExpr invokeExpr, StringBuilder messageType, Boolean containsNullComp) {

        if (Pattern.matches("getData", invokeExpr.getMethod().getName())) {
            // extracting URI. getData() returns URI
            // check: can the tool's corresponding intent have an URI field?
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                messageType.append(invokeExpr.getMethod().getName()+"().");
                if (containsNullComp) {
                    intentCatCounts.put("uri-nullness", intentCatCounts.get("uri-nullness")+1);
                } else {
                    // we do not model uri in general
                    // PROFILE: URI (not URI nullness)
                    intentCatCounts.put("uri", intentCatCounts.get("uri")+1);
                }
                return true;
            }
        }
        if (Pattern.matches("getDataString", invokeExpr.getMethod().getName())) {
            // extracting URI as String. getDataString() returns URI
            // check: can the tool's corresponding intent have an URI field?
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                messageType.append(invokeExpr.getMethod().getName()+"().");
                if (containsNullComp) {
                    intentCatCounts.put("uri-nullness", intentCatCounts.get("uri-nullness")+1);
                } else {
                    // we do not model uri in general
                    // PROFILE: URI (not URI nullness)
                    intentCatCounts.put("uri", intentCatCounts.get("uri")+1);
                }
                return true;
            }
        }

       if (Pattern.matches("get.*Extra", invokeExpr.getMethod().getName())) {
           // model array array variants now: nullness
           /*
           if (Pattern.matches("get.*ArrayExtra", invokeExpr.getMethod().getName()) ||
               Pattern.matches("get.*ArrayListExtra", invokeExpr.getMethod().getName())) {
               // we do not model these
               // PROFILE: attribute extraction methods that we don't model
               addToProfileMap(noModelAttrs, invokeExpr.getMethod().getName());
               intentCatCounts.put("array-extras-value", intentCatCounts.get("array-extras-value")+1);
               intentControlDepPaths += 1;  // since it won't increment in unitNeedsAnalysis because we don't return true
               return null;
           }
            */
           // extracting extra data value
           if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                String arg = getIeArg(invokeExpr, localDefs, defUnit);
                if (arg == null) {
                    // extra data arg not sucessfully retrieved
                    return null;
                }
               //messageType.append(invokeExpr.getMethod().getName()+"("+getIeArg(invokeExpr)+").");
               intentCatCounts.put("extras-value", intentCatCounts.get("extras-value")+1);
               return true;
           }
        }
        if (Pattern.matches("hasExtra", invokeExpr.getMethod().getName())) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                String arg = getIeArg(invokeExpr, localDefs, defUnit);
                if (arg == null) {
                    // extra data arg not sucessfully retrieved
                    return null;
                }
				//messageType.append(invokeExpr.getMethod().getName()+"("+getIeArg(invokeExpr)+").");
                intentCatCounts.put("extras-key", intentCatCounts.get("extras-key")+1);
                return true;
            }
        }
        if (Globals.bundleExtraDataMethodsSet.contains(invokeExpr.getMethod().getName())) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.os.Bundle")) {
                Boolean isFromIntent = isBundleFromIntent(localDefs, defUnit, invokeExpr, messageType);
                if (isFromIntent) {
                    String arg = getIeArg(invokeExpr, localDefs, defUnit);
                    if (arg == null) {
                        // extra data arg not sucessfully retrieved
                        return null;
                    }
                    if (invokeExpr.getMethod().getName().equals("containsKey")) {
                        intentCatCounts.put("bundleExtras-key", intentCatCounts.get("bundleExtras-key")+1);
                    } else {
                        intentCatCounts.put("bundleExtras-value", intentCatCounts.get("bundleExtras-value")+1);
                    }
                    //messageType.append(invokeExpr.getMethod().getName()+"("+getIeArg(invokeExpr)+").");
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
                    if (invokeExpr.getMethod().getName().equals("containsKey")) {
                        intentCatCounts.put("bundleExtras-key", intentCatCounts.get("bundleExtras-key")+1);
                    } else {
                        intentCatCounts.put("bundleExtras-value", intentCatCounts.get("bundleExtras-value")+1);
                    }
                    //messageType.append(invokeExpr.getMethod().getName()+"("+getIeArg(invokeExpr)+").");
                }
                return isFromIntent;
            }
        }
        if (Globals.categoryMethodsSet.contains(invokeExpr.getMethod().getName())) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                if (invokeExpr.getMethod().getName().equals("hasCategory")) {
                    String arg = getIeArg(invokeExpr, localDefs, defUnit);
                    if (arg == null) {
                        // extra data arg not sucessfully retrieved
                        return null;
                    }
                    //messageType.append(invokeExpr.getMethod().getName()+"("+getIeArg(invokeExpr)+").");
                }
                intentCatCounts.put("category", intentCatCounts.get("category")+1);
                return true;
            }
        }
        if (Pattern.matches("getAction", invokeExpr.getMethod().getName())) {
            // redundant. also in stringReturningIntentMethodsSet
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
				messageType.append(invokeExpr.getMethod().getName()+"().");
                intentCatCounts.put("action", intentCatCounts.get("action")+1);
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
                                String arg = getIeArg(invokeExpr, localDefs, defUnit);
                                if (arg == null) {
                                    // extra data arg not sucessfully retrieved
                                    return null;
                                }
                                // getStringExtra. Extracting extra data value
								//messageType.append(invokeExpr.getMethod().getName()+"("+getIeArg(invokeExpr)+").");
                                intentCatCounts.put("extras-value", intentCatCounts.get("extras-value")+1);
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return null;
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

	public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit inUnit, StringBuilder messageType) {
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

        BriefUnitGraph ug = new BriefUnitGraph(method.getActiveBody());
        SimpleLocalDefs localDefs = new SimpleLocalDefs(ug);
        for (Unit pred : ug.getPredsOf(inUnit)) {
            if (pred instanceof IfStmt) {
                //System.out.println("current unit: " + inUnit.toString()+", currClassName: "+currClassName+", method: "+method.toString());
                Boolean containsNullComp = isNullComparison((IfStmt) pred);
                controlDepPaths += 1;
                Boolean isIntentControlled = false;
                IfStmt predIfStmt = (IfStmt) pred;
                for (ValueBox useBox : predIfStmt.getUseBoxes()) {
                    if (useBox.getValue() instanceof Local) {
                        Local useLocal = (Local) useBox.getValue();
                        for (Unit defUnit : localDefs.getDefsOfAt(useLocal, predIfStmt)) {
                            // defUnit is the definition of useLocal at predIfStmt
                            Boolean defUnitUses = checkIfUnitUsesIntentPayload(defUnit, localDefs, messageType, containsNullComp);
                            if (defUnitUses != null) {
                                if (defUnitUses.booleanValue()) {
                                    // pred of unit is an if-statement that contains usage of intent payload
                                    isIntentControlled = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (isIntentControlled) {
                    intentControlDepPaths += 1;
                    doesUnitNeedAnalysisSummary.put(inUnit, true);
                    // debugging purpose
                    //System.out.println("UNIT: " + inUnit.toString() + " at line " + String.valueOf(inUnit.getJavaSourceStartLineNumber()) + " of method " + method.getName() + " and class " +method.getDeclaringClass().getName() );
                    logger.debug("UNIT: " + inUnit.toString() + " at line " + String.valueOf(inUnit.getJavaSourceStartLineNumber()) + " of method " + method.getName() + " and class " +method.getDeclaringClass().getName() );
                    return true;
                }
                // return value of getPredsOf is sorted by scope. First element is the outermost scope
                doesUnitNeedAnalysisSummary.put(inUnit, false);
                return false;
            }
        }
        doesUnitNeedAnalysisSummary.put(inUnit,false);
        return false;
	}

//	@Override
	protected void internalTransform(String phaseName,
									 Map<String, String> options) {
		logger.debug("Setting up dummy main method");
		Utils.setupDummyMainMethod();
		logger.debug("Constructing CHA call graph");
		CHATransformer.v().transform();
		logger.debug("CHA call graph built");

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

		rtoMethods = Utils.getMethodsInReverseTopologicalOrder();

		int currMethodCount=0;
		for (SootMethod method : rtoMethods) {
			logger.debug("Checking if I should analyze method: " + method);
			if (Utils.isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
				if (method.hasActiveBody()) {
					PatchingChain<Unit> units = method.getActiveBody().getUnits();
					//logger.debug("Analyzing method: " + method);
                    //System.out.println("Analyzing method: " + method);
					StringBuilder messageType = new StringBuilder("");
					for (Unit unit : units) {
						unitNeedsAnalysis(method, method.getDeclaringClass().getName(), unit, messageType);
					}

    			}
				else {
					logger.debug("method " + method + " has no active body, so it's won't be analyzed.");
				}
			}

			logger.debug("Finished path analysis on method: " + method);
			logger.debug("Number of methods analyzed: " + currMethodCount);
			currMethodCount++;
		}
	}

//	@Override
	public void run() {
		// resolve the PrintStream and System soot-classes
		Scene.v().addBasicClass("java.io.PrintStream", SIGNATURES);
		Scene.v().addBasicClass("java.lang.System", SIGNATURES);
		Scene.v().addBasicClass("android.util.Log", SIGNATURES);
		Options.v().set_whole_program(true);
		Options.v().setPhaseOption("jb", "use-original-names:true");

		PackManager.v().getPack("wjtp").add(new Transform("wjtp.pathexec", this));
		PackManager.v().getPack("wjtp").apply();

		Options.v().set_output_format(Options.output_format_dex);
		Options.v().set_force_overwrite(true); // allows the PackManager to override the existing apk file BUT it's not working :(
		PackManager.v().writeOutput(); //write instrumented apk to sootOutputDir
	}
}