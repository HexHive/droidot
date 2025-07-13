package aaa.bbb.ccc.path.analyses.extradata;

import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.Globals;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerPy;
import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class ExtraDataUseTransformerPy extends TargetedPathTransformerPy {

	Map<Unit,Boolean> doesUnitNeedAnalysisSummary = new LinkedHashMap<Unit,Boolean>();

	public ExtraDataUseTransformerPy(String apkFilePath) {
		super(apkFilePath);
	}

	@Override
	public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit inUnit) {
		if (doesUnitNeedAnalysisSummary.containsKey(inUnit)) {
			// previously has already computed whether unit `inUnit` needs analysis or not
			return doesUnitNeedAnalysisSummary.get(inUnit);
		}

		Stmt inStmt = (Stmt)inUnit;
		if (inStmt.containsInvokeExpr()) {
			InvokeExpr ie = inStmt.getInvokeExpr();
			//System.out.println("@@@ unitNeedsAnalysis: "+inUnit.toString());
			//System.out.println(" $$ Signature: "+ie.getMethod().getSignature());
			//System.out.println(" ~~ SubSignature: "+ie.getMethod().getSubSignature());
			//System.out.println(" %% Name: "+ie.getMethod().getName());
			for (int i=0;i<ie.getArgCount();i++) {
				Value arg = ie.getArg(i);
				if (arg.getType().toString().equals("android.content.Intent") && !method.getName().equals("dummyMainMethod") && !method.getDeclaringClass().getName().equals("dummyMainClass")) {
					// one of the function arguments is an intent
					doesUnitNeedAnalysisSummary.put(inUnit,true);
					return true;
				}
			}
		}

		BriefUnitGraph ug = new BriefUnitGraph(method.getActiveBody());
		SimpleLocalDefs localDefs = new SimpleLocalDefs(ug);
		Boolean inUnitUses = checkIfUnitUsesIntentPayload(inUnit, localDefs);
		if (inUnitUses != null) {
			if (!(inUnit instanceof IfStmt)) {
				doesUnitNeedAnalysisSummary.put(inUnit,inUnitUses);
				return inUnitUses;
			}
			else {
				doesUnitNeedAnalysisSummary.put(inUnit,false);
				return false;
			}
		}

		for (Unit pred : ug.getPredsOf(inUnit)) {
			if (pred instanceof IfStmt) {
				IfStmt predIfStmt = (IfStmt)pred;
				for (ValueBox useBox : predIfStmt.getUseBoxes()) {
					if (useBox.getValue() instanceof Local) {
						Local useLocal = (Local)useBox.getValue();
						for (Unit defUnit : localDefs.getDefsOfAt(useLocal,predIfStmt)) {
							Boolean defUnitUses = checkIfUnitUsesIntentPayload(defUnit,localDefs);
							if (defUnitUses!=null) {
								if (defUnitUses.booleanValue()) {
									return true;
								}
							}

						}
					}
				}
			}
			Boolean predUses = checkIfUnitUsesIntentPayload(pred,localDefs);
			if (predUses!=null) {
				doesUnitNeedAnalysisSummary.put(inUnit,predUses);
				return predUses;
			}
		}
		doesUnitNeedAnalysisSummary.put(inUnit,false);
		return false;
	}

	private Boolean checkIfUnitUsesIntentPayload(Unit inUnit, SimpleLocalDefs localDefs) {
		Stmt inStmt = (Stmt)inUnit;
		if (inStmt.containsInvokeExpr()) {
			InvokeExpr ie = inStmt.getInvokeExpr();
			Boolean x = isIntentPayloadExtractionMethod(localDefs,inUnit,ie);
			if (x != null && x == true) {
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
						return x;

				}
			}
		}
		return null;
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

	public boolean isBundleFromIntent(SimpleLocalDefs localDefs, Unit defUnit, InvokeExpr invokeExpr) {
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
								return true;
							}
						}
					}
				}
			}
		}
		return false;
	}
}
