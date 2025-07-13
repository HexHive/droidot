package aaa.bbb.ccc.path.analyses.extradata;

import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.Globals;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerSpEval;
import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.util.*;
import java.util.regex.Pattern;

public class ExtraDataUseTransformerSpEval extends TargetedPathTransformerSpEval {

    Map<Unit, Boolean> doesUnitNeedAnalysisSummary = new LinkedHashMap<Unit, Boolean>();
    Set<String> classesNeedAnalysis = new LinkedHashSet<String>();
    boolean accountEv = true;  // evaluation account for extra values

    public ExtraDataUseTransformerSpEval(String apkFilePath, List jsons) {
        super(apkFilePath, jsons);
    }

    //Map<String,Integer> intentCatCounts = new LinkedHashMap<String,Integer>();

    public ExtraDataUseTransformerSpEval(String apkFilePath, List jsons, boolean accountEv) {
        super(apkFilePath, jsons);
        this.accountEv = accountEv;
    }

//    @Override
    public String unitNeedsAnalysis(SootMethod method, String currClassName, Unit inUnit) {
        if (Utils.isAndroidMethod(method)) {
            return null;
        }
        if (method.getName().startsWith("access$")) {
            return null;
        }
        if (method.getName().startsWith("<init>")) {
            // constructor
            return null;
        }
        if (method.getName().startsWith("<clinit>")) {
            // static initializer
            return null;
        }

        /*
        if (doesUnitNeedAnalysisSummary.containsKey(inUnit)) {
            // previously has already computed whether unit `inUnit` needs analysis or not
            return doesUnitNeedAnalysisSummary.get(inUnit);
        }
         */

        BriefUnitGraph ug = new BriefUnitGraph(method.getActiveBody());
        SimpleLocalDefs localDefs = new SimpleLocalDefs(ug);
        for (Unit pred : ug.getPredsOf(inUnit)) {
            if (pred instanceof IfStmt) {
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
                        for (Unit defUnit : localDefs.getDefsOfAt(useLocal, predIfStmt)) {
                            // defUnit is the definition of useLocal at predIfStmt
                            StringBuilder messageType = new StringBuilder("");
                            String attr = checkIfUnitUsesIntentPayload(defUnit, localDefs, messageType, containsNullComp);
                            if (attr != null) {
                                // pred of unit is an if-statement that contains usage of intent payload
                                // track if-stmt that passes unitNeedsAnalysis
                                doesUnitNeedAnalysisSummary.put(inUnit, true);
                                return attr;
                            }
                        }
                    }
                }
                // return value of getPredsOf is sorted by scope. First element is the outermost scope
                doesUnitNeedAnalysisSummary.put(inUnit, false);
                return null;
            }
        }

        doesUnitNeedAnalysisSummary.put(inUnit, false);
        return null;
    }

    public String checkIfUnitUsesIntentPayload(Unit inUnit, SimpleLocalDefs localDefs, StringBuilder messageType, Boolean containsNullComp) {
        // only check intent-controlled statements phenomenon model. Good for catching bugs
        Stmt inStmt = (Stmt)inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            String attr = isIntentPayloadExtractionMethod(localDefs, inUnit, ie, messageType, containsNullComp);
            if (attr != null) {
                // inUnit is an intent extraction instruction
                return attr;
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
                    String attr = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp);
                    if (attr != null)
                        return attr;
                }
            }
        }
        return null;
    }

    /*
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
                        //if (invokeExpr.getMethod().getName().equals("charAt") && invokeExpr.getMethod().getDeclaringClass().toString().equals("java.lang.String")) {
                        //    addToProfileMap(noModelStrOps, "charAt");
                        //}
                        if (x != null && x == true)
                            return x;
                    }
                }
            }
        }
        return null;
    }
    */

    public String isIntentPayloadExtractionMethod(SimpleLocalDefs localDefs,
                                                   Unit defUnit,
                                                   InvokeExpr invokeExpr,
                                                   StringBuilder messageType,
                                                   Boolean containsNullComp) {
        // TODO: make this method almost same as TargetedPathTransformerSpEval's version

        String invokedMethodName = invokeExpr.getMethod().getName();

        /*
        if (Pattern.matches("getParcelableExtra", invokedMethodName)) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                //intentCatCounts.put("parcelable", intentCatCounts.get("parcelable")+1);
                return "parcelable";
            }
        }
        if (Pattern.matches("getParcelableArrayExtra", invokedMethodName)) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                //intentCatCounts.put("parcelable-array", intentCatCounts.get("parcelable-array")+1);
                return "parcelable-array";
            }
        }
        if (Pattern.matches("getParcelableArrayListExtra", invokedMethodName)) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                //intentCatCounts.put("parcelable-arraylist", intentCatCounts.get("parcelable-arraylist")+1);
                return "parcelable-arraylist";
            }
        }
         */

        if (Pattern.matches("getData", invokedMethodName)) {
            // extracting URI. getData() returns URI
            // check: can the tool's corresponding intent have an URI field?
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                messageType.append(invokedMethodName+"().");
                if (containsNullComp) {
                    //intentCatCounts.put("uri-nullness", intentCatCounts.get("uri-nullness")+1);
                    return "uri-nullness";
                } else {
                    // TODO: we do not model uri in general
                    //intentCatCounts.put("uri", intentCatCounts.get("uri")+1);
                    return "uri";
                }
            }
        }

        if (Pattern.matches("getDataString", invokedMethodName)) {
            // extracting URI as String. getDataString() returns URI
            // check: can the tool's corresponding intent have an URI field?
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                messageType.append(invokedMethodName+"().");
                if (containsNullComp) {
                    //intentCatCounts.put("uri-nullness", intentCatCounts.get("uri-nullness")+1);
                    return "uri-nullness";
                } else {
                    // TODO: handled by stringOpsSet
                    //intentCatCounts.put("uri", intentCatCounts.get("uri")+1);
                    //updateTotalCompare("uri");
                    //intentCatCounts.put("uri", intentCatCounts.get("uri")+1);
                    //return "uri";
                }
            }
        }

       if (Pattern.matches("get.*Extra", invokedMethodName)) {
           // model array array variants now: nullness
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
           if (invokedMethodName.equals("getSerializableExtra") || invokedMethodName.equals("getParcelableArrayExtra")
                    || invokedMethodName.equals("getParcelableArrayListExtra") || invokedMethodName.equals("getParcelableExtra")) {
               return "serial";
           }
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                String arg = getIeArg(invokeExpr, localDefs, defUnit);
                if (arg == null) {
                    // extra data arg not sucessfully retrieved
                    return null;
                }
                //intentCatCounts.put("extras-value", intentCatCounts.get("extras-value")+1);
                return "extras-value";
                /*
                if (accountEv) {
                    return true;
                } else {
                    return false;
                }
                 */
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
                //intentCatCounts.put("extras-key", intentCatCounts.get("extras-key")+1);
                return "extras-key";
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
                        //intentCatCounts.put("bundleExtras-key", intentCatCounts.get("bundleExtras-key")+1);
                        return "bundleExtras-key";
                    } else {
                        if (invokedMethodName.equals("getString")) {
                            return null;
                        }
                        //intentCatCounts.put("bundleExtras-value", intentCatCounts.get("bundleExtras-value")+1);
                        return "bundleExtras-value";
                        /*
                        if (accountEv) {
                            return true;
                        } else {
                            return false;
                        }
                         */
                    }
                }
                return null;
                //return false;
                //return isFromIntent;
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
                        //intentCatCounts.put("bundleExtras-key", intentCatCounts.get("bundleExtras-key")+1);
                        return "bundleExtras-key";
                    } else {
                        if (invokedMethodName.equals("getString")) {
                            return null;
                        }
                        //intentCatCounts.put("bundleExtras-value", intentCatCounts.get("bundleExtras-value")+1);
                        return "bundleExtras-value";
                        /*
                        if (accountEv) {
                            return true;
                        } else {
                            return false;
                        }
                         */
                    }
                }
                return null;
                //return isFromIntent;
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
                    // TODO: CAT does not have it here
                    //intentCatCounts.put("category", intentCatCounts.get("category")+1);
                    return "category";
                } else {
                    messageType.append(invokedMethodName+"().");
                    //intentCatCounts.put("category", intentCatCounts.get("category")+1);
                    return "category";
                }
            }
        }
/*
        if (Pattern.matches("getAction", invokedMethodName)) {
            // redundant. also in stringReturningIntentMethodsSet
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
				messageType.append(invokedMethodName+"().");
                //intentCatCounts.put("action", intentCatCounts.get("action")+1);
                return "action";
            }
        }
 */
        // TODO: also check for length and other string operations here?
        if (Globals.stringOpsSet.contains(invokeExpr.getMethod().getName()) && invokeExpr.getMethod().getDeclaringClass().getName().equals("java.lang.String")) {
            if (invokeExpr instanceof VirtualInvokeExpr) {
                VirtualInvokeExpr vInvokeExpr = (VirtualInvokeExpr) invokeExpr;
                Value base = vInvokeExpr.getBase();
                // check if `base` is a string that is a return value of intent extraction method (e.g., getIntExtra)
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
                                    // extra data arg not sucessfully retrieved
                                    return null;
                                }
								messageType.append(invokedMethodName+"("+arg+").");
                                String strOperatedMethod = baseInvokeExpr.getMethod().getName();
                                if (strOperatedMethod.equals("getStringExtra")) {
                                    return "extras-value";
                                } else if (strOperatedMethod.equals("getAction")) {
                                    return "action";
                                } else if (strOperatedMethod.equals("getDataString")) {
                                    return "uri";
                                } else if (strOperatedMethod.equals("getString"))  {
                                    return "bundleExtras-value";
                                }
                                //intentCatCounts.put("extras-value", intentCatCounts.get("extras-value")+1);
                                /*
                                if (accountEv) {
                                } else {
                                    return false;
                                }
                                 */
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    public static boolean isBundleFromIntent(SimpleLocalDefs localDefs, Unit defUnit, InvokeExpr invokeExpr) {
        if (invokeExpr instanceof InstanceInvokeExpr) {
            InstanceInvokeExpr instanceInvokeExpr = (InstanceInvokeExpr) invokeExpr;
            if (instanceInvokeExpr.getBase() instanceof Local) {
                Local base = (Local) instanceInvokeExpr.getBase();
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
