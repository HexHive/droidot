package aaa.bbb.ccc.path.analyses.extradata;

import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.Globals;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerAnn;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerSp;
import soot.*;
import soot.jimple.*;
import soot.tagkit.Tag;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.util.*;
import java.util.regex.Pattern;

import static aaa.bbb.ccc.Utils.getInvokeExpr;

public class ExtraDataUseTransformerAnn extends TargetedPathTransformerAnn {

    Map<Unit, Boolean> doesUnitNeedAnalysisSummary = new LinkedHashMap<Unit, Boolean>();
    Set<String> classesNeedAnalysis = new LinkedHashSet<String>();

    public ExtraDataUseTransformerAnn(String apkFilePath) {
        super(apkFilePath);
    }

    public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit inUnit) {
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

        // not in the static instrumentation version (Cat, Compare)
        Stmt inStmt = (Stmt) inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            for (int i = 0; i < ie.getArgCount(); i++) {
                Value arg = ie.getArg(i);
                if (arg.getType().toString().equals("android.content.Intent") && !method.getName().equals("dummyMainMethod") && !method.getDeclaringClass().getName().equals("dummyMainClass")) {
                    // one of the function arguments is an intent
                    doesUnitNeedAnalysisSummary.put(inUnit, true);
                    return true;
                }
            }
        }

        BriefUnitGraph ug = new BriefUnitGraph(method.getActiveBody());
        SimpleLocalDefs localDefs = new SimpleLocalDefs(ug);
        for (Unit pred : ug.getPredsOf(inUnit)) {
            if (pred instanceof IfStmt) {
                IfStmt predIfStmt = (IfStmt) pred;
                for (ValueBox useBox : predIfStmt.getUseBoxes()) {
                    if (useBox.getValue() instanceof Local) {
                        Local useLocal = (Local) useBox.getValue();
                        for (Unit defUnit : localDefs.getDefsOfAt(useLocal, predIfStmt)) {
                            // defUnit is the definition of useLocal at predIfStmt
                            Boolean defUnitUses = checkIfUnitUsesIntentPayload(defUnit, localDefs);
                            if (defUnitUses != null) {
                                if (defUnitUses.booleanValue()) {
                                    // pred of unit is an if-statement that contains usage of intent payload
                                    // track if-stmt that passes unitNeedsAnalysis
                                    doesUnitNeedAnalysisSummary.put(inUnit, true);
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

        doesUnitNeedAnalysisSummary.put(inUnit, false);
        return false;
    }

    public boolean unitNeedsAnalysisTag(SootMethod method, String currClassName, Unit inUnit, Set<SootMethod> methodsWithSum, List<String> intentLocs) {
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

        // checking for pred has to happen before checking for callee since pred
        // can prematurely return false when checking for callee
        // example: pred is a android method call
        BriefUnitGraph ug = new BriefUnitGraph(method.getActiveBody());
        for (Unit pred : ug.getPredsOf(inUnit)) {
            if (pred instanceof IfStmt) {
                if (pred.hasTag("StringTag")) {
                    IfStmt predIfStmt = (IfStmt) pred;
                    int lineNum = pred.getJavaSourceStartLineNumber();
                    Tag t = pred.getTag("StringTag");
                    String tagVal = String.valueOf(t);
                    if (tagVal.startsWith("isIntentDependent")) {
                        if (justLineNumber) {
                            if (tagVal.contains(":")) {
                                // contains attribute
                                String attr = tagVal.split(":")[1];

                                if (isNullComparison(predIfStmt)) {
                                    // null comparison
                                    intentLocs.add(lineNum + ":" + attr + "-nullness");
                                } else {
                                    intentLocs.add(lineNum + ":" + attr);
                                }
                            } else {
                                // does not contain attribute
                                intentLocs.add(lineNum + ":?");
                            }
                        }
                        return true;
                    }
                }
            }
        }

        // return true on callee that has 1 or more arguments from Intent
        if (!justLineNumber) {
            // justLineNumber means we only want the line number of where the Intent-dependent if-statements are
            Stmt inStmt = (Stmt) inUnit;
            if (inStmt.containsInvokeExpr()) {
                InvokeExpr ie = getInvokeExpr(inStmt);
                if (ie == null) {
                    return false;
                }
                SootMethod calleeMethod = ie.getMethod();
                if (calleeMethod.hasTag("StringTag")) {
                    return true;
                } else {
                    return false;
                }
            }
        }

        return false;
    }

    public Boolean checkIfUnitUsesIntentPayload(Unit inUnit, SimpleLocalDefs localDefs) {
        // only check intent-controlled statements phenomenon model. Good for catching bugs
        Stmt inStmt = (Stmt)inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            Boolean x = isIntentPayloadExtractionMethod(localDefs, inUnit, ie);
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

                    Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr);
                    if (x != null && x == true)
                        return x;                }
            }
        }
        return null;
    }


    /*
    public Boolean checkIfUnitUsesIntentPayload(Unit inUnit, SimpleLocalDefs localDefs) {
        Stmt inStmt = (Stmt) inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            Boolean x = isIntentPayloadExtractionMethod(localDefs, inUnit, ie);
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
            // check args
            List<Value> args = ie.getArgs();
            for (Value arg : args) {
                if (arg instanceof Local) {
                    List<Unit> defUnits = localDefs.getDefsOfAt((Local) arg, inUnit);
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
            // check base
            if (ie instanceof InstanceInvokeExpr) {
                // base exists
                InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
                if (iie.getBase() instanceof Local) {
                    Local base = (Local) iie.getBase();
                    boolean baseIsIntentPayload = false;
                    List<Unit> defUnits = localDefs.getDefsOfAt(base, inUnit);
                    for (Unit defUnit : defUnits) {
                        InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
                        if (invokeExpr == null) {
                            continue;
                        }
                        if (invokeExpr.getMethod().getName().equals("valueOf")) {
                             // check if it's boolean. Boolean return from hasExtras has one more level
                            // of indirection before an intent payload extraction method is reached
                            Value value = invokeExpr.getArg(0);
                            if (value instanceof Local) {
                                List<Unit> defUnits2 = localDefs.getDefsOfAt((Local)value, defUnit);
                                for (Unit defUnit2 : defUnits2) {
                                    InvokeExpr invokeExpr2 = Utils.getInvokeExprOfAssignStmt(defUnit2);
                                    if (invokeExpr2 == null) {
                                        continue;
                                    }
                                    Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit2, invokeExpr2);
                                    if (x != null && x == true) {
                                        baseIsIntentPayload = true;
                                        break;
                                    }
                                }
                                if (baseIsIntentPayload) {
                                    break;
                                }
                            }
                        } else {
                            Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr);
                            if (x != null && x == true) {
                                baseIsIntentPayload = true;
                                break;
                            }
                        }
                    }
                    if (baseIsIntentPayload) {
                        // only return true for base operation we model
                        if (ie.getMethod().getDeclaringClass().toString().equals("java.lang.String")) {
                            if (ie.getMethod().getName().equals("length")) {
                                return true;
                            } else if (ie.getMethod().getName().equals("equals")) {
                                return true;
                            }
                        }   else if (ie.getMethod().getDeclaringClass().toString().equals("java.lang.Boolean")) {
                            if (ie.getMethod().getName().equals("booleanValue")) {
                                return true;
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
                        Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr);
                        if (x != null && x == true)
                            return x;
                    }
                }
            }
        }
        return null;
    }
     */

    public static Boolean isIntentPayloadExtractionMethod(SimpleLocalDefs localDefs, Unit defUnit, InvokeExpr invokeExpr) {

        /*
        if (Pattern.matches("getParcelableExtra", invokeExpr.getMethod().getName())) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                return true;
            }
        }
        if (Pattern.matches("getParcelableArrayExtra", invokeExpr.getMethod().getName())) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                return true;
            }
        }
        if (Pattern.matches("getParcelableArrayListExtra", invokeExpr.getMethod().getName())) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                return true;
            }
        }
         */

        if (Pattern.matches("getData", invokeExpr.getMethod().getName())) {
            // extracting URI. getData() returns URI
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                return true;
            }
        }
        if (Pattern.matches("getDataString", invokeExpr.getMethod().getName())) {
            // extracting URI as String. getDataString() returns URI
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                return true;
            }
        }

        if (Pattern.matches("get.*Extra", invokeExpr.getMethod().getName())) {
            // model array array variants now: nullness
            /*
            if (Pattern.matches("get.*ArrayExtra", invokeExpr.getMethod().getName()) ||
                    Pattern.matches("get.*ArrayListExtra", invokeExpr.getMethod().getName())) {
                // we do not model these
                return null;
            }
             */
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
        if (Globals.stringOpsSet.contains(invokeExpr.getMethod().getName()) && invokeExpr.getMethod().getDeclaringClass().getName().equals("java.lang.String")) {
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
