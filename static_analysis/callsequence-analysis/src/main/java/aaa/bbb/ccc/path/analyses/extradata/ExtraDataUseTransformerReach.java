package aaa.bbb.ccc.path.analyses.extradata;

import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerJni;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerReach;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

import java.util.*;

public class ExtraDataUseTransformerReach extends TargetedPathTransformerReach {

    Map<Unit,Boolean> doesUnitNeedAnalysisSummary = new LinkedHashMap<Unit,Boolean>();
    Set<String> classesNeedAnalysis = new LinkedHashSet<String>();

    public ExtraDataUseTransformerReach(String apkFilePath) {
        super(apkFilePath);
    }

    @Override
    public boolean unitNeedsAnalysisSink(SootMethod method, String currClassName, Unit inUnit, Map<SootMethod, Map<Unit, List<UnitPathSink>>> methodSummaries, Set<String> sinksMethodSignatures) {
        if (Utils.isAndroidMethod(method)) {
            return false;
        }
        if (method.getName().startsWith("access$")) {
            return false;
        }

        Stmt inStmt = (Stmt) inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            SootMethod calledMethod = ie.getMethod();
            // check if it is a method call that transitively calls a method that contains JNI call
            if (methodSummaries.containsKey(calledMethod)) {
                return true;
            }
            // check if method call is a sink
            for (String sink : sinksMethodSignatures) {
                if (calledMethod.getSignature().equals(sink)) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public boolean unitNeedsAnalysisSource(SootMethod method, String currClassName, Unit inUnit, Map<SootMethod, Map<Unit, List<UnitPathSink>>> srcMethodSummaries, Set<String> sourcesMethodSignatures) {
        if (Utils.isAndroidMethod(method)) {
            return false;
        }
        if (method.getName().startsWith("access$")) {
            return false;
        }

        Stmt inStmt = (Stmt) inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            SootMethod calledMethod = ie.getMethod();
//            SootClass clsk = Scene.v().getSootClass("com.mitake.network.k");
//            SootClass clsi = Scene.v().getSootClass("com.mitake.network.i");
//            SootMethod ka = clsk.getMethod("void a(java.io.InputStream)");
//            SootMethod ia = clsi.getMethod("byte[] a(java.io.InputStream,int)");
//            SootClass clsk = Scene.v().getSootClass("e.c.d.d0");
//            SootClass clsi = Scene.v().getSootClass("e.c.d.v");
//            SootMethod ka = clsk.getMethod("void E(java.io.InputStream)");
//            SootMethod ia = clsi.getMethod("byte[] D(java.io.InputStream,int)");
			//SootClass parCls = Scene.v().getSootClass("com.ubikey.stock.UbikeyLibrary");
            //SootMethod parMtd = parCls.getMethod("boolean ubikeyConnect(android.content.Context)");
            if (srcMethodSummaries.containsKey(calledMethod)) {
                return true;
            }
            // check if method call is a source
            for (String source : sourcesMethodSignatures) {
                if (calledMethod.getSignature().equals(source)) {
                    return true;
                }
            }
        }
        return false;
    }
}