package aaa.bbb.ccc.path.analyses.extradata;

import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerAndrolib;
import soot.*;
import soot.jimple.*;

import java.util.*;

public class ExtraDataUseTransformerAndrolib extends TargetedPathTransformerAndrolib {

    Map<Unit,Boolean> doesUnitNeedAnalysisSummary = new LinkedHashMap<Unit,Boolean>();
    Set<String> classesNeedAnalysis = new LinkedHashSet<String>();

    public ExtraDataUseTransformerAndrolib(String apkFilePath) {
        super(apkFilePath);
    }

    @Override
    public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit inUnit) {
        if (Utils.isAndroidMethod(method)) {
            return false;
        }
        if (method.getName().startsWith("access$")) {
            return false;
        }

        if (doesUnitNeedAnalysisSummary.containsKey(inUnit)) {
            // previously has already computed whether unit `inUnit` needs analysis or not
            return doesUnitNeedAnalysisSummary.get(inUnit);
        }

        Stmt inStmt = (Stmt)inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();

            // check if it is JNI call
            SootMethod calledMethod = ie.getMethod();
            if (calledMethod.getDeclaration().contains(" native ")) {
                doesUnitNeedAnalysisSummary.put(inUnit, true);
                return true;
            }

        }

        doesUnitNeedAnalysisSummary.put(inUnit,false);
        return false;
    }

}
