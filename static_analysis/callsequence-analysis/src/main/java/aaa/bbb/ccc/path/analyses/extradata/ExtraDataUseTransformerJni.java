package aaa.bbb.ccc.path.analyses.extradata;

import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerJni;
import soot.*;
import soot.jimple.*;
import org.javatuples.Pair;

import java.util.*;

public class ExtraDataUseTransformerJni extends TargetedPathTransformerJni {

    Map<Unit,Boolean> doesUnitNeedAnalysisSummary = new LinkedHashMap<Unit,Boolean>();
    Set<String> classesNeedAnalysis = new LinkedHashSet<String>();

    public ExtraDataUseTransformerJni(String apkFilePath) {
        super(apkFilePath);
    }

    @Override
    public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit inUnit, Map<String, Pair<Boolean,Map<Unit, List<UnitPathJNI>>>> methodSummaries, boolean isIntra) {
        if (Utils.isAndroidMethodAndroLib(method)) {
            return false;
        }
        /*
        if (method.getName().startsWith("access$")) {
            return false;
        }
         */

        if (doesUnitNeedAnalysisSummary.containsKey(inUnit)) {
            // previously has already computed whether unit `inUnit` needs analysis or not
            return doesUnitNeedAnalysisSummary.get(inUnit);
        }

        Stmt inStmt = (Stmt) inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            SootMethod calledMethod = ie.getMethod();
            // check if unit is a JNI call
            if (Utils.isAndroidMethodAndroLib(calledMethod)) {
                // skip non-JNI methods
                // str: .equals
                return false;
            }
            if (calledMethod.getDeclaration().contains(" native ")) {
                doesUnitNeedAnalysisSummary.put(inUnit, true);
                return true;
            }
            if (!isIntra) {
                // check if it is a method call that transitively calls a method that contains JNI call
                if (methodSummaries.containsKey(calledMethod.getSignature())) {
                    doesUnitNeedAnalysisSummary.put(inUnit, true);
                    return true;
                }

                if (calledMethod.getSignature().startsWith("<android.os.AsyncTask: android.os.AsyncTask execute(")) {
                    // handle AsyncTask
                   return true;
                }
                if (calledMethod.getSignature().startsWith("<android.os.AsyncTask: void publishProgress(")) {
                    // publishProgress inside doInBackground, which implicitly calls onProgressUpdate
                    return true;
                }
                if (calledMethod.getSignature().equals("<java.lang.Runnable: void run()>")) {
                    // handle Runnable
                    return true;
                }
            }
        }

        doesUnitNeedAnalysisSummary.put(inUnit, false);
        return false;
    }

}
