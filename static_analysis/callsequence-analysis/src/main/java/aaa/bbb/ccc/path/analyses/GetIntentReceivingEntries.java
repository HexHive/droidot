package aaa.bbb.ccc.path.analyses;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import aaa.bbb.ccc.Utils;
import soot.*;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class GetIntentReceivingEntries {

    String apkFilePath;
    public static String androidJar = System.getenv("ANDROID_HOME");

    @Parameter(description="APK",required=true)
    private List<String> parameters = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        GetIntentReceivingEntries d = new GetIntentReceivingEntries();
        JCommander jCommander = new JCommander(d, args);
        jCommander.setProgramName("JCommanderGetIntentReceivingEntries");

        String newLine = System.getProperty("line.separator");

        String apkFilePath = d.parameters.get(0);
        File apk = new File(apkFilePath);
        String apkName = apk.getName();
        G.reset();

        FileWriter outputPerAPk = new FileWriter("eval/"+apkName+".entries");
        outputPerAPk.write("method signature"+newLine);
        outputPerAPk.flush();

        Utils.applyWholeProgramSootOptions(apkFilePath);
        for (SootClass curClass : Scene.v().getApplicationClasses()) {
            if (curClass.isJavaLibraryClass()) {
                continue;
            }
            if (curClass.isLibraryClass()) {
                continue;
            }
            if (!curClass.isApplicationClass()) {
                continue;
            }

            List<SootMethod> methods = new ArrayList<>(curClass.getMethods());
            for (SootMethod method : methods) {

                if (!Utils.isUserMethod(method)) {
                    continue;
                }

                // filter will entry method that retrieves Intent
                if (!method.getName().startsWith("on") && !method.getName().startsWith("finish")) {
                    // Components: Activity, Service, Broadcast Receiver
                    // not a lifecycle method
                    continue;
                }
                if (method.getDeclaringClass().getSuperclass().getName().startsWith("android.")) {
                    // Android lifecycle method
                    List<Type> types = method.getParameterTypes();
                    Boolean argIsIntent = false;
                    for (Type type : types) {
                        if (type.toString().equals("android.content.Intent")) {
                            // Android lifecycle method with Intent as a parameter
                            outputPerAPk.write(method.getSignature()+newLine);
                            outputPerAPk.flush();
                            argIsIntent = true;
                            break;
                        }
                    }
                    if (!argIsIntent) {
                        // check for Activity entry method that retrieves Intent
                        String superclassName = method.getDeclaringClass().getSuperclass().getName();
                        if (superclassName.contains("Activity") ||
                                superclassName.startsWith("android.support")) {
                            // only Activity has getIntent()
                            Boolean containsGetIntent = checkBody(method);
                            if (containsGetIntent) {
                                // body of methods contain "getIntent"
                                outputPerAPk.write(method.getSignature()+newLine);
                                outputPerAPk.flush();
                            }
                        }
                    }
                } else {
                    // check for Activity entry method that retrieves Intent
                    if (method.getDeclaringClass().getSuperclass().getName().contains("Activity")) {
                        // only Activity has getIntent()
                        Boolean containsGetIntent = checkBody(method);
                        if (containsGetIntent) {
                            // body of methods contain "getIntent"
                            outputPerAPk.write(method.getSignature()+newLine);
                            outputPerAPk.flush();
                        }
                    }
                }
            }
        }

        outputPerAPk.close();
    }

    private static Boolean checkBody(SootMethod method) {
        Body b;
        b = method.retrieveActiveBody();
        PatchingChain<Unit> units = b.getUnits();
        if (units.toString().contains("getIntent()")) {
            return true;
        } else {
            return false;
        }
        /*
        Body b;
        b = method.retrieveActiveBody();
        PatchingChain<Unit> units = b.getUnits();
        for (Unit u : units) {
            Stmt s = (Stmt) u;
            if (u instanceof AssignStmt) {
                AssignStmt assignStmt = (AssignStmt) u;
                if (assignStmt.getRightOp() instanceof InvokeExpr) {
                    InvokeExpr ie = (InvokeExpr)assignStmt.getRightOp();
                    SootMethod calledMethod = ie.getMethod();
                    if (calledMethod.getName().equals("getIntent")) {
                        return true;
                    }
                }
            } else if (s.containsInvokeExpr()) {
                InvokeExpr ie = s.getInvokeExpr();
                SootMethod calledMethod = ie.getMethod();
                if (calledMethod.getSignature().equals("<android.app.Activity: android.content.Intent getIntent()>")) {
                    return true;
                }
            }
        }
        return false;
         */
    }

}
