package aaa.bbb.ccc.path.analyses.getnatives;

import aaa.bbb.ccc.Config;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.SootMethod;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.options.Options;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.StronglyConnectedComponentsFast;
import soot.toolkits.graph.UnitGraph;

import java.util.Collections;
import java.util.List;

public class FindLoops {

    public final static String USER_HOME = System.getProperty("user.home");
    public static String androidJar = System.getenv("ANDROID_HOME");

    public static void prettyPrint(List<Stmt> toPrint, String method)
    {
        System.out.println("Current Method: "+method);
        for (Stmt instr: toPrint) {
            System.out.println("\t"+instr.toString());
        }
    }

    public static void main(String[] args)
    {
        String methodSignature = args[1];
        String calledMethodName = args[2];
        //System.out.println("'"+methodSignature+"'");
        //System.out.println("'"+calledMethodName+"'");

        System.out.println("### Analyzing APK: " + Config.apkFilePath);
        SootMethod method = Scene.v().getMethod(methodSignature);
        UnitGraph unitGraph = new ExceptionalUnitGraph(method.getActiveBody());
        StronglyConnectedComponentsFast connectedComponents = new StronglyConnectedComponentsFast(unitGraph);
        List<List<Stmt>> components = connectedComponents.getTrueComponents();
        if (components.size() >= 1) {
            for (List<Stmt> c : components) {
                for (Stmt s : c) {
                    if (s.containsInvokeExpr()) {
                        InvokeExpr ie = s.getInvokeExpr();
                        String currCalledMethod = ie.getMethod().getName();
                        if (currCalledMethod.equals(calledMethodName)) {
                            System.out.println(calledMethodName + " is in a loop");
                            return;
                        }
                    }
                }
            }
        }
        System.out.println(calledMethodName + " is NOT in a loop");
    }
}
