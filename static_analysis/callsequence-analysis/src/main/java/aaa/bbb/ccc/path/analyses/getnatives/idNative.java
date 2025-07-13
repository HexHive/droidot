package aaa.bbb.ccc.path.analyses.getnatives;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.Utils;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Stmt;
import soot.options.Options;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;


public class idNative {
    public final static String USER_HOME = System.getProperty("user.home");
    public final static String androidJAR = System.getenv("ANDROID_HOME") + File.separator +"android-32" + File.separator + "android.jar";
    public static String androidJar = USER_HOME + File.separator +
            "AppData" + File.separator +
            "Local" + File.separator +
            "Android" + File.separator +
            "Sdk" + File.separator + "platforms";

    public static List<nativeFuncInfo> main(String apkFilePath, SootMethod method)
    {
        String apkName = Utils.getApkJsonNameFromPath(apkFilePath);
        List<nativeFuncInfo> nativeFuncs = new ArrayList<nativeFuncInfo>();;
        Dictionary<String,String> funcToLib = new Hashtable<>(); 
        if (Utils.isAndroidMethod(method))
            return nativeFuncs;

        //     right now not being used, but will follow up with req's to see
        //     what we want to do with these libraries; debug in output for now
        PatchingChain<Unit> us = method.getActiveBody().getUnits();
        if (us.toString().contains("java.lang.System: void loadLibrary")) {
            for (Unit u : us) {
                if (u.toString().contains("loadLibrary")) {
                    System.out.println("Found a library");
                    System.out.println(u);
                    funcToLib.put(method.getDeclaringClass().getName(), u.getUseBoxes().get(0).getValue().toString().replace("\"", ""));
                }
            }
        }

        Stmt su;
        for (Unit u : method.getActiveBody().getUnits()) {
            su = (Stmt) u;
            if (su.containsInvokeExpr()) {
                InvokeExpr ie = su.getInvokeExpr();
                SootMethod calledMethod = ie.getMethod();
                if (Utils.isAndroidMethod(calledMethod))
                    continue;
                if (calledMethod.getDeclaration().contains(" native ")) {
                    // current method is a JNI call
                    List<Type> params = calledMethod.getParameterTypes();
                    // map list of type to list of string
                    List<String> paramsStr = params.stream()
                            .map(object -> Objects.toString(object, null))
                            .collect(Collectors.toList());
                    //     currently implemented as single string, but can be extended to an ArrayList
                    //     mapping between method <-> class <-> library
                    String libStr = "";
                    if (funcToLib.get(calledMethod.getDeclaringClass().getName()) != null) {
                        libStr = funcToLib.get(calledMethod.getDeclaringClass().getName());
                    }
                    nativeFuncInfo curNativeFunc = new nativeFuncInfo(method.getSignature(),
                            u.toString(),
                            method.getDeclaringClass().getName(),
                            calledMethod.getName(),
                            String.valueOf(u.getJavaSourceStartLineNumber()),
                            calledMethod.getSignature(),
                            paramsStr);
                    nativeFuncs.add(curNativeFunc);
                }
            }
        }

        /*
        try {
            Writer writer = new FileWriter("nativesAnalysis"+File.separator+apkName, true);
            Gson gson = new GsonBuilder().disableHtmlEscaping().create();
            String json = gson.toJson(nativeFuncs);
            writer.write(json);
            writer.flush();
            writer.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
         */

        return nativeFuncs;
    }

    public static List<nativeFuncInfo> main(String apkFilePath, List<SootMethod> rtoMethods, boolean isODCG)
    {

        String apkName = Utils.getApkJsonNameFromPath(apkFilePath);
        List<nativeFuncInfo> nativeFuncs = new ArrayList<nativeFuncInfo>();
        Dictionary<String,String> funcToLib = new Hashtable<>(); 

        System.out.println("### Analyzing APK: " + apkFilePath);

        for (SootMethod method : rtoMethods) {
            if (Utils.isAndroidMethod(method))
                continue;

            //     right now not being used, but will follow up with req's to see
            //     what we want to do with these libraries; debug in output for now
            PatchingChain<Unit> us = method.getActiveBody().getUnits();
            String llString = "staticinvoke <java.lang.System: void loadLibrary(java.lang.String)>";
            if (us.toString().contains(llString)) {
                for (Unit u : us) {
                    String uS = u.toString();
                    if (u instanceof InvokeStmt && uS.startsWith("static")) {
                        System.out.println("Found a library");
                        System.out.println(u);
                        funcToLib.put(method.getDeclaringClass().getName(), u.getUseBoxes().get(0).getValue().toString().replace("\"", ""));
                    }
                }
            }

            Stmt su;
            for (Unit u : method.getActiveBody().getUnits()) {
                su = (Stmt) u;
                if (su.containsInvokeExpr()) {
                    InvokeExpr ie = su.getInvokeExpr();
                    SootMethod calledMethod = ie.getMethod();
                    if (Utils.isAndroidMethod(calledMethod))
                        continue;
                    if (calledMethod.getDeclaration().contains(" native ")) {
                        // current method is a JNI call
                        List<Type> params = calledMethod.getParameterTypes();
                        // map list of type to list of string
                        List<String> paramsStr = params.stream()
                                .map(object -> Objects.toString(object, null))
                                .collect(Collectors.toList());
                        //     currently implemented as single string, but can be extended to an ArrayList
                        //     mapping between method <-> class <-> library
                        String libStr = "";
                        if (funcToLib.get(calledMethod.getDeclaringClass().getName()) != null) {
                            libStr = funcToLib.get(calledMethod.getDeclaringClass().getName());
                        }
                        nativeFuncInfo curNativeFunc = new nativeFuncInfo(method.getSignature(),
                                u.toString(),
                                method.getDeclaringClass().getName(),
                                calledMethod.getName(),
                                String.valueOf(u.getJavaSourceStartLineNumber()),
                                calledMethod.getSignature(),
                                paramsStr);
                        nativeFuncs.add(curNativeFunc);
                    }
                }

            }
        }

        if (!isODCG) {
            try {
                Writer writer = new FileWriter("nativesAnalysis" + File.separator + apkName);
                Gson gson = new GsonBuilder().disableHtmlEscaping().create();
                String json = gson.toJson(nativeFuncs);
                writer.write(json);
                writer.flush();
                writer.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        return nativeFuncs;
    }
}
