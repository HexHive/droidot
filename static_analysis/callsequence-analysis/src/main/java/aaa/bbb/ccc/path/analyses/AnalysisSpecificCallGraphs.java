package aaa.bbb.ccc.path.analyses;

import com.google.common.collect.Lists;
import aaa.bbb.ccc.Utils;
import soot.*;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.Edge;
import soot.tagkit.StringTag;
import soot.tagkit.Tag;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.FlowSet;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public class AnalysisSpecificCallGraphs {

    String apkFilePath;
    //List<String> methodsSeen = new ArrayList<>();
    Boolean handleOnActivityResult = false;
    Boolean intentDependentExtractionOn = false;

    public AnalysisSpecificCallGraphs(String apkFilePath) {
        G.reset();  // G.reset() has executed when TargetedPathTransformerSp is instiantiated
        this.apkFilePath = apkFilePath;
    }

    public List<List<SootMethod>> callgraphs = new CopyOnWriteArrayList<List<SootMethod>>();

    public List<List<SootMethod>> main(Boolean payloadAsArg) {
        // list of on-demand callgraphs in topological order
        // each callgraph in topological order is represented as a list
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
                if (!handleOnActivityResult) {
                    if (method.getName().startsWith("onActivityResult")) {
                        // filter for onActivityResult since whole-program does not process this
                        continue;
                    }
                }

                List<SootMethod> rtoCg = null;
                if (method.getDeclaringClass().getSuperclass().getName().startsWith("android.")) {
                    // Android lifecycle method
                    List<Type> types = method.getParameterTypes();
                    Boolean argIsIntent = false;
                    List<String> intentRelatedParams = new ArrayList<>();
                    for (Type type : types) {
                        // initialize intentRelatedParams
                        intentRelatedParams.add("0");
                    }
                    int idx = 0;
                    for (Type type : types) {
                        if (type.toString().equals("android.content.Intent")) {
                            // Android lifecycle method with Intent as a parameter
                            // taint Intent argument
                            intentRelatedParams.add(idx, "2");
                            String intentRelatedParamsStr = String.join(",", intentRelatedParams);
                            Tag t = new StringTag(intentRelatedParamsStr);
                            //Tag a = new AnnotationTag(intentRelatedParamsStr);
                            method.addTag(t);
                            rtoCg = createCg(method, payloadAsArg);
                            argIsIntent = true;
                            break;
                        }
                        idx += 1;
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
                                rtoCg = createCg(method, payloadAsArg);
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
                            rtoCg = createCg(method, payloadAsArg);
                        }
                    }
                }

                if ( rtoCg != null && !rtoCg.isEmpty()) {
                    callgraphs.add(rtoCg); // constructed an on-demand callgraph
                }
            }
        }
        return callgraphs;
    }

    private Boolean checkBody(SootMethod method) {
        Body b;
        b = method.retrieveActiveBody();
        PatchingChain<Unit> units = b.getUnits();
        if (units.toString().contains("getIntent()")) {
            return true;
        } else {
            return false;
        }
        /*
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

    private InvokeExpr getInvokeExpr(Stmt s) {
        if (s instanceof AssignStmt) {
            AssignStmt assignStmt = (AssignStmt) s;
            if (assignStmt.getRightOp() instanceof InvokeExpr) {
                return (InvokeExpr)assignStmt.getRightOp();
            }
        } else if (s.containsInvokeExpr()) {
            return s.getInvokeExpr();
        }
        return null;
    }

    private List<SootMethod> createCg(SootMethod method, Boolean payloadAsArg) {
        // argument method is root of a new callgraph
        // return callgraph, cg, in reverse topological order
        // TODO: test different callgraph scenarios
        List<SootMethod> topologicalOrderMethods = new ArrayList<SootMethod>();
        Stack<SootMethod> methodsToAnalyze = new Stack<SootMethod>();
        methodsToAnalyze.push(method);  // worklist begins with root

        while (!methodsToAnalyze.isEmpty()) {
            SootMethod wipMethod = methodsToAnalyze.pop();
            // also filter methods already seen
            //if (!topologicalOrderMethods.contains(wipMethod) && !methodsSeen.contains(wipMethod.getSignature())) {
            if (!topologicalOrderMethods.contains(wipMethod)) {
                Body b;
                UnitGraph ug;
                try {
                    b = wipMethod.retrieveActiveBody();
                } catch (OutOfMemoryError e) {
                    return new ArrayList<>();
                } catch (Exception e) {
                    continue;
                }
                PatchingChain<Unit> units = b.getUnits();
                if (units.size() != 0) {
                    // also filter methods already seen
                    topologicalOrderMethods.add(wipMethod);
                    //methodsSeen.add(wipMethod.getSignature());

                    List<String> taintedArgs;
                    if (wipMethod.hasTag("StringTag")) {
                        // wipMethod has tainted parameters
                        // taint whatever those parameters taint
                        String taintedArgsStr = String.valueOf(wipMethod.getTag("StringTag"));
                        taintedArgs = Arrays.asList(taintedArgsStr.split("\\s*,\\s*"));
                    } else {
                        taintedArgs = new ArrayList<>();
                    }
                    ug = new ExceptionalUnitGraph(b);

                    //IntentPropagationGranular ip = new IntentPropagationGranular(ug, wipMethod, taintedArgs, intentDependentExtractionOn);
                    IntentPropagation ip = new IntentPropagation(ug, wipMethod, taintedArgs, intentDependentExtractionOn);
                    for (Unit u : units) {
                        // add callee to methodsToAnalyze if
                        // (1) callee argument is data dependent on Intent
                        // (2) callee return value is data dependent on Intent
                        // for (1), we annotate the method
                        // for (2), we annotate the return stmt/unit
                        Stmt s = (Stmt) u;
                        if (s.containsInvokeExpr()) {
                            Boolean extendToCallee = false;
                            InvokeExpr ie = getInvokeExpr(s);
                            if (ie == null) {
                                continue;
                            }
                            if (!Utils.isUserMethod(ie.getMethod())) {
                                continue;
                            }
                            // iflow for Intent flow hahaa
                            FlowSet iflow = (FlowSet) ip.getFlowBefore(u);
                            if (!iflow.isEmpty()) {
                                // Values data dependent on Intent flow to this callee instruction
                                // Check if callee parameters intersect with those Values
                                List<String> intentRelatedParams = new ArrayList<>();
                                if (!payloadAsArg) {
                                    // extend callee if a callee paramter is an Intent
                                    List<Type> paramTypes = ie.getMethod().getParameterTypes();
                                    for (Type t : paramTypes) {
                                        if (t.toString().equals("android.content.Intent")) {
                                            // arg is data dependent on Intent
                                            intentRelatedParams.add("2");
                                            extendToCallee = true;
                                        } else {
                                            // arg is not data dependent on Intent
                                            intentRelatedParams.add("0");
                                        }
                                    }
                                } else {
                                    // extend callee if a callee parameter is data-dependent on Intent
                                    List<Value> args = ie.getArgs();
                                    for (Value arg : args) {
                                        //IntentPropagationGranular.IntentFact argFact = IntentPropagationGranular.containsWithoutAttrsRet(iflow, arg.toString());
                                        //if (argFact != null) {
                                        if (iflow.contains(arg.toString())) {
                                            // arg is data dependent on Intent
                                            if (arg.getType().toString().equals("android.content.Intent")) {
                                                // arg is Intent
                                                intentRelatedParams.add("2");
                                            } else {
                                                // arg is data-dependent on Intent
                                                intentRelatedParams.add("1");
                                                //if (argFact.hasAttr()) {
                                                //    intentRelatedParams.add("1:"+argFact.getAttr());
                                                //}
                                            }
                                            extendToCallee = true;
                                        } else {
                                            // arg is not data dependent on Intent
                                            intentRelatedParams.add("0");
                                        }
                                    }
                                }
                                if (extendToCallee) {
                                    // (1) add annotation on which arguments are data dependent on Intent
                                    // (2) add annotation on the callee statement for unitNeedsAnalysis
                                    // annotate for (1)
                                    SootMethod calleeMethod = ie.getMethod();
                                    String intentRelatedParamsStr = String.join(",", intentRelatedParams);
                                    Tag t = new StringTag(intentRelatedParamsStr);
                                    //Tag a = new AnnotationTag(intentRelatedParamsStr);
                                    calleeMethod.addTag(t);
                                    // extend callgraph
                                    methodsToAnalyze.add(calleeMethod);
                                    // annotate for (2)
                                    //Tag t2 = new StringTag("isIntentDependent");
                                    //u.addTag(t2);
                                }
                            }
                        }
                    }
                }

            }
        }
        return Lists.reverse(topologicalOrderMethods);
    }

}