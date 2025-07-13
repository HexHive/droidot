package aaa.bbb.ccc.path.analyses;

import aaa.bbb.ccc.Utils;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public class onDemandCallGraphs {

    String apkFilePath;
    Set<String> sinksMethodSignatures = new LinkedHashSet<String>();
    Set<String> sourcesMethodSignatures = new LinkedHashSet<String>();
    public String cpre = null;

    public onDemandCallGraphs(String apkFilePath, String srcsnsinksFilePath) {
        this.apkFilePath = apkFilePath;
        try(BufferedReader br = new BufferedReader(new FileReader(srcsnsinksFilePath))) {
            String sMethodSig = br.readLine();
            while (sMethodSig != null) {
                String[] sig = sMethodSig.split(" -> ");
                if (sig[1].equals("_SINK_")) {
                    sinksMethodSignatures.add(sig[0]);
                } else {
                    // NOT source or sink signature!
                    throw new RuntimeException();
                }
                sMethodSig = br.readLine();
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public onDemandCallGraphs(String apkFilePath) {
        this.apkFilePath = apkFilePath;
    }

    //public List<List<SootMethod>> callgraphs = new CopyOnWriteArrayList<List<SootMethod>>();
    public List<List<String>> callgraphs = new CopyOnWriteArrayList<List<String>>();

    protected List<List<String>> main() {
        // list of on-demand callgraphs in topological order
        // each callgraph in topological order is represented as a list
        Utils.applyWholeProgramSootOptions(apkFilePath);
        Hierarchy h = Scene.v().getActiveHierarchy();

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

                /*
                Body b;
                try {
                    b = method.retrieveActiveBody();
                } catch (OutOfMemoryError e) {
                    continue;
                }
                 */
                if (!createCg(method)) {
                    continue;
                }

                //System.out.println("^ " + method.getSignature() + " ^ " + method.getDeclaringClass().getFilePath() );

                // if we include this, then only one calling context is saved
                // actually, no it is fine since the check happens in a bottom-up manner
                Boolean methodExists = false;
                for (Iterator<List<String>> odcgIter = callgraphs.iterator(); odcgIter.hasNext(); ) {
                    List<String> odcg = odcgIter.next();
                    if (odcg.contains(method)) {
                        // method is already part of an existing on-demand callgraph
                        methodExists = true;
                        break;
                    }
                }
                if (methodExists) {
                    continue;
                }

                // create partial callgraph starting from b
                Set<String> visited = new LinkedHashSet<>(); // methods already visited
                List<String> cg = new CopyOnWriteArrayList<>();
                Stack<SootMethod> worklist = new Stack<SootMethod>();
                worklist.push(method);
                List<SootMethod> curCallees;

                while (!worklist.isEmpty()) {
                    SootMethod wMethod = worklist.pop();
                    visited.add(wMethod.getSignature());
                    cg.add(wMethod.getSignature());
                    curCallees = getCallees(wMethod, h);
                    for (Iterator<SootMethod> calleeIter = curCallees.iterator(); calleeIter.hasNext(); ) {
                        SootMethod callee = calleeIter.next();
                        if (Utils.isUserMethod(callee)) {
                            if (callee.isConcrete() && !visited.contains(callee.getSignature())) {
                                // check if callee is already part of an existing on-demand callgraph
                                //List<SootMethod> odcgMatch = null;
                                List<String> odcgMatch = null;
                                for (Iterator<List<String>> odcgIter = callgraphs.iterator(); odcgIter.hasNext(); ) {
                                    List<String> odcg = odcgIter.next();
                                    // callee must be the root of an existing on-demand callgraph
                                    if (odcg.get(0).equals(callee.getSignature())) {
                                        odcgMatch = odcg;
                                        // combine existing callgraph with callee with current cg
                                        // since existing callgraph is subsumed by current cg
                                        cg.addAll(odcg);
                                        break;
                                    }
                                }
                                if (odcgMatch == null) {
                                    // if callee is not part of an existing on-demand callgraph, then push to worklist
                                    worklist.push(callee);
                                } /*else {
                                    // remove existing callgraph
                                    callgraphs.remove(odcgMatch);
                                }*/
                            }
                        }
                    }
                }
                if (!cg.isEmpty()) {
                    callgraphs.add(cg); // constructed an on-demand callgraph
                }
            }
        }
        return callgraphs;
    }

    private synchronized List<SootMethod> getCallees(SootMethod m, Hierarchy h) {
        String mClass = m.getDeclaringClass().getFilePath();
        List<SootMethod> callees = new ArrayList<SootMethod>();
        Body body = m.retrieveActiveBody();
        Iterator<Unit> us = body.getUnits().snapshotIterator();
        while (us.hasNext()) {
            Unit u = us.next();
            Stmt s = (Stmt) u;
            if (s.containsInvokeExpr()) {
                InvokeExpr ie = s.getInvokeExpr();
                SootMethod calledMethod = ie.getMethod();
                String calledMethodClass = calledMethod.getDeclaringClass().getFilePath();
                if (mClass.equals(calledMethodClass)) {
                    // callee in the same class
                    SootClass mc =  m.getDeclaringClass();
                    SootClass mc_og = mc;
                    while (mc.hasOuterClass()) {
                        // use outer class' hierarchy. Inner class is usually private
                        mc = mc.getOuterClass();
                    }
                    String calledMethodSig = calledMethod.getSubSignature();
                    // identify subclass whose method is called instead for calledMethod
                    /*if (!mc.isInterface()) {
                        for (SootClass sc : h.getDirectSubclassesOf(mc)) {
                            // only has direct subclass for non-interface mc
                            List<SootMethod> cms = new ArrayList<>(sc.getMethods()); // to avoid concurrent exception
                            for (SootMethod scm : cms) {
                                if (scm.getSubSignature().equals(calledMethodSig)) {
                                    if (Utils.isUserMethod(calledMethod)) {
                                        callees.add(scm);
                                    }
                                }
                            }
                        }
                    }*/
                }
                if (Utils.isUserMethod(calledMethod)) {
                    callees.add(calledMethod);
                }
            }
        }
        return callees;
    }

    private boolean createCg(SootMethod method) {
        // create cg if (1) body contains JNI calls or (2) is a sink
        Body b;
        try {
            b = method.retrieveActiveBody();
        } catch (OutOfMemoryError e) {
            return false;
        }
        // create cg if (1) body contains JNI calls or (2) is a sink
        Iterator<Unit> us = b.getUnits().snapshotIterator();
        while (us.hasNext()) {
            Unit currUnit = us.next();
            Stmt currStmt = (Stmt) currUnit;
            if (currStmt.containsInvokeExpr()) {
                InvokeExpr ie = currStmt.getInvokeExpr();
                SootMethod calledMethod = ie.getMethod();
                // JNI native call
                if (calledMethod.getDeclaration().contains(" native ")) {
                    return true;
                }
                if (sourcesMethodSignatures.contains(calledMethod.getSignature())) {
                    return true;
                }
                /*
                // a sink (for reachability pass)
                for (String sink : sinksMethodSignatures) {
                    if (calledMethod.getSignature().equals(sink)) {
                        return true;
                    }
                }
                 */
            }
        }
        return false;
    }
}