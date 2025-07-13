package aaa.bbb.ccc.path.analyses.getnatives.mustcall;

import com.google.common.collect.Lists;
import org.javatuples.Pair;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;

import java.io.File;
import java.util.*;


public class MustCallBackend
{
    public String apkPath;
    public String enclosingMethod;
    public String methodCall;
    public final static String USER_HOME = System.getProperty("user.home");
    public static String androidJar = System.getenv("ANDROID_HOME");
    static String androidDemoPath = System.getProperty("user.dir") + File.separator + "demo" + File.separator + "Android";
    private Map<Edge,FlowSet> interMethodFlows = new HashMap<Edge,FlowSet>();
    private Map<SootMethod,FlowSet> intraMethodFlows = new HashMap<SootMethod,FlowSet>();

    public MustCallBackend(String apkFilePath, String enclosingMethod, String methodCall) {
        this.apkPath = apkFilePath;
        this.enclosingMethod = enclosingMethod;
        this.methodCall = methodCall;
    }

    public FlowSet<String> getMustCall(SootMethod method, String methodToGetFlow) {
        Body b = method.getActiveBody();
        UnitGraph ug = new BriefUnitGraph(method.getActiveBody());
        // perform intraprocedural analysis
        MustCallIntra mcAnalysis = new MustCallIntra(ug);

        FlowSet<String> currMustCallset = new ArraySparseSet<String>();
        int i = 0; // keep track of how many times an instruction called methodToGetFlow
        for (Unit unit : b.getUnits()) {
            Stmt stmt = (Stmt) unit;
            if (stmt.containsInvokeExpr()) {
                InvokeExpr ie = stmt.getInvokeExpr();
                if (ie.getMethod().getName().equals(methodToGetFlow)) {
                    //mustCallMethods = mcAnalysis.getFlowBefore(unit);
                    if (i == 0) {
                        // first flowset result. Just add all
                        currMustCallset.union(mcAnalysis.getFlowBefore(unit), currMustCallset);
                    } else {
                        // subsequent flowset is a must analysis
                        currMustCallset.intersection(mcAnalysis.getFlowBefore(unit), currMustCallset);
                    }
                    i ++;
                }
            }
        }
        return currMustCallset;
    }

    public boolean methodCallExists(SootMethod method, String methodcall) {
        PatchingChain<Unit> units = method.getActiveBody().getUnits();
        for (Unit u : units) {
            Stmt s = (Stmt) u;
            if (s.containsInvokeExpr()) {
                InvokeExpr ie = s.getInvokeExpr();
                if (ie.getMethod().getName().equals(methodcall)) {
                    return true;
                }
            }
        }
        return false;
    }

    public List<String> run() {
        SootMethod leafMethod = null;
        List<Pair<SootMethod,SootMethod>> methodsToProcess = new ArrayList<Pair<SootMethod,SootMethod>>();
        List<SootMethod> rtoMethods = new ArrayList<SootMethod>();
        Set<SootMethod> alreadyProcessedMethods = new LinkedHashSet<SootMethod>();

        CallGraph cg = Scene.v().getCallGraph();
        SootMethod method = Scene.v().getMethod(enclosingMethod);
        leafMethod = method;
        // TODO: make the second argument a signature?
        if (!methodCallExists(method, methodCall)) {
            return new ArrayList<String>();
        }
        FlowSet<String> mustCallsLeaf = getMustCall(method, methodCall);
        intraMethodFlows.put(leafMethod, mustCallsLeaf);
        alreadyProcessedMethods.add(leafMethod);
        Iterator<Edge> edges = cg.edgesInto(leafMethod);
        Edge curEdge = null;
        SootMethod curMethod = null;
        while (edges.hasNext()) {
            curEdge = edges.next();
            curMethod = (SootMethod) curEdge.getSrc();
            methodsToProcess.add(new Pair<SootMethod,SootMethod>(curMethod,leafMethod));
            rtoMethods.add(curMethod);
        }

        // processing the call chain to create summaries for each method in leafMethod's call chain path
        // backward walk
        // TODO: flowset string be method signature?
        SootMethod parentMethod;
        FlowSet<String> mustCalls;
        // breadth-first search by treating leafMethod as root node
        // the traversal will be in reverse topological ordering
        while (!methodsToProcess.isEmpty()) {
            Pair<SootMethod,SootMethod> methodInfo = methodsToProcess.remove(0);
            curMethod = methodInfo.getValue0();
            if (alreadyProcessedMethods.contains(curMethod)) {
                // can visit a method again if loops exist
                continue;
            }
            parentMethod = methodInfo.getValue1();
            mustCalls = getMustCall(curMethod,parentMethod.getName());
            intraMethodFlows.put(curMethod,mustCalls);
            alreadyProcessedMethods.add(curMethod);
            edges = cg.edgesInto(curMethod);
            while (edges.hasNext()) {
                curEdge = edges.next();
                SootMethod edgeMethod = (SootMethod) curEdge.getSrc();
                if (alreadyProcessedMethods.contains(edgeMethod)) {
                    // can visit a method again if loops exist
                    continue;
                }
                methodsToProcess.add(new Pair<SootMethod,SootMethod>(edgeMethod,curMethod));
                rtoMethods.add(edgeMethod);
            }
        }

        if (rtoMethods.isEmpty())
            // only contains original method, leafMethod
            // mustCallsLeaf
            return mustCallsLeaf.toList();
        // processing in topological order
        // forward analysis to combine the method summaries
        List<SootMethod> toMethods = Lists.reverse(rtoMethods);
        FlowSet<String> postEdgeSum = null;
        FlowSet<String> preEdgeSum = null;
        for (SootMethod m : toMethods) {
            FlowSet<String> mSum = intraMethodFlows.get(m);
            //processing pre edges
            Iterator<Edge> toEdges = cg.edgesInto(m);
            FlowSet<String> toEdgesSum = new ArraySparseSet<String>();
            FlowSet<String> curEdgeSum = null;
            int i = 0;
            while (toEdges.hasNext()) {
                Edge toEdge = toEdges.next();
                if (interMethodFlows.containsKey(toEdge)) {
                    // edge connected to previously processed method
                    curEdgeSum = interMethodFlows.get(toEdge);
                    if (i == 0) {
                        // first iteration, the result FlowSet will always be empty
                        // if intersection, then result will always be empty
                        toEdgesSum.union(curEdgeSum, toEdgesSum);
                    } else {
                        toEdgesSum.intersection(curEdgeSum, toEdgesSum);
                    }
                }
                i ++;
            }
            mSum.union(toEdgesSum,mSum);
            intraMethodFlows.put(m,mSum);
            // processing post edge
            toEdges = cg.edgesOutOf(m);
            while (toEdges.hasNext()) {
                Edge toEdge = toEdges.next();
                if (alreadyProcessedMethods.contains(toEdge.getTgt())) {
                    // there can be edges out of m that does not lead to desired method
                    interMethodFlows.put(toEdge, mSum);
                }
            }
        }
        // combine all edge summaries going into desired method
        Iterator<Edge> finalEdges = cg.edgesInto(leafMethod);
        FlowSet<String> toEdgesSum = new ArraySparseSet<String>();
        FlowSet<String> curEdgeSum = null;
        int i = 0;
        while (finalEdges.hasNext()) {
            Edge edge = finalEdges.next();
            curEdgeSum = interMethodFlows.get(edge);
            if (i == 0) {
                toEdgesSum.union(curEdgeSum, toEdgesSum);
            } else {
                toEdgesSum.intersection(curEdgeSum, toEdgesSum);
            }
            i ++;
        }
        // combine combined interprocedural edge summaries into leafMethod
        mustCallsLeaf.union(toEdgesSum,mustCallsLeaf);
        return mustCallsLeaf.toList();
    }
}

