package aaa.bbb.ccc.path.analyses.getnatives.mustcall;

import aaa.bbb.ccc.Utils;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.SpecialInvokeExpr;
import soot.jimple.Stmt;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.ForwardFlowAnalysis;

import java.util.*;

public class MustCallIntra extends ForwardFlowAnalysis<Unit, FlowSet<String>> {
    private static final FlowSet<String> EMPTY_SET = new ArraySparseSet<String>();
    private final Map<Unit, FlowSet<String>> unitToGenerateSet;

    public MustCallIntra(UnitGraph graph) {
        super(graph);
        this.unitToGenerateSet = new HashMap<Unit, FlowSet<String>>(graph.size() * 2 + 1, 0.7f);

        Iterator unitIt = graph.iterator();
        while (unitIt.hasNext()){
            Unit s = (Unit) unitIt.next();
            Stmt ss = (Stmt) s;
            FlowSet genSet = EMPTY_SET.emptySet();

            if (ss.containsInvokeExpr()) {
                InvokeExpr ie = ss.getInvokeExpr();
                if (ie instanceof SpecialInvokeExpr) {
                    // method call to Constructor or static initializer
                    continue;
                }
                SootMethod method = ie.getMethod();
                if (!Utils.isAndroidMethod(method)) {
                    String methodName = method.getSignature();
                    genSet.add(methodName, genSet);
                }
            }
            unitToGenerateSet.put(s, genSet);
        }
        doAnalysis();
    }

    @Override
    protected void flowThrough(FlowSet inSet, Unit unit, FlowSet outSet) {
        inSet.union(unitToGenerateSet.get(unit), outSet);
    }

    @Override
    protected FlowSet<String> newInitialFlow() {
        return EMPTY_SET.clone();
    }

    @Override
    protected FlowSet<String> entryInitialFlow() {
        return EMPTY_SET.clone();
    }

    @Override
    protected void merge(FlowSet<String> in1, FlowSet<String> in2, FlowSet<String> out) {
        in1.intersection(in2, out);
    }

    @Override
    protected void copy(FlowSet source, FlowSet dest) {
        source.copy(dest);
    }
}