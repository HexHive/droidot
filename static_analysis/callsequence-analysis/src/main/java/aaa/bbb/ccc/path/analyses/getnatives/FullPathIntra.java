package aaa.bbb.ccc.path.analyses.getnatives;

import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.SpecialInvokeExpr;
import soot.jimple.Stmt;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.BackwardFlowAnalysis;
import soot.toolkits.scalar.FlowSet;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class FullPathIntra extends BackwardFlowAnalysis<Unit, FlowSet<String>> {

    private static final FlowSet<String> EMPTY_SET = new ArraySparseSet<String>();
    private final Map<Unit, FlowSet<String>> unitToGenerateSet;

    public FullPathIntra(UnitGraph graph, Set<Unit> markedUnits) {
        super(graph);
        this.unitToGenerateSet = new HashMap<Unit, FlowSet<String>>(graph.size() * 2 + 1, 0.7f);

        Iterator unitIt = graph.iterator();
        while (unitIt.hasNext()){
            Unit s = (Unit) unitIt.next();
            FlowSet genSet = EMPTY_SET.emptySet();

            if (markedUnits.contains(s)) {
                genSet.add(1, genSet);
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
        // Backward MUST Analysis
        in1.intersection(in2, out);
    }

    @Override
    protected void copy(FlowSet source, FlowSet dest) {
        source.copy(dest);
    }

}
