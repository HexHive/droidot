package aaa.bbb.ccc.path.analyses;

import aaa.bbb.ccc.Utils;
import soot.Local;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.toolkits.graph.DirectedGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.BackwardFlowAnalysis;
import soot.toolkits.scalar.FlowSet;

import java.util.Iterator;

import soot.*;
import soot.util.*;
import java.util.*;
import soot.jimple.*;
import soot.toolkits.graph.*;
import soot.toolkits.scalar.*;


public class NoPostDom extends BackwardFlowAnalysis
{
    private static final FlowSet<String> EMPTY_SET = new ArraySparseSet<String>();
    private final Map<Unit, FlowSet<String>> unitToGenerateSet;

    protected void copy(Object src, Object dest)
    {
        FlowSet srcSet  = (FlowSet) src;
        FlowSet destSet = (FlowSet) dest;

        srcSet.copy(destSet);
    }

    protected void merge(Object src1, Object src2, Object dest)
    {
        FlowSet srcSet1 = (FlowSet) src1;
        FlowSet srcSet2 = (FlowSet) src2;
        FlowSet destSet = (FlowSet) dest;

        srcSet1.union(srcSet2, destSet);
    }

    protected void flowThrough(Object in, Object unit,
                               Object out)
    {
        FlowSet outSet = (FlowSet) out;
        FlowSet inSet  = (FlowSet) in;
        Unit s = (Unit) unit;
        inSet.union(unitToGenerateSet.get(s), outSet);
    }

    protected Object entryInitialFlow()
    {
        return EMPTY_SET.clone();
    }

    protected Object newInitialFlow()
    {
        return EMPTY_SET.clone();
    }

    public NoPostDom(DirectedGraph g, Set<Unit> onDemandApproved)
    {
        super(g);
        this.unitToGenerateSet = new HashMap<Unit, FlowSet<String>>(graph.size() * 2 + 1, 0.7f);

        Iterator unitIt = graph.iterator();
        while (unitIt.hasNext()){
            Unit s = (Unit) unitIt.next();
            FlowSet genSet = EMPTY_SET.emptySet();
            if (onDemandApproved.contains(s)) {
                genSet.add(s.toString(), genSet);
            }
            unitToGenerateSet.put(s, genSet);
        }
        doAnalysis();
    }
}