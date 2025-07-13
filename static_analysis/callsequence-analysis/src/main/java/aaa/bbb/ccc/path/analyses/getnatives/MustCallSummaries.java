package aaa.bbb.ccc.path.analyses.getnatives;

import aaa.bbb.ccc.path.analyses.TargetedPathTransformerJni;
import heros.solver.Pair;
import soot.Unit;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


/**
 *  MustCall Summaries for a callee
 */
public class MustCallSummaries {

    public String calleeName;

    public List<Pair<String,List<String>>> calls;

    public MustCallSummaries(String calleeName, List<Pair<String,List<String>>> calls) {
        this.calleeName = calleeName;
        this.calls = calls;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        MustCallSummaries callsSum = (MustCallSummaries) o;

        if (!calleeName.equals(callsSum.calleeName)) return false;
        if (!calls.equals(callsSum.calls)) return false;
        return true;
    }

    @Override
    public int hashCode() {
        int result = calleeName.hashCode();
        result = 31 * result + calls.hashCode();
        return result;
    }

}
