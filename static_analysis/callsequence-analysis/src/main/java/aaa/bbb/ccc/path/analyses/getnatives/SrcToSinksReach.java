package aaa.bbb.ccc.path.analyses.getnatives;

import aaa.bbb.ccc.path.analyses.TargetedPathTransformerJni;
import soot.Unit;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * Source to sink function trace
 */
public class SrcToSinksReach {

    public List<String> source;

    public List<String> sinkTrace;

    public SrcToSinksReach(List<String> source, List<String> sinkTrace) {
        this.source = new ArrayList<>();
        this.sinkTrace = new ArrayList<String>();
        for (String s : source) {
            this.source.add(s);
        }
        for (String sinkPath : sinkTrace) {
            this.sinkTrace.add(sinkPath);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SrcToSinksReach callsSum = (SrcToSinksReach) o;

        if (!source.equals(callsSum.source)) return false;
        if (!sinkTrace.equals(callsSum.sinkTrace)) return false;
        return true;
    }

    @Override
    public int hashCode() {
        int result = source.hashCode();
        result = 31 * result + sinkTrace.hashCode();
        return result;
    }

}
