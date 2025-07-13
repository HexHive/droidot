package aaa.bbb.ccc.path.analyses.getnatives;

import aaa.bbb.ccc.path.analyses.TargetedPathTransformerJni;
import soot.Unit;

import java.util.*;
import java.util.stream.Collectors;


/**
 *  JNI call sequences per Unit (ie, set of call sequences that reach provided Unit)
 */
public class JniCallsSummaries {

    public String callerName;

    public String lineNumber;

    public String instruction;

    public Set<List<String>> callSequences;

    public JniCallsSummaries(String callerName, String lineNumber, String instruction, List<TargetedPathTransformerJni.UnitPathJNI> callSequences) {
        this.callerName = callerName;
        this.lineNumber = lineNumber;
        this.instruction = instruction;
        this.callSequences = new LinkedHashSet<List<String>>();
        for (TargetedPathTransformerJni.UnitPathJNI upJNI : callSequences) {
            List<String> currSeq = upJNI.getPathJNI().stream()
                    .map(Unit::toString)
                    .collect(Collectors.toList());
            this.callSequences.add(currSeq);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        JniCallsSummaries callsSum = (JniCallsSummaries) o;

        if (!callerName.equals(callsSum.callerName)) return false;
        if (!lineNumber.equals(callsSum.lineNumber)) return false;
        if (!instruction.equals(callsSum.instruction)) return false;
        return callSequences.equals(callsSum.callSequences);
    }

    @Override
    public int hashCode() {
        int result = callerName.hashCode();
        result = 31 * result + lineNumber.hashCode();
        result = 31 * result + instruction.hashCode();
        result = 31 * result + callSequences.hashCode();
        return result;
    }

}
