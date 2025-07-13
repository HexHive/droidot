package aaa.bbb.ccc.path.analyses.getnatives;

import java.util.List;

public class nativeFuncInfo {
    public String callerName;
    public String name;
    public String instruction;
    public String lineNumber;
    public String nativeName;
    public String signature;
    public List<String> params;
    public List<String> callSequences;

    public nativeFuncInfo(String callerName, String instruction, String className, String nativeName, String lineNumber, String signature, List<String> params) {
        this.callerName = callerName;
        this.instruction = instruction;
        this.name = className+"_"+lineNumber;
        this.nativeName = nativeName;
        this.lineNumber = lineNumber;
        this.signature = signature;
        this.params = params;
    }

    @Override
    public String toString() {
        return "nativeFuncInfo{" +
                "callerName='" + callerName + '\'' +
                ", name='" + name + '\'' +
                ", instruction='" + instruction + '\'' +
                ", lineNumber='" + lineNumber + '\'' +
                ", nativeName='" + nativeName + '\'' +
                ", signature='" + signature + '\'' +
                ", params=" + params +
                '}';
    }
}
