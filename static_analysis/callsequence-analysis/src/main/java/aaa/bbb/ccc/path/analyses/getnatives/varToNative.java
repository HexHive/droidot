package aaa.bbb.ccc.path.analyses.getnatives;

import java.util.List;

public class varToNative {
    public String name;
    public Integer argPos;
    public String varName;  // z3 variable name

    public boolean isIntent;

    public List<String> z3Files;

    public varToNative(String className, String lineNumber, Integer argPos, String varName, boolean isIntent){
        this.name = className+"_"+lineNumber;
        this.argPos = argPos;
        this.varName = varName;
        this.isIntent = isIntent;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        varToNative intent = (varToNative) o;

        if (!name.equals(intent.name)) return false;
        if (argPos != intent.argPos) return false;
        if (!varName.equals(intent.varName)) return false;
        if (isIntent != intent.isIntent) return false;
        return true;
    }

    @Override
    public int hashCode() {
        int result = name.hashCode();
        result = 31 * result + argPos.hashCode();
        result = 31 * result + varName.hashCode();
        if (isIntent) {
            result += 1;
        }
        return result;
    }

}
