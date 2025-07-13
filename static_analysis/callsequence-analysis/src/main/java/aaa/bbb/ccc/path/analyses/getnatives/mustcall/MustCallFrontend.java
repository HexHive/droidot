/**
 * Identify all methods that MUST be called to reach a sink (e.g., JNI call)
 *
 * <p>Given a target method and a call instruction inside, this program will identify
 * all methods that must be called before it.</>
 *
 * <p>If the target method is not an entry point, this program will "walk up" the
 * callgraph in BFS fashion to analyze each relevant methods (methods in the path).
 * This way we can traverse in topological order from entry method to target method
 * to correctly combine all intraprocedural analysis results.</>
 *
 * <p>Intraprocedural analysis is a forward MUST analysis implemented in Soot Monotone
 * Framework.</>
 *
 */

package aaa.bbb.ccc.path.analyses.getnatives.mustcall;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.getnatives.MustCallSummaries;
import aaa.bbb.ccc.path.analyses.getnatives.nativeFuncInfo;
import heros.solver.Pair;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MustCallFrontend
{

    @Parameter(description="APK Signature Method",required=true)
    private List<String> parameters = new ArrayList<>();

    @Parameter(
            names = {"--intraonly", "-i"}
    )
    public boolean intraonly = false;

    public static void main(String apkFilePath, String methodName, List<nativeFuncInfo> nativeFuncs)
    {
        List<Pair<String,List<String>>> methodNameSum = new ArrayList<Pair<String,List<String>>>();
        for (nativeFuncInfo nativefunc : nativeFuncs) {
            if (nativefunc.nativeName.equals(methodName)) {
                MustCallBackend dp = new MustCallBackend(apkFilePath, nativefunc.callerName, methodName);
                List<String> mustCallMethods = dp.run();
                methodNameSum.add(new Pair<String,List<String>>(nativefunc.callerName, mustCallMethods));
            }
        }

        MustCallSummaries mcs = new MustCallSummaries(methodName, methodNameSum);
        String apkName = Utils.getApkJsonNameFromPath(apkFilePath);
        try {
            Writer writer = new FileWriter("nativesAnalysis"+ File.separator+"M_"+apkName);
            Gson gson = new GsonBuilder().disableHtmlEscaping().create();
            String json = gson.toJson(mcs);
            writer.write(json);
            writer.flush();
            writer.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}
