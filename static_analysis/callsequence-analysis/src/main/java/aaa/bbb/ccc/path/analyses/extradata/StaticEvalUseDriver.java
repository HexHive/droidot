package aaa.bbb.ccc.path.analyses.extradata;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.model.Intent;
import aaa.bbb.ccc.path.analyses.*;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import soot.*;
import soot.options.Options;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class StaticEvalUseDriver {
    @Parameter(description = "APK", required = true)
    private List<String> parameters = new ArrayList<>();

    @Parameter(names = {"--functions", "-f"})
    private List<String> functions = new ArrayList<>();

    @Parameter(names = {"--parallel", "-p"}, description = "enables parallel per-target-statement analysis")
    boolean parallelEnabled = false;

    @Parameter(names = {"--limitpaths", "-l"}, description = "use path limiting per target unit---false disables path limiting, true enables it and is the default", arity = 1)
    boolean pathLimitEnabled = true;

    @Parameter(names = {"--z3py", "-z"})
    boolean z3py = false;

    @Parameter(names = {"--sharedprefsanalysis", "-s"})
    boolean spAnalysis = false;

    @Parameter(names = {"--evalanalysis", "-e"})
    boolean evalAnalysis = false;

    @Parameter(names = {"--jnianalysis", "-j"})
    boolean jniAnalysis = false;

    @Parameter(names = {"--androlibanalysis", "-a"})
    boolean androlibAnalysis = false;

    @Parameter(names = {"--modelnumbers", "-n"}, description = "numbers of unique models")
    public Integer modelNums = 1;

    @Parameter(names = {"--help", "-h"}, help = true)
    private boolean help;

    @Parameter(
            names = {"--timeout", "-t"},
            description = "modifies the timeout for path extraction in seconds (default: 180 for \"intraprocedural\" and 1800 for \"whole-program\")",
            arity = 1,
            required = false
    )
    int timeout = 0;

    @Parameter(names = {"--intra", "-i"}, description = "perform intra-procedural analysis for specified passes")
    boolean intraFlag = false;

    @Parameter(names = {"--ondemand", "-o"}, description = "perform inter-procedural analysis with on-demand callgraphs")
    boolean onDemandFlag = false;


    public static void main(String[] args) throws IOException, ParseException {
        StopWatch allPhaseStopWatch = new StopWatch();
        allPhaseStopWatch.start();

        StaticEvalUseDriver d = new StaticEvalUseDriver();
        JCommander jCommander = new JCommander(d, args);
        jCommander.setProgramName("JCommanderExample");
        if (d.help) {
            jCommander.usage();
            return;
        }

        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_time(false);

        JSONParser ic3parser = new JSONParser();
        JSONParser iccbotparser = new JSONParser();
        JSONParser fwparser = new JSONParser();

        String analysisFolder = args[0]; // root folder with apks and jsons folders
        String fileName = args[1]; // apk filename without extension
        String apkFilePath = analysisFolder + File.separator + "apks" + File.separator + fileName + ".apk";
        Logger logger = Utils.setupLogger(StaticEvalUseDriver.class, fileName + ".apk");

        // only iccbot and phenomenon have parser script
        String ic3FilePath = analysisFolder + File.separator + "jsons" + File.separator + "ic3-" + fileName + ".json";
        String ic3ExitsFilePath = analysisFolder + File.separator + "jsons" + File.separator + "ic3-exits-" + fileName + ".json";
        String iccbotFilePath = analysisFolder + File.separator + "jsons" + File.separator + "iccbotp-" + fileName + ".json";
        String fwFilePath = analysisFolder + File.separator + "jsons" + File.separator + "fw-" + fileName + ".json";

        JSONObject ic3obj = null;
        JSONObject ic3exitsobj = null;
        JSONObject iccbotobj = null;
        JSONObject fwobj = null;
        File checkFile = new File(ic3FilePath);
        if (checkFile.isFile()) {
            ic3obj = (JSONObject) ic3parser.parse(new FileReader(ic3FilePath));
        }
        checkFile = new File(ic3ExitsFilePath);
        if (checkFile.isFile()) {
            ic3exitsobj = (JSONObject) ic3parser.parse(new FileReader(ic3ExitsFilePath));
        }
        checkFile = new File(iccbotFilePath);
        if (checkFile.isFile()) {
            iccbotobj = (JSONObject) iccbotparser.parse(new FileReader(iccbotFilePath));
        }
        checkFile = new File(fwFilePath);
        if (checkFile.isFile()) {
            fwobj = (JSONObject) fwparser.parse(new FileReader(fwFilePath));
        }
        List jsons = new ArrayList();
        jsons.add(ic3obj);
        jsons.add(iccbotobj);
        jsons.add(fwobj);
        jsons.add(ic3exitsobj);

        // with extra values
        TargetedPathTransformerSpEval teval = new ExtraDataUseTransformerSpEval(apkFilePath, jsons, true);
        teval.parallelEnabled = d.parallelEnabled;
        teval.pathLimitEnabled = d.pathLimitEnabled;
        Utils.setupDummyMainMethod();
        Options.v().set_whole_program(true);
        Options.v().set_time(false);
        Options.v().setPhaseOption("jb", "use-original-names:true");
        PackManager.v().getPack("wjtp").add(new Transform("wjtp.constant", new ConstantValueInitTransformer()));
        PackManager.v().getPack("wjtp").apply();
        assert teval != null;
        teval.main(false);

        /*
        // without extra values
        TargetedPathTransformerSpEval teval2 = new ExtraDataUseTransformerSpEval(apkFilePath, jsons, false);
        teval2.parallelEnabled = d.parallelEnabled;
        teval2.pathLimitEnabled = d.pathLimitEnabled;
        Utils.setupDummyMainMethod(false);
        Options.v().set_whole_program(true);
        Options.v().set_time(false);
        Options.v().setPhaseOption("jb", "use-original-names:true");
        PackManager.v().getPack("wjtp").add(new Transform("wjtp.constant", new ConstantValueInitTransformer()));
        PackManager.v().getPack("wjtp").apply();
        assert teval2 != null;
        teval2.main(false);
         */

        /*
        System.out.println("Final (with extra values): ");
        System.out.println("    Total: "+teval.compareOut.get("total"));
        System.out.println("    FW: "+teval.compareOut.get("fw"));
        System.out.println("    IC3: "+teval.compareOut.get("ic3"));
        System.out.println("    ICCBOT: "+teval.compareOut.get("iccbot"));

        System.out.println("Final (without extra values): ");
        System.out.println("    Total: "+teval2.compareOut.get("total"));
        System.out.println("    FW: "+teval2.compareOut.get("fw"));
        System.out.println("    IC3: "+teval2.compareOut.get("ic3"));
        System.out.println("    ICCBOT: "+teval2.compareOut.get("iccbot"));
         */
    }

}
