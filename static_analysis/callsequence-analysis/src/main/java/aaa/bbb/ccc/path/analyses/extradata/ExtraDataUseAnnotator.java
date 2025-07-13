package aaa.bbb.ccc.path.analyses.extradata;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.path.analyses.ConstantValueInitTransformer;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerAnn;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerL;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerSp;
import soot.PackManager;
import soot.Transform;
import soot.options.Options;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class ExtraDataUseAnnotator {
    @Parameter(description = "APK", required = true)
    private List<String> parameters = new ArrayList<>();

    @Parameter(names = {"--parallel", "-p"}, description = "enables parallel per-target-statement analysis")
    boolean parallelEnabled = false;

    @Parameter(names = {"--limitpaths", "-l"}, description = "use path limiting per target unit---false disables path limiting, " +
                                                             "true enables it and is the default", arity = 1)
    boolean pathLimitEnabled = true;

    @Parameter(names = {"--sharedprefsanalysis", "-s"})
    boolean spAnalysis = false;

    @Parameter(names = {"--reducedcallgraph", "-r"})
    boolean reducedAnalysis = false;

    @Parameter(names = {"--modelnumbers", "-n"}, description = "numbers of unique models")
    public Integer modelNums = 1;

    @Parameter(
            names = {"--timeout", "-t"},
            description = "modifies the timeout for path extraction in seconds (default: 180 for \"intraprocedural\" " +
                          "and 1800 for \"whole-program\")",
            arity = 1,
            required = false
    )
    int timeout = 0;

    @Parameter(names = {"--debugging", "-d"}, description = "remove generated z3 files after use")
    boolean debugFlag = false;

    @Parameter(names = {"--intra", "-i"}, description = "perform intra-procedural analysis for specified passes")
    boolean intraFlag = false;

    @Parameter(names = {"--intraTwo", "-k"}, description = "perform intra-procedural analysis (v2) for specified passes")
    boolean intraFlag2 = false;

    @Parameter(names = {"--ondemand", "-o"}, description = "perform inter-procedural analysis with on-demand callgraphs")
    boolean onDemandFlag = false;

    @Parameter(names = {"--ondemandfilter", "-f"}, description = "perform on-demand pre-analysis")
    boolean demandFilterFlag = false;

    @Parameter(names = {"--just", "-j"}, description = "just line numbers")
    boolean justLineNumbers = false;

    @Parameter(names = {"--datadependentpathextraction", "-z"}, description = "extracted paths only contain Intent-dependent units")
    boolean intentDependentExtractionFlag = false;

    @Parameter(names = {"--payloadasarg", "-y"}, description = "perform interprocedural analysis with analysis-specific " +
                                                               "callgraph that accounts for Intent payload as callee argument")
    boolean payloadAsArgFlag = false;

    @Parameter(names = {"--handleonactivityresult", "-h"}, description = "account for onActivityResult when constructing Analysis-Specific Callgraph")
    boolean handleOnActivityResultFlag = false;

    public static TargetedPathTransformerAnn tann;

    public static void main(String[] args) throws IOException {
        StopWatch allPhaseStopWatch = new StopWatch();
        allPhaseStopWatch.start();

        ExtraDataUseAnnotator d = new ExtraDataUseAnnotator();
        JCommander jCommander = new JCommander(d, args);
        jCommander.setProgramName("JCommanderExample");

        // apkFilePath will be used to set Config.apkFilePath in TargetedPathTransformer.java
        String apkFilePath = d.parameters.get(0);
        File apkFile = new File(apkFilePath);

        System.out.println("Analyzing apk " + apkFilePath);

        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_time(false);

        // start time and start memory usage
        MemoryMXBean mbean = ManagementFactory.getMemoryMXBean();
        System.gc();
        MemoryUsage beforeHeapMemoryUsage = mbean.getHeapMemoryUsage();
        long startTime = System.currentTimeMillis();

        tann = new ExtraDataUseTransformerAnn(apkFilePath);

        StopWatch singlePhaseStopWatch = new StopWatch();

        singlePhaseStopWatch.start();
        // run PHENOM
        Options.v().setPhaseOption("jb", "use-original-names:true");
        PackManager.v().getPack("wjtp").add(new Transform("wjtp.constant", new ConstantValueInitTransformer()));
        PackManager.v().getPack("wjtp").apply();
        // analysis-specific callgraph
        assert tann != null;
        tann.demandFilterFlag = true;
        tann.debugFlag = d.debugFlag;
        tann.payloadAsArgFlag = true;
        tann.intentDependentExtractionFlag = false;
        tann.handleOnActivityResultFlag = true;
        tann.justLineNumber = d.justLineNumbers;
        tann.main(true);
        singlePhaseStopWatch.stop();

        // end time and end memory usage
        System.gc();
        MemoryUsage afterHeapMemoryUsage = mbean.getHeapMemoryUsage();
        long consumed = afterHeapMemoryUsage.getUsed() -
                beforeHeapMemoryUsage.getUsed();
        long stopTime = System.currentTimeMillis();
        long elapsedTime = stopTime - startTime;
        double elapsedSeconds = elapsedTime / 1000.0;
        Path p = Paths.get(apkFilePath);
        String apkName = p.getFileName().toString();
    }
}
