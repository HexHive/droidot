package aaa.bbb.ccc.path.analyses.extradata;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.model.Intent;
import aaa.bbb.ccc.path.analyses.*;
import soot.*;
import soot.options.Options;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.*;

public class ExtraDataUseDriver {
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

    @Parameter(names = {"--whole", "-w"}, description = "perform just whole-program callgraph construction")
    boolean wholeProgramCgFlag = false;

    @Parameter(names = {"--datadependentpathextraction", "-z"}, description = "extracted paths only contain Intent-dependent units")
    boolean intentDependentExtractionFlag = false;

    @Parameter(names = {"--payloadasarg", "-y"}, description = "perform interprocedural analysis with analysis-specific " +
                                                               "callgraph that accounts for Intent payload as callee argument")
    boolean payloadAsArgFlag = false;

    @Parameter(names = {"--handleonactivityresult", "-h"}, description = "account for onActivityResult when constructing Analysis-Specific Callgraph")
    boolean handleOnActivityResultFlag = false;

    public static TargetedPathTransformerSp tsp;
    public static TargetedPathTransformerSpIntra tspi;
    public static TargetedPathTransformerL t;


    public static void main(String[] args) throws IOException {
        StopWatch allPhaseStopWatch = new StopWatch();
        allPhaseStopWatch.start();

        ExtraDataUseDriver d = new ExtraDataUseDriver();
        JCommander jCommander = new JCommander(d, args);
        jCommander.setProgramName("JCommanderExample");

        // apkFilePath will be used to set Config.apkFilePath in TargetedPathTransformer.java
        String apkFilePath = d.parameters.get(0);
        File apkFile = new File(apkFilePath);

        System.out.println("Analyzing apk " + apkFilePath);

        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_time(false);

        FileWriter outputMemFile;
        if (d.spAnalysis) {
            outputMemFile = new FileWriter("phenom.mem", true);
        } else {
            outputMemFile = new FileWriter("old.mem", true);
        }

        // start time and start memory usage
        MemoryMXBean mbean = ManagementFactory.getMemoryMXBean();
        System.gc();
        MemoryUsage beforeHeapMemoryUsage = mbean.getHeapMemoryUsage();
        long startTime = System.currentTimeMillis();

        if (d.spAnalysis) {
            tsp = new ExtraDataUseTransformerSp(apkFilePath);
            t = null;
        } else {
            t = new ExtraDataUseTransformerL(apkFilePath);
            tsp = null;
        }

        StopWatch singlePhaseStopWatch = new StopWatch();

        singlePhaseStopWatch.start();
        if (d.spAnalysis) {
            // run PHENOM
            Options.v().setPhaseOption("jb", "use-original-names:true");
            PackManager.v().getPack("wjtp").add(new Transform("wjtp.constant", new ConstantValueInitTransformer()));
            PackManager.v().getPack("wjtp").apply();
            if (d.onDemandFlag) {
                // analysis-specific callgraph
                assert tsp != null;
                tsp.reducedFlag = d.reducedAnalysis;
                tsp.demandFilterFlag = d.demandFilterFlag;
                tsp.debugFlag = d.debugFlag;
                tsp.payloadAsArgFlag = d.payloadAsArgFlag;
                tsp.intentDependentExtractionFlag = d.intentDependentExtractionFlag;
                tsp.handleOnActivityResultFlag = d.handleOnActivityResultFlag;
                tsp.outputMemFile = outputMemFile;
                tsp.main(true);
            } else {
                // normal interprocedural analysis
                //Utils.setupDummyMainMethod();
                //Options.v().set_whole_program(true);
                //Options.v().set_time(false);
                assert tsp != null;
                tsp.reducedFlag = d.reducedAnalysis;
                tsp.demandFilterFlag = d.demandFilterFlag;
                tsp.debugFlag = d.debugFlag;
                tsp.intentDependentExtractionFlag = d.intentDependentExtractionFlag;
                tsp.wholeProgramCgFlag = d.wholeProgramCgFlag;  // does not make sense to set for analysis-specific callgraph
                tsp.outputMemFile = outputMemFile;
                tsp.main(false);
            }
        } else {
            // run old
            t.run();
        }
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
        outputMemFile.write("Overall," + apkName + "," + consumed + "B," + consumed/(1024 * 1024) + "MB," + elapsedSeconds + "s\n");
        outputMemFile.flush();
        outputMemFile.close();
    }
}
