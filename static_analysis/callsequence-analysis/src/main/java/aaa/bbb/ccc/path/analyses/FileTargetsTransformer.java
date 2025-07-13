package aaa.bbb.ccc.path.analyses;

import com.beust.jcommander.JCommander;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.model.Intent;
import org.javatuples.Pair;
import org.slf4j.Logger;
import soot.SootMethod;
import soot.Unit;

import java.io.*;
import java.util.*;

import com.beust.jcommander.Parameter;
import soot.tagkit.BytecodeOffsetTag;


public class FileTargetsTransformer extends TargetedPathTransformer {

    Set<Pair<Integer,String>> targets = new LinkedHashSet<Pair<Integer,String>>();

    public FileTargetsTransformer(String apkFilePath, String targetsFilePath) {
        super(apkFilePath);

        try(BufferedReader br = new BufferedReader(new FileReader(targetsFilePath))) {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            while (line != null) {

                String[] tokens = line.split("#");
                String bytecodeOffsetStr = tokens[0];
                String methodName = tokens[1];
                int bytecodeOffset = Integer.parseInt(bytecodeOffsetStr);

                System.out.println(bytecodeOffset + " -> " + methodName);
                targets.add(new Pair<Integer,String>(bytecodeOffset,methodName));

                line = br.readLine();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit inUnit) {
        BytecodeOffsetTag inBcoTag = Utils.extractByteCodeOffset(inUnit);
        if (inBcoTag == null) {
            return false;
        }
        Pair<Integer,String> inPair = new Pair<Integer,String>(inBcoTag.getBytecodeOffset(),method.toString());
        if (targets.contains(inPair)) {
            return true;
        }
        return false;
    }

    public static void main(String[] args) {
        StopWatch allPhaseStopWatch = new StopWatch();
        allPhaseStopWatch.start();

        IntentGeneratorOptions opts = new IntentGeneratorOptions();
        new JCommander(opts,args);
        String apkFilePath = opts.apkFilePath;
        File apkFile = new File(apkFilePath);

        System.out.println("Analyzing apk " + apkFilePath);

        Logger logger = Utils.setupLogger(FileTargetsTransformer.class,apkFile.getName());

        FileTargetsTransformer t = new FileTargetsTransformer(opts.apkFilePath,opts.targetsFilePath);
        t.parallelEnabled = opts.parallelEnabled;
        t.pathLimitEnabled = opts.pathLimitEnabled;

        if (t.parallelEnabled) {
            System.out.println("Parallelism is enabled");
        } else {
            System.out.println("Parallelism is disabled");
        }

        StopWatch singlePhaseStopWatch = new StopWatch();

        singlePhaseStopWatch.start();
        t.run();
        singlePhaseStopWatch.stop();
        logger.debug("transformer analysis time (milliseconds):" + singlePhaseStopWatch.getElapsedTime());
        logger.debug("main analysis time (milliseconds):" + t.mainAnalysisRuntime);

        Map<List<Unit>,Intent> pathIntents = t.getPathIntents();
        logger.debug("Intents to generate: ");
        for (Map.Entry<List<Unit>,Intent> entry : pathIntents.entrySet()) {
            List<Unit> path = entry.getKey();
            Intent intent = entry.getValue();
            logger.debug(intent.toString());
        }

        allPhaseStopWatch.stop();
        logger.debug("total runtime for all phases (milliseconds):" + allPhaseStopWatch.getElapsedTime());
        System.out.println("total runtime for all phases (milliseconds):" + allPhaseStopWatch.getElapsedTime());

        logger.debug("Reached end of path executor driver...");
        logger.debug("Number of paths analyzed: " + t.getPathsAnalyzedCount());

    }
}
