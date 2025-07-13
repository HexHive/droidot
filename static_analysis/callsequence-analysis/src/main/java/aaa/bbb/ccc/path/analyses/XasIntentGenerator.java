package aaa.bbb.ccc.path.analyses;

import com.beust.jcommander.JCommander;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.model.Intent;
import org.javatuples.Pair;
import org.javatuples.Triplet;
import org.slf4j.Logger;
import soot.SootMethod;
import soot.Unit;
import soot.tagkit.BytecodeOffsetTag;

import java.io.*;
import java.util.*;

public class XasIntentGenerator extends TargetedPathTransformer {

    Map<Integer,String> bcoToUrlKeyMap = new LinkedHashMap<Integer,String>();
    List<String> urlKeys = new ArrayList<String>();
    Set<Pair<Integer,String>> targets = new LinkedHashSet<Pair<Integer,String>>();
    private String INJECTED_URL = "http://aaaaaa";;

    protected static String DROZER_XIG_INTENT_CMDS = "drozer_xig_intent_cmds_";

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

    public XasIntentGenerator(String apkFilePath, String targetsFilePath) {
        super(apkFilePath);
        super.DROZER_TARGETED_INTENT_CMDS = DROZER_XIG_INTENT_CMDS;

        try(BufferedReader br = new BufferedReader(new FileReader(targetsFilePath))) {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            while (line != null) {

                String[] tokens = line.split("#");
                String bytecodeOffsetStr = tokens[0];
                String methodName = tokens[1];
                String extraToRemove = tokens[2];
                int bytecodeOffset = Integer.parseInt(bytecodeOffsetStr);

                System.out.println(bytecodeOffset + " -> " + methodName);
                targets.add(new Pair<Integer,String>(bytecodeOffset,methodName));

                urlKeys.add(extraToRemove);
                bcoToUrlKeyMap.put(bytecodeOffset,extraToRemove);

                line = br.readLine();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected Intent modifyGeneratedIntent(Intent genIntent, Unit startingUnit) {
        Intent modIntent = new Intent(genIntent);
        BytecodeOffsetTag startingBco = Utils.extractByteCodeOffset(startingUnit);
        Triplet<String,String,String> extraToAlter = null;

        if (bcoToUrlKeyMap.containsKey(startingBco.getBytecodeOffset())) {
            String extraKeyToAlter = bcoToUrlKeyMap.get(startingBco.getBytecodeOffset());
            for (Triplet<String,String,String> extra : modIntent.extras) {
                String currKey = extra.getValue1();
                if (currKey.equals(extraKeyToAlter)) {
                    extraToAlter = extra;
                }
            }
        }

        if (extraToAlter != null) {
            modIntent.extras.remove(extraToAlter);
            Triplet<String,String,String> newExtra = new Triplet<String,String,String>(extraToAlter.getValue0(),extraToAlter.getValue1(),INJECTED_URL);
            modIntent.extras.add(newExtra);
        }

        return modIntent;
    }

    public static void main(String[] args) {
        StopWatch allPhaseStopWatch = new StopWatch();
        allPhaseStopWatch.start();

        IntentGeneratorOptions opts = new IntentGeneratorOptions();
        new JCommander(opts,args);
        String apkFilePath = opts.apkFilePath;
        File apkFile = new File(apkFilePath);

        System.out.println("Analyzing apk " + apkFilePath);

        Logger logger = Utils.setupLogger(XasIntentGenerator.class,apkFile.getName());

        XasIntentGenerator t = new XasIntentGenerator(opts.apkFilePath,opts.targetsFilePath);
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
