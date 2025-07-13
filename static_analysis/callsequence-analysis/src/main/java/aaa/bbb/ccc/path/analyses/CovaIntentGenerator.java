package aaa.bbb.ccc.path.analyses;

import com.beust.jcommander.JCommander;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.model.Intent;
import org.javatuples.Pair;
import org.slf4j.Logger;
import soot.SootMethod;
import soot.Unit;
import soot.tagkit.SourceLineNumberTag;
import soot.tagkit.Tag;

import java.io.*;
import java.util.*;

public class CovaIntentGenerator extends TargetedPathTransformer {

    protected static String DROZER_NIIG_INTENT_CMDS = "drozer_cova_intent_cmds_";
    Map<Unit,Boolean> doesUnitNeedAnalysisSummary = new LinkedHashMap<Unit,Boolean>();

    Set<Pair<Integer,String>> targets;
    Integer targetsCount;

    @Override
    public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit inUnit) {
        if (doesUnitNeedAnalysisSummary.containsKey(inUnit)) {
            // previously has already computed whether unit `inUnit` needs analysis or not
            return doesUnitNeedAnalysisSummary.get(inUnit);
        }

        SourceLineNumberTag srcLineTag = extractSourceLineNumber(inUnit);
        if (srcLineTag == null) {
            doesUnitNeedAnalysisSummary.put(inUnit, false);
            return false;
        }
        int srcLine = Integer.parseInt(srcLineTag.toString());

        Pair<Integer,String> inPair = new Pair<Integer,String>(srcLine, method.toString());
        // TODO: It ignores all functions except the one matched in target's bytecode offset and its method string
        if (targets.contains(inPair)) {
            // contains bytecode and method pair
            targetsCount += 1;
            doesUnitNeedAnalysisSummary.put(inUnit, true);
            return true;
        }
        doesUnitNeedAnalysisSummary.put(inUnit, false);
        return false;
    }

    public CovaIntentGenerator(String apkFilePath, String targetsFilePath) {
        super(apkFilePath);
        super.DROZER_TARGETED_INTENT_CMDS = DROZER_NIIG_INTENT_CMDS;
        targets = new LinkedHashSet<Pair<Integer,String>>();
        targetsCount = 0;

        try(BufferedReader br = new BufferedReader(new FileReader(targetsFilePath))) {
            String line = br.readLine();
            while (line != null) {

                // target file line format: <bytecode offset>#<method name>
                String[] tokens = line.split("#");
                String srcLineStr = tokens[0];
                String methodName = tokens[1];
                int srcLine = Integer.parseInt(srcLineStr);

                System.out.println(srcLineStr + " -> " + methodName);
                targets.add(new Pair<Integer,String>(srcLine,methodName));

                line = br.readLine();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

	public static SourceLineNumberTag extractSourceLineNumber(Unit unit) {
		for (Tag tag : unit.getTags()) {
		  if (tag instanceof SourceLineNumberTag) {
			SourceLineNumberTag srcTag = (SourceLineNumberTag) tag;
			return srcTag;
		  }
		}
		return null;
	}

    public static void main(String[] args) {
        StopWatch allPhaseStopWatch = new StopWatch();
        allPhaseStopWatch.start();

        IntentGeneratorOptions opts = new IntentGeneratorOptions();
        new JCommander(opts,args);

        if (opts.targetsFolder == null) {
            String apkFilePath = opts.apkFilePath;
            File apkFile = new File(apkFilePath);
            System.out.println("Analyzing apk " + apkFilePath);
            Logger logger = Utils.setupLogger(CovaIntentGenerator.class,apkFile.getName());

            CovaIntentGenerator t = new CovaIntentGenerator(opts.apkFilePath, opts.targetsFilePath);
            t.run();
            if (t.targets.size() != t.targetsCount) {
                // not all targets are reached
                // something is wrong
                System.out.println("not all targets are reached");
            }
        } else {
            if (opts.apksFolder == null) {
                System.out.println("Need to provide filepath to apks folder");
            }
            File targetsFolder = new File(opts.targetsFolder);
            for (File f : targetsFolder.listFiles()){
                String targetsFilePath = f.getAbsolutePath();
                String name = f.getName();
                String apkName = name.substring(0, name.lastIndexOf('.')) + ".apk";
                String apkFilePath = opts.apksFolder + File.separator + apkName;
                System.out.println("Analyzing apk " + apkFilePath);
                CovaIntentGenerator t = new CovaIntentGenerator(apkFilePath, targetsFilePath);
                t.run();
                /*
                if (t.targets.size() != t.targetsCount) {
                    // not all targets are reached
                    // something is wrong
                    System.out.println("not all targets are reached");
                }
                 */
            }
        }
    }
}
