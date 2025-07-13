package aaa.bbb.ccc.path.analyses.extradata.instrument;

import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import org.slf4j.Logger;

import java.io.File;
import java.util.Map;

public class InstrumentDriverCat {

	//public static int instrumentStatementCnt = 1;
	private static AndroidProcessor androidProcessor = new AndroidProcessor();
	public static void main(String[] args) {
		
		StopWatch allPhaseStopWatch = new StopWatch();
		allPhaseStopWatch.start();

		String apkFilePath = args[0];
		File apkFile = new File(apkFilePath);

		Logger logger = Utils.setupLogger(InstrumentDriverCat.class,apkFile.getName());

		InstrumentTransformerCat transformer = new InstrumentTransformerCat(apkFilePath);

		StopWatch singlePhaseStopWatch = new StopWatch();

		singlePhaseStopWatch.start();
		
		// only perform categorization and write to file. Does not add instrumentation code
		transformer.run();
		singlePhaseStopWatch.stop();
		logger.debug("path analysis time (milliseconds):" + singlePhaseStopWatch.getElapsedTime());
		
		allPhaseStopWatch.stop();
		logger.debug("total runtime for all phases (milliseconds):" + allPhaseStopWatch.getElapsedTime());
		
		logger.debug("Total number of units added to app: " + transformer.getInstrumentStmtCount());
		System.out.println("Total number of units added to app: " + transformer.getInstrumentStmtCount());
		logger.debug("Reached end of path executor driver...");

		// cat
		// categorize the kind of intent-controlled statements:
		// category, action, uri, uri-nullness, extras-key, extras-value, bundleExtras-key, bundleExtras-value
		System.out.println("total number of control-dependent paths: " + transformer.controlDepPaths);
		System.out.println("total number of Intent control-dependent paths: " + transformer.intentControlDepPaths);
		System.out.println("categories of Intent control-dependencies: ");
		for (Map.Entry<String,Integer> item : transformer.intentCatCounts.entrySet()) {
			String cat = item.getKey();
			Integer counts = item.getValue();
			System.out.println("    "+cat+":"+counts);
		}

	}
}