package aaa.bbb.ccc.path.analyses.extradata.instrument;

import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import org.slf4j.Logger;
import java.io.File;
import java.util.Map;

public class InstrumentDriver {

	//public static int instrumentStatementCnt = 1;
	private static AndroidProcessor androidProcessor = new AndroidProcessor();
	public static void main(String[] args) {
		
		StopWatch allPhaseStopWatch = new StopWatch();
		allPhaseStopWatch.start();

		String apkFilePath = args[0];
		File apkFile = new File(apkFilePath);

		Logger logger = Utils.setupLogger(InstrumentDriver.class,apkFile.getName());
		//Options.v().set_output_format(Options.output_format_dex);
		
		//Options.v().set_output_format(Options.output_format_dex);
		InstrumentTransformer transformer = new InstrumentTransformer(apkFilePath);

		StopWatch singlePhaseStopWatch = new StopWatch();

		singlePhaseStopWatch.start();
		
		//remove the apk file from the sootOutputDir, if exists
		// !!! those three variables should be in the Utils class
        /*String sootOutputDir= "./sootOutput/";
        String[] arr = apkFilePath.split(File.separator);
        String apkName = arr[arr.length-1];

        System.out.println("**** remove the previous instrumented apk, if exists ***********");
        String[] removeApkArgs = {"rm",sootOutputDir+apkName};
        Utils.runCmdAsProcess(removeApkArgs);*/

		transformer.run();
		singlePhaseStopWatch.stop();
		logger.debug("path analysis time (milliseconds):" + singlePhaseStopWatch.getElapsedTime());
		
		allPhaseStopWatch.stop();
		logger.debug("total runtime for all phases (milliseconds):" + allPhaseStopWatch.getElapsedTime());
		
		logger.debug("Total number of units added to app: " + transformer.getInstrumentStmtCount());
		System.out.println("Total number of units added to app: " + transformer.getInstrumentStmtCount());
		System.out.println("Total number of intent-controlled statements: " + transformer.getIntentControlledStatementCnt());
		logger.debug("Reached end of path executor driver...");

	}
}