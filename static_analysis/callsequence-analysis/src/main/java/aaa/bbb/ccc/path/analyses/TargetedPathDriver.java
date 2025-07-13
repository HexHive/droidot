package aaa.bbb.ccc.path.analyses;

import java.io.File;

import org.slf4j.Logger;
import org.slf4j.MDC;

import soot.options.Options;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;

public class TargetedPathDriver {

	public static void main(String[] args) {
		StopWatch allPhaseStopWatch = new StopWatch();
		allPhaseStopWatch.start();
		
		String apkFilePath = args[0];
		Logger logger = Utils.setupLogger(TargetedPathDriver.class,(new File(apkFilePath)).getName());
		
		Options.v().set_output_format(Options.output_format_none);
		
		TargetedPathTransformer transformer = new TargetedPathTransformer(apkFilePath);
		//String[] flowDroidArgs = {apkFilePath,System.getenv("ANDROID_HOME"), "--nostatic", "--aplength", "1", "--aliasflowins", "--nocallbacks","--layoutmode", "none"};
		//String[] flowDroidArgs = {appFileName.getAbsolutePath(),"/home/abc/android-sdks/platforms/android-17/android.jar"};
		
		// Setup dump of method bodies
		/*List<String> dump = new ArrayList<String>();
		dump.add("ALL");
		Options.v().set_dump_cfg(dump);
		Options.v().set_dump_body(dump);
		PhaseDumper.v();*/
		
		StopWatch singlePhaseStopWatch = new StopWatch();

		// Test.main(flowDroidArgs);

		singlePhaseStopWatch.start();
		transformer.run();
		singlePhaseStopWatch.stop();
		logger.debug("path analysis time (milliseconds):" + singlePhaseStopWatch.getElapsedTime());
		
		allPhaseStopWatch.stop();
		logger.debug("total runtime for all phases (milliseconds):" + allPhaseStopWatch.getElapsedTime());
		logger.debug("Reached end of path executor driver...");

	}

}
