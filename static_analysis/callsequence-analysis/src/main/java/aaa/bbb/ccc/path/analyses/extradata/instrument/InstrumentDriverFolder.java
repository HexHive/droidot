package aaa.bbb.ccc.path.analyses.extradata.instrument;

import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import org.slf4j.Logger;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.*;

public class InstrumentDriverFolder {

	//public static int instrumentStatementCnt = 1;
	private static AndroidProcessor androidProcessor = new AndroidProcessor();
	public static void main(String[] args) throws IOException {
		
		StopWatch allPhaseStopWatch = new StopWatch();
		allPhaseStopWatch.start();

		String apksFolderPath = args[0];
		String newLine = System.getProperty("line.separator");

		File targetsFolder = new File(apksFolderPath);
		String folderName = targetsFolder.getName();
		FileWriter iFile = new FileWriter(folderName+"-dyn-intentrich-apks.txt");
		FileWriter nFile = new FileWriter(folderName+"-dyn-notintentrich-apks.txt");
		FileWriter eFile = new FileWriter(folderName+"-dyn-error-apks.txt");
		FileWriter lFile = new FileWriter(folderName+"-dyn-log-apks.txt");
		FileWriter tFile = new FileWriter(folderName+"-timedout-apks.txt");
		iFile.close();
		nFile.close();
		eFile.close();
		lFile.close();
		tFile.close();

		for (File f : targetsFolder.listFiles()) {

			String name = f.getName();
			String apkName = name.substring(0, name.lastIndexOf('.')) + ".apk";
			String apkFilePath = targetsFolder + File.separator + apkName;
			System.out.println("Analyzing apk " + apkFilePath);

			iFile = new FileWriter(folderName+"-dyn-intentrich-apks.txt", true);
			nFile = new FileWriter(folderName+"-dyn-notintentrich-apks.txt", true);
			eFile = new FileWriter(folderName+"-dyn-error-apks.txt", true);
			lFile = new FileWriter(folderName+"-dyn-log-apks.txt", true);
			tFile = new FileWriter(folderName+"-dyn-timedout-apks.txt", true);
			lFile.write("Analyzing apk " + apkFilePath+newLine);
			lFile.close();

			ExecutorService executor = Executors.newSingleThreadExecutor();

			//Logger logger = Utils.setupLogger(InstrumentDriverFolder.class, apkName);
			InstrumentTransformer transformer = new InstrumentTransformer(apkFilePath, folderName);
			Future future = executor.submit(new Runnable() {
				@Override
				public void run() {
					// only perform categorization and write to file. Does not add instrumentation code
					transformer.run();
				}
			});

			executor.shutdown();
			try {
				future.get(10, TimeUnit.MINUTES);
			}
			catch (InterruptedException ie) {
				// Handle the interruption. Or ignore it
			}
			catch (ExecutionException ee) {
				// Handle the error. Or ignore it.
				eFile.write(apkName+newLine);
			}
			catch (TimeoutException te) {
				// Handle the timeout. Or ignore it
				tFile.write(apkName+newLine);
			}
			if (!executor.isTerminated())
				// stop the code that hasn't finished
				executor.shutdownNow();

			//logger.debug("Total number of units added to app: " + transformer.getInstrumentStmtCount());
			System.out.println("Total number of units added to app: " + transformer.getInstrumentStmtCount());
			//logger.debug("Reached end of path executor driver...");

			//iFile.write(apkName+","+transformer.getIntentControlledStatementCnt()+","+transformer.getInstrumentStmtCount()+newLine);
			if (transformer.getInstrumentStmtCount() >= 1) {
				iFile.write(apkName+","+transformer.getIntentControlledStatementCnt()+","+transformer.getInstrumentStmtCount()+newLine);
			} else {
				nFile.write(apkName+","+transformer.getInstrumentStmtCount()+newLine);
			}
			iFile.close();
			nFile.close();
			eFile.close();
			tFile.close();
		}
	}
}
