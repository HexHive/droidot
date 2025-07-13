package aaa.bbb.ccc.path.analyses.extradata.instrument;

import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import org.slf4j.Logger;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.*;

public class InstrumentDriverFolderCat {

	//public static int instrumentStatementCnt = 1;
	private static AndroidProcessor androidProcessor = new AndroidProcessor();
	public static void main(String[] args) throws IOException {
		
		StopWatch allPhaseStopWatch = new StopWatch();
		allPhaseStopWatch.start();

		String apksFolderPath = args[0];
		String newLine = System.getProperty("line.separator");

		FileWriter iFile = new FileWriter("intentrich-apks.txt");
		FileWriter nFile = new FileWriter("notintentrich-apks.txt");
		FileWriter eFile = new FileWriter("error-apks.txt");
		FileWriter tFile = new FileWriter("timedout-apks.txt");
		FileWriter lFile = new FileWriter("log-apks.txt");
		FileWriter cFile = new FileWriter("cats.txt");
		FileWriter c2File = new FileWriter("cats_noev.txt");
		FileWriter spFile = new FileWriter("str_profiles.txt");
		FileWriter apFile = new FileWriter("attr_profiles.txt");
		iFile.close();
		nFile.close();
		eFile.close();
		tFile.close();
		lFile.close();
		cFile.close();
		c2File.close();
		spFile.close();
		apFile.close();
		cFile = new FileWriter("cats.txt", true);
		cFile.write("apkName,control-dependent paths,intent control-dependent paths,action,uri,uri-nullness,extras-key,extras-value,bundleExtras-key,bundleExtras-value,category,array-extras-value"+newLine);
		cFile.close();
		c2File = new FileWriter("cats_noev.txt", true);
		c2File.write("apkName,control-dependent paths,intent control-dependent paths,action,uri,uri-nullness,extras-key,bundleExtras-key,category"+newLine);
		c2File.close();

		File targetsFolder = new File(apksFolderPath);
		for (File f : targetsFolder.listFiles()) {
			iFile = new FileWriter("intentrich-apks.txt", true);
			nFile = new FileWriter("notintentrich-apks.txt", true);
			eFile = new FileWriter("error-apks.txt", true);
			tFile = new FileWriter("timedout-apks.txt", true);
			lFile = new FileWriter("log-apks.txt", true);
			cFile = new FileWriter("cats.txt", true);
			c2File = new FileWriter("cats_noev.txt", true);
			spFile = new FileWriter("str_profiles.txt", true);
			apFile = new FileWriter("attr_profiles.txt", true);

			ExecutorService executor = Executors.newSingleThreadExecutor();

			String name = f.getName();
			String apkName = name.substring(0, name.lastIndexOf('.')) + ".apk";
			String apkFilePath = targetsFolder + File.separator + apkName;
			System.out.println("Analyzing apk " + apkFilePath);
			lFile.write("Analyzing apk " + apkFilePath+newLine);
			lFile.close();

			Logger logger = Utils.setupLogger(InstrumentDriverFolderCat.class, apkName);

			InstrumentTransformerCat transformer = new InstrumentTransformerCat(apkFilePath);
			Future future = executor.submit(new Runnable() {
				@Override
				public void run() {
					// only perform categorization and write to file. Does not add instrumentation code
					transformer.run();
				}
			});

			executor.shutdown();
			try {
				future.get(30, TimeUnit.MINUTES);
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

			logger.debug("Total number of units added to app: " + transformer.getInstrumentStmtCount());
			System.out.println("Total number of units added to app: " + transformer.getInstrumentStmtCount());
			logger.debug("Reached end of path executor driver...");

			// profile
			spFile.write(apkName);
			int totalNoModelStrOps = transformer.noModelStrOps.values().stream().mapToInt(Integer::intValue).sum();
			spFile.write(","+totalNoModelStrOps);
			for (Map.Entry<String,Integer> entry : transformer.noModelStrOps.entrySet()) {
				String op = entry.getKey();
				Integer occurs = entry.getValue();
				spFile.write(","+op+":"+occurs);
			}
			spFile.write(newLine);

			apFile.write(apkName);
			int totalNoModelAttrs = transformer.noModelAttrs.values().stream().mapToInt(Integer::intValue).sum();
			apFile.write(","+totalNoModelAttrs);
			for (Map.Entry<String,Integer> entry : transformer.noModelAttrs.entrySet()) {
				String op = entry.getKey();
				Integer occurs = entry.getValue();
				apFile.write(","+op+":"+occurs);
			}
			apFile.write(newLine);

			// categorization
			cFile.write(apkName+","+transformer.controlDepPaths+","+transformer.intentControlDepPaths);
			cFile.write(","+transformer.intentCatCounts.get("action"));
			cFile.write(","+transformer.intentCatCounts.get("uri"));
			cFile.write(","+transformer.intentCatCounts.get("uri-nullness"));
			cFile.write(","+transformer.intentCatCounts.get("extras-key"));
			cFile.write(","+transformer.intentCatCounts.get("extras-value"));
			cFile.write(","+transformer.intentCatCounts.get("bundleExtras-key"));
			cFile.write(","+transformer.intentCatCounts.get("bundleExtras-value"));
			cFile.write(","+transformer.intentCatCounts.get("category"));
			cFile.write(","+transformer.intentCatCounts.get("array-extras-value")+newLine);

			int pathsWithoutExtras = transformer.intentControlDepPaths - transformer.intentCatCounts.get("array-extras-value");
			c2File.write(apkName+","+transformer.controlDepPaths+","+pathsWithoutExtras);
			c2File.write(","+transformer.intentCatCounts.get("action"));
			c2File.write(","+transformer.intentCatCounts.get("uri"));
			c2File.write(","+transformer.intentCatCounts.get("uri-nullness"));
			c2File.write(","+transformer.intentCatCounts.get("extras-key"));
			c2File.write(","+transformer.intentCatCounts.get("bundleExtras-key"));
			c2File.write(","+transformer.intentCatCounts.get("category")+newLine);

			System.out.println("total number of control-dependent paths: " + transformer.controlDepPaths);
			System.out.println("total number of Intent control-dependent paths: " + transformer.intentControlDepPaths);
			System.out.println("categories of Intent control-dependencies: ");
			for (Map.Entry<String,Integer> item : transformer.intentCatCounts.entrySet()) {
				String cat = item.getKey();
				Integer counts = item.getValue();
				System.out.println("    "+cat+":"+counts);
			}

			if (transformer.getInstrumentStmtCount() >= 10) {
				iFile.write(apkName+","+transformer.getInstrumentStmtCount()+newLine);
			} else {
				nFile.write(apkName+","+transformer.getInstrumentStmtCount()+newLine);
			}
			iFile.close();
			nFile.close();
			eFile.close();
			cFile.close();
			c2File.close();
			tFile.close();
			// profiling
			spFile.close();
			apFile.close();
		}


	}

}
