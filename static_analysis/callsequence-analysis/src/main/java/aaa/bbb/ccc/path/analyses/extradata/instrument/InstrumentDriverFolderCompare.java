package aaa.bbb.ccc.path.analyses.extradata.instrument;

import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.*;

public class InstrumentDriverFolderCompare {

	//public static int instrumentStatementCnt = 1;
	private static AndroidProcessor androidProcessor = new AndroidProcessor();

	public static String getCompareTotal(Map<String,Integer> compare, boolean withEv) {
		Integer total = 0;
		total += compare.get("action");
		total += compare.get("uri");
		total += compare.get("extras-key");
		if (withEv) {
			total += compare.get("extras-value");
		}
		total += compare.get("categories");
		return String.valueOf(total);
	}

	public static void main(String[] args) throws IOException, ParseException {
		
		StopWatch allPhaseStopWatch = new StopWatch();
		allPhaseStopWatch.start();

		String apksFolderPath = args[0] + File.separator + "apks";
		String newLine = System.getProperty("line.separator");

		FileWriter iFile = new FileWriter("intentrich-apks.txt");
		FileWriter nFile = new FileWriter("notintentrich-apks.txt");
		FileWriter eFile = new FileWriter("error-apks.txt");
		FileWriter lFile = new FileWriter("log-apks.txt");
		FileWriter cFile = new FileWriter("compare.txt");
		FileWriter c2File = new FileWriter("compare_noev.txt");
		FileWriter tFile = new FileWriter("timedout-apks.txt");
		tFile.close();
		iFile.close();
		nFile.close();
		eFile.close();
		lFile.close();
		cFile.close();
		c2File.close();
		cFile = new FileWriter("compare.txt", true);
		cFile.write("apkName,total,action,uri,categories,extras key,extras value,phenomenon total,action,uri,categories,extras key,extras value,iccbot total,action,uri,categories,extras key,extras value,ic3 total,action,uri,categories,extras key,extras value"+newLine);
		cFile.close();
		c2File = new FileWriter("compare_noev.txt", true);
		c2File.write("apkName,total,action,uri,categories,extras key,phenomenon total,action,uri,categories,extras key,iccbot total,action,uri,categories,extras key,ic3 total,action,uri,categories,extras key"+newLine);
		c2File.close();

		File targetsFolder = new File(apksFolderPath);
		for (File f : targetsFolder.listFiles()) {
			String apkFilePath = f.getPath();
			String apkName = f.getName();

			iFile = new FileWriter("intentrich-apks.txt", true);
			nFile = new FileWriter("notintentrich-apks.txt", true);
			eFile = new FileWriter("error-apks.txt", true);
			lFile = new FileWriter("log-apks.txt", true);
			cFile = new FileWriter("compare.txt", true);
			c2File = new FileWriter("compare_noev.txt", true);
			tFile = new FileWriter("timedout-apks.txt", true);

			ExecutorService executor = Executors.newSingleThreadExecutor();

			JSONParser ic3parser = new JSONParser();
			JSONParser iccbotparser = new JSONParser();
			JSONParser fwparser = new JSONParser();
			String analysisFolder = args[0]; // root folder with apks and jsons folders
			String fileName = apkName.replaceFirst("[.][^.]+$", "");; // apk filename without extension
			//String apkFilePath = analysisFolder + File.separator + "apks" + File.separator + fileName + ".apk";
			// only iccbot and phenomenon have parser script
			String ic3FilePath = analysisFolder + File.separator + "jsons" + File.separator + "ic3-" + fileName + ".json";
			String ic3ExitsFilePath = analysisFolder + File.separator + "jsons" + File.separator + "ic3-exits-" + fileName + ".json";
			String iccbotFilePath = analysisFolder + File.separator + "jsons" + File.separator + "iccbotp-" + fileName + ".json";
			String fwFilePath = analysisFolder + File.separator + "jsons" + File.separator + "fw-" + fileName + ".json";
			System.out.println(ic3FilePath);
			System.out.println(iccbotFilePath);
			System.out.println(fwFilePath);

			JSONObject ic3obj = null;
			JSONObject ic3exitsobj = null;
			JSONObject iccbotobj = null;
			JSONObject fwobj = null;
			File checkFile = new File(ic3FilePath);
			if (checkFile.isFile()) {
				ic3obj = (JSONObject) ic3parser.parse(new FileReader(ic3FilePath));
			}
			checkFile = new File(ic3ExitsFilePath);
			if (checkFile.isFile()) {
				ic3exitsobj = (JSONObject) ic3parser.parse(new FileReader(ic3ExitsFilePath));
			}
			checkFile = new File(iccbotFilePath);
			if (checkFile.isFile()) {
				iccbotobj = (JSONObject) iccbotparser.parse(new FileReader(iccbotFilePath));
			}
			checkFile = new File(fwFilePath);
			if (checkFile.isFile()) {
				fwobj = (JSONObject) fwparser.parse(new FileReader(fwFilePath));
			}

			Quartet<JSONObject,JSONObject,JSONObject,JSONObject> jsons = new Quartet<>(ic3obj,iccbotobj,fwobj,ic3exitsobj);

			System.out.println("Analyzing apk " + apkFilePath);
			lFile.write("Analyzing apk " + apkFilePath+newLine);
			lFile.close();

			Logger logger = Utils.setupLogger(InstrumentDriverFolderCompare.class, apkName);
			InstrumentTransformerCompare transformer = new InstrumentTransformerCompare(apkFilePath,jsons);

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

/*
			try {
				// only perform categorization and write to file. Does not add instrumentation code
				transformer.run();
			} catch (Exception e) {
				eFile.write(apkName+newLine);
			}
 */

			// analysis
			cFile.write(apkName);
			cFile.write(","+getCompareTotal(transformer.totalCompare, true));
			cFile.write(","+transformer.totalCompare.get("action"));
			cFile.write(","+transformer.totalCompare.get("uri"));
			cFile.write(","+transformer.totalCompare.get("categories"));
			cFile.write(","+transformer.totalCompare.get("extras-key"));
			cFile.write(","+transformer.totalCompare.get("extras-value"));
			cFile.write(","+getCompareTotal(transformer.fwCompare, true));
			cFile.write(","+transformer.fwCompare.get("action"));
			cFile.write(","+transformer.fwCompare.get("uri"));
			cFile.write(","+transformer.fwCompare.get("categories"));
			cFile.write(","+transformer.fwCompare.get("extras-key"));
			cFile.write(","+transformer.fwCompare.get("extras-value"));
			cFile.write(","+getCompareTotal(transformer.iccbotCompare, true));
			cFile.write(","+transformer.iccbotCompare.get("action"));
			cFile.write(","+transformer.iccbotCompare.get("uri"));
			cFile.write(","+transformer.iccbotCompare.get("categories"));
			cFile.write(","+transformer.iccbotCompare.get("extras-key"));
			cFile.write(","+transformer.iccbotCompare.get("extras-value"));
			cFile.write(","+getCompareTotal(transformer.ic3Compare, true));
			cFile.write(","+transformer.ic3Compare.get("action"));
			cFile.write(","+transformer.ic3Compare.get("uri"));
			cFile.write(","+transformer.ic3Compare.get("categories"));
			cFile.write(","+transformer.ic3Compare.get("extras-key"));
			cFile.write(","+transformer.ic3Compare.get("extras-value")+newLine);

			c2File.write(apkName);
			c2File.write(","+getCompareTotal(transformer.totalCompare, false));
			c2File.write(","+transformer.totalCompare.get("action"));
			c2File.write(","+transformer.totalCompare.get("uri"));
			c2File.write(","+transformer.totalCompare.get("categories"));
			c2File.write(","+transformer.totalCompare.get("extras-key"));
			c2File.write(","+getCompareTotal(transformer.fwCompare, false));
			c2File.write(","+transformer.fwCompare.get("action"));
			c2File.write(","+transformer.fwCompare.get("uri"));
			c2File.write(","+transformer.fwCompare.get("categories"));
			c2File.write(","+transformer.fwCompare.get("extras-key"));
			c2File.write(","+getCompareTotal(transformer.iccbotCompare, false));
			c2File.write(","+transformer.iccbotCompare.get("action"));
			c2File.write(","+transformer.iccbotCompare.get("uri"));
			c2File.write(","+transformer.iccbotCompare.get("categories"));
			c2File.write(","+transformer.iccbotCompare.get("extras-key"));
			c2File.write(","+getCompareTotal(transformer.ic3Compare, false));
			c2File.write(","+transformer.ic3Compare.get("action"));
			c2File.write(","+transformer.ic3Compare.get("uri"));
			c2File.write(","+transformer.ic3Compare.get("categories"));
			c2File.write(","+transformer.ic3Compare.get("extras-key")+newLine);

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
		}
	}
}