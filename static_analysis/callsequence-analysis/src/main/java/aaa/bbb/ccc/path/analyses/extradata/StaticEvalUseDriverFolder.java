package aaa.bbb.ccc.path.analyses.extradata;

import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import aaa.bbb.ccc.path.analyses.ConstantValueInitTransformer;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerSpEval;
import aaa.bbb.ccc.path.analyses.extradata.instrument.InstrumentTransformerCompare;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import soot.PackManager;
import soot.Transform;
import soot.options.Options;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

public class StaticEvalUseDriverFolder {

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

//		FileWriter iFile = new FileWriter("intentrich-apks.txt");
//		FileWriter nFile = new FileWriter("notintentrich-apks.txt");
		FileWriter eFile = new FileWriter("error-apks2.txt");
		FileWriter lFile = new FileWriter("log-apks2.txt");
		FileWriter cFile = new FileWriter("compare2.txt");
		FileWriter c2File = new FileWriter("compare2-pi.txt");
		//FileWriter c2File = new FileWriter("compare2-noev.txt");
		FileWriter tFile = new FileWriter("timedout2-apks.txt");
		FileWriter ccFile = new FileWriter("catsv2.txt");
		ccFile.close();
		tFile.close();
//		iFile.close();
//		nFile.close();
		eFile.close();
		lFile.close();
		cFile.close();
		c2File.close();
		cFile = new FileWriter("compare2.txt", true);
		cFile.write("apkName,cis,total,phenomenon,ic3,iccbot (A,R,S)"+newLine);
		cFile.close();
		c2File = new FileWriter("compare2-pi.txt", true);
		c2File.write("apkName,cis,total,phenomenon,ic3,iccbot (A,R,S)"+newLine);
		c2File.close();
		ccFile = new FileWriter("catsv2.txt", true);
		ccFile.write("apkName,intent control-statements,action,uri,uri-nullness,extras-key,extras-value,bundleExtras-key,bundleExtras-value,category,array-extras-value (A,R,S)"+newLine);
		ccFile.close();

		File targetsFolder = new File(apksFolderPath);
		for (File f : targetsFolder.listFiles()) {
			String apkFilePath = f.getPath();
			String apkName = f.getName();

			if (!apkFilePath.endsWith("apk")) {
				continue;
			}

//			iFile = new FileWriter("intentrich-apks.txt", true);
//			nFile = new FileWriter("notintentrich-apks.txt", true);
			eFile = new FileWriter("error-apks2.txt", true);
			lFile = new FileWriter("log-apks2.txt", true);
			cFile = new FileWriter("compare2.txt", true);
			c2File = new FileWriter("compare2-pi.txt", true);
			tFile = new FileWriter("timedout2-apks.txt", true);
			ccFile = new FileWriter("catsv2.txt", true);

			ExecutorService executor = Executors.newSingleThreadExecutor();

			JSONParser ic3parser = new JSONParser();
			JSONParser iccbotparser = new JSONParser();
			JSONParser fwparser = new JSONParser();
			JSONParser fwcparser = new JSONParser();
			JSONParser fwiparser = new JSONParser();
			JSONParser faxparser = new JSONParser();
			JSONParser lbparser = new JSONParser();
			String analysisFolder = args[0]; // root folder with apks and jsons folders
			String fileName = apkName.replaceFirst("[.][^.]+$", "");; // apk filename without extension
			//String apkFilePath = analysisFolder + File.separator + "apks" + File.separator + fileName + ".apk";
			// only iccbot and phenomenon have parser script
			String ic3FilePath = analysisFolder + File.separator + "jsons" + File.separator + "ic3-" + fileName + ".json";
			String ic3ExitsFilePath = analysisFolder + File.separator + "jsons" + File.separator + "ic3-exits-" + fileName + ".json";
			String iccbotFilePath = analysisFolder + File.separator + "jsons" + File.separator + "iccbotp-" + fileName + ".json";
			String fwFilePath = analysisFolder + File.separator + "jsons" + File.separator + "fw-" + fileName + "_P_.json";
			String fwcFilePath = analysisFolder + File.separator + "jsons" + File.separator + "fw-" + fileName + "_R_.json";
			String fwiFilePath = analysisFolder + File.separator + "jsons" + File.separator + "fw-intra2_" + fileName + "_K_.json";
			String faxFilePath = analysisFolder + File.separator + "jsons" + File.separator + "x-" + fileName + ".json";
			String lbFilePath = analysisFolder + File.separator + "jsons" + File.separator + "fw-" + fileName + "_L_.json";
			System.out.println(ic3FilePath);
			System.out.println(iccbotFilePath);
			System.out.println(fwFilePath);
			System.out.println(fwcFilePath);
			System.out.println(fwiFilePath);
			System.out.println(lbFilePath);
			JSONObject ic3obj = null;
			JSONObject ic3exitsobj = null;
			JSONObject iccbotobj = null;
			JSONObject fwobj = null;
			JSONObject fwcobj = null;
			JSONObject fwiobj = null;
			JSONObject faxobj = null;
			JSONObject lbobj = null;
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
			checkFile = new File(fwcFilePath);
			if (checkFile.isFile()) {
				//fwcobj = (JSONObject) fwcparser.parse(new FileReader(fwcFilePath));
				// we don't evaluate with callgraph reduction
				fwcobj = null;
			}
			checkFile = new File(fwiFilePath);
			if (checkFile.isFile()) {
				fwiobj = (JSONObject) fwiparser.parse(new FileReader(fwiFilePath));
			}
			checkFile = new File(faxFilePath);
			if (checkFile.isFile()) {
				faxobj = (JSONObject) faxparser.parse(new FileReader(faxFilePath));
			}
			checkFile = new File(lbFilePath);
			if (checkFile.isFile()) {
				lbobj = (JSONObject) lbparser.parse(new FileReader(lbFilePath));
			}
			List jsons;

			if (iccbotobj==null && ic3obj==null && ic3exitsobj==null && fwobj==null && fwcobj==null && fwiobj==null && faxobj==null && lbobj==null) {
				jsons = null;
			} else {
				jsons = new ArrayList<>();
				jsons.add(ic3obj);
				jsons.add(iccbotobj);
				jsons.add(fwobj);
				jsons.add(ic3exitsobj);
				jsons.add(faxobj);
				jsons.add(fwcobj);
				jsons.add(fwiobj);
				jsons.add(lbobj);
			}

			System.out.println("Analyzing apk " + apkFilePath);
			lFile.write("Analyzing apk " + apkFilePath+newLine);
			lFile.close();

			//Logger logger = Utils.setupLogger(StaticEvalUseDriverFolder.class, apkName);

			// with extra values

			Options.v().set_whole_program(true);
			Options.v().set_time(false);
			Options.v().setPhaseOption("jb", "use-original-names:true");
			PackManager.v().getPack("wjtp").add(new Transform("wjtp.constant", new ConstantValueInitTransformer()));
			PackManager.v().getPack("wjtp").apply();
			TargetedPathTransformerSpEval teval = new ExtraDataUseTransformerSpEval(apkFilePath, jsons, true);
//			teval.pathInsensitiveEval = true;
			Future future = executor.submit(new Runnable() {
				@Override
				public void run() {
					// only perform categorization and write to file. Does not add instrumentation code
                    Utils.setupDummyMainMethod();  // reducedAnalysis:false
					teval.main(false);
				}
			});
			executor.shutdown();
			try {
				future.get(60, TimeUnit.MINUTES);
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
				teval.main(false);
			} catch (Exception e) {
				eFile.write(apkName+",with extra values"+newLine);
			}
			 */

			/*
			// without extra values
			TargetedPathTransformerSpEval teval2 = new ExtraDataUseTransformerSpEval(apkFilePath, jsons, false);
			Options.v().set_whole_program(true);
			Options.v().set_time(false);
			Options.v().setPhaseOption("jb", "use-original-names:true");
			PackManager.v().getPack("wjtp").add(new Transform("wjtp.constant", new ConstantValueInitTransformer()));
			PackManager.v().getPack("wjtp").apply();
			try {
				// only perform categorization and write to file. Does not add instrumentation code
				Utils.setupDummyMainMethod(false);
				teval2.main(false);
			} catch (Exception e) {
				eFile.write(apkName+",with extra values"+newLine);
			}

			 */

			// analysis
			cFile.write(apkName);
			cFile.write(","+teval.totalIcs);  // total numbered of Intent-controlled Statements (path-insensitive)

			cFile.write(","+teval.compareOutA.get("cis"));  // total number of ics for category
			cFile.write(","+teval.compareOutA.get("fw-first"));
			cFile.write(","+teval.compareOutA.get("fwc-first"));
			cFile.write(","+teval.compareOutA.get("fwi-first"));
			cFile.write(","+teval.compareOutA.get("lb-first"));
			cFile.write(","+teval.compareOutA.get("fax-first"));
			cFile.write(","+teval.compareOutA.get("ic3-first"));
			cFile.write(","+teval.compareOutA.get("iccbot-first"));
			cFile.write(","+teval.compareOutA.get("total"));  // total number of Intent-controlled paths
			cFile.write(","+teval.compareOutA.get("fw"));
			cFile.write(","+teval.compareOutA.get("fwc"));
			cFile.write(","+teval.compareOutA.get("fwi"));
			cFile.write(","+teval.compareOutA.get("lb"));
			cFile.write(","+teval.compareOutA.get("fax"));
			cFile.write(","+teval.compareOutA.get("ic3"));
			cFile.write(","+teval.compareOutA.get("iccbot"));

			cFile.write(","+teval.compareOutR.get("cis"));
			cFile.write(","+teval.compareOutR.get("fw-first"));
			cFile.write(","+teval.compareOutR.get("fwc-first"));
			cFile.write(","+teval.compareOutR.get("fwi-first"));
			cFile.write(","+teval.compareOutR.get("lb-first"));
			cFile.write(","+teval.compareOutR.get("fax-first"));
			cFile.write(","+teval.compareOutR.get("ic3-first"));
			cFile.write(","+teval.compareOutR.get("iccbot-first"));
			cFile.write(","+teval.compareOutR.get("total"));
			cFile.write(","+teval.compareOutR.get("fw"));
			cFile.write(","+teval.compareOutR.get("fwc"));
			cFile.write(","+teval.compareOutR.get("fwi"));
			cFile.write(","+teval.compareOutR.get("lb"));
			cFile.write(","+teval.compareOutR.get("fax"));
			cFile.write(","+teval.compareOutR.get("ic3"));
			cFile.write(","+teval.compareOutR.get("iccbot"));

			cFile.write(","+teval.compareOutS.get("cis"));
			cFile.write(","+teval.compareOutS.get("fw-first"));
			cFile.write(","+teval.compareOutS.get("fwc-first"));
			cFile.write(","+teval.compareOutS.get("fwi-first"));
			cFile.write(","+teval.compareOutS.get("lb-first"));
			cFile.write(","+teval.compareOutS.get("fax-first"));
			cFile.write(","+teval.compareOutS.get("ic3-first"));
			cFile.write(","+teval.compareOutS.get("iccbot-first"));
			cFile.write(","+teval.compareOutS.get("total"));
			cFile.write(","+teval.compareOutS.get("fw"));
			cFile.write(","+teval.compareOutS.get("fwc"));
			cFile.write(","+teval.compareOutS.get("fwi"));
			cFile.write(","+teval.compareOutS.get("lb"));
			cFile.write(","+teval.compareOutS.get("fax"));
			cFile.write(","+teval.compareOutS.get("ic3"));
			cFile.write(","+teval.compareOutS.get("iccbot")+newLine);

			int action = ((TargetedPathTransformerSpEval) teval).intentCatCountsA.get("action");
			int uri = ((TargetedPathTransformerSpEval) teval).intentCatCountsA.get("uri");
			int uri_nullness = ((TargetedPathTransformerSpEval) teval).intentCatCountsA.get("uri-nullness");
			int extras_key = ((TargetedPathTransformerSpEval) teval).intentCatCountsA.get("extras-key");
			int extras_value = ((TargetedPathTransformerSpEval) teval).intentCatCountsA.get("extras-value");
			int bundleextras_key = ((TargetedPathTransformerSpEval) teval).intentCatCountsA.get("bundleExtras-key");
            int bundleextras_value = ((TargetedPathTransformerSpEval) teval).intentCatCountsA.get("bundleExtras-value");
            int category = ((TargetedPathTransformerSpEval) teval).intentCatCountsA.get("category");
			int total = action+uri+uri_nullness+extras_key+extras_value+bundleextras_key+bundleextras_value+category;
			ccFile.write(apkName+","+total);
			ccFile.write(","+ action);
			ccFile.write(","+ uri);
			ccFile.write(","+ uri_nullness);
			ccFile.write(","+ extras_key);
			ccFile.write(","+ extras_value);
			ccFile.write(","+ bundleextras_key);
			ccFile.write(","+ bundleextras_value);
			ccFile.write(","+ category);
			action = ((TargetedPathTransformerSpEval) teval).intentCatCountsR.get("action");
			uri = ((TargetedPathTransformerSpEval) teval).intentCatCountsR.get("uri");
			uri_nullness = ((TargetedPathTransformerSpEval) teval).intentCatCountsR.get("uri-nullness");
			extras_key = ((TargetedPathTransformerSpEval) teval).intentCatCountsR.get("extras-key");
			extras_value = ((TargetedPathTransformerSpEval) teval).intentCatCountsR.get("extras-value");
			bundleextras_key = ((TargetedPathTransformerSpEval) teval).intentCatCountsR.get("bundleExtras-key");
			bundleextras_value = ((TargetedPathTransformerSpEval) teval).intentCatCountsR.get("bundleExtras-value");
			category = ((TargetedPathTransformerSpEval) teval).intentCatCountsR.get("category");
			total = action+uri+uri_nullness+extras_key+extras_value+bundleextras_key+bundleextras_value+category;
			ccFile.write(","+total);
			ccFile.write(","+ action);
			ccFile.write(","+ uri);
			ccFile.write(","+ uri_nullness);
			ccFile.write(","+ extras_key);
			ccFile.write(","+ extras_value);
			ccFile.write(","+ bundleextras_key);
			ccFile.write(","+ bundleextras_value);
			ccFile.write(","+ category);
			action = ((TargetedPathTransformerSpEval) teval).intentCatCountsS.get("action");
			uri = ((TargetedPathTransformerSpEval) teval).intentCatCountsS.get("uri");
			uri_nullness = ((TargetedPathTransformerSpEval) teval).intentCatCountsS.get("uri-nullness");
			extras_key = ((TargetedPathTransformerSpEval) teval).intentCatCountsS.get("extras-key");
			extras_value = ((TargetedPathTransformerSpEval) teval).intentCatCountsS.get("extras-value");
			bundleextras_key = ((TargetedPathTransformerSpEval) teval).intentCatCountsS.get("bundleExtras-key");
			bundleextras_value = ((TargetedPathTransformerSpEval) teval).intentCatCountsS.get("bundleExtras-value");
			category = ((TargetedPathTransformerSpEval) teval).intentCatCountsS.get("category");
			total = action+uri+uri_nullness+extras_key+extras_value+bundleextras_key+bundleextras_value+category;
			ccFile.write(","+total);
			ccFile.write(","+ action);
			ccFile.write(","+ uri);
			ccFile.write(","+ uri_nullness);
			ccFile.write(","+ extras_key);
			ccFile.write(","+ extras_value);
			ccFile.write(","+ bundleextras_key);
			ccFile.write(","+ bundleextras_value);
			ccFile.write(","+ category+newLine);

			/*
			c2File.write(apkName);
			c2File.write(","+teval2.compareOut.get("cis"));
			c2File.write(","+teval2.compareOut.get("total"));
			c2File.write(","+teval2.compareOut.get("fw"));
			c2File.write(","+teval2.compareOut.get("ic3"));
			c2File.write(","+teval2.compareOut.get("iccbot")+newLine);
			 */

			/*
			if (transformer.getInstrumentStmtCount() >= 10) {
				iFile.write(apkName+","+transformer.getInstrumentStmtCount()+newLine);
			} else {
				nFile.write(apkName+","+transformer.getInstrumentStmtCount()+newLine);
			}
			 */
			//iFile.close();
			//nFile.close();
			eFile.close();
			cFile.close();
			c2File.close();
			tFile.close();
			ccFile.close();
		}
	}
}