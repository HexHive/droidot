package aaa.bbb.ccc.path.analyses.extradata;

import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import aaa.bbb.ccc.path.analyses.ConstantValueInitTransformer;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerSpEval;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerSpEvalControlled;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
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

public class StaticEvalUseDriverFolderControlled {

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

		String evalFolderPath = args[0] + File.separator + "annotations";
		String newLine = System.getProperty("line.separator");

		FileWriter eFile = new FileWriter("cerror.txt");
		FileWriter lFile = new FileWriter("clog.txt");
		FileWriter cFile = new FileWriter("ceval.txt");  // eval results
		FileWriter tFile = new FileWriter("ctimedout.txt");
		tFile.close();
		eFile.close();
		lFile.close();
		cFile.close();
		cFile = new FileWriter("ceval.txt", true);
		cFile.write("apkName,cis,total,phenomenon,ic3,iccbot (A,R,S)"+newLine);
		cFile.close();

		File targetsFolder = new File(evalFolderPath);
		for (File f : targetsFolder.listFiles()) {
			String aFilePath = f.getPath();
			String aName = f.getName();
			String apkName = aName.substring(0, aName.length() - 5);

			if (!aFilePath.endsWith("json")) {
				// could be .txt file for extra annotation information
				continue;
			}

			eFile = new FileWriter("cerror.txt", true);
			lFile = new FileWriter("clog.txt", true);
			cFile = new FileWriter("ceval.txt", true);
			tFile = new FileWriter("timedout2-apks.txt", true);

			ExecutorService executor = Executors.newSingleThreadExecutor();

			JSONParser ic3parser = new JSONParser();
			JSONParser iccbotparser = new JSONParser();
			JSONParser fwparser = new JSONParser();   // PHENOM with Analysis-Specific Callgraph
			JSONParser fwiparser = new JSONParser();  // original PHENOM
			JSONParser faxparser = new JSONParser();
			JSONParser lbparser = new JSONParser();
			JSONParser aparser = new JSONParser();
			String analysisFolder = args[0];  // root folder with annotated apk jsons and tools' results jsons folders
			String fileName = apkName.replaceFirst("[.][^.]+$", "");; // apk filename without extension
			//String apkFilePath = analysisFolder + File.separator + "apks" + File.separator + fileName + ".apk";
			// only iccbot and phenomenon have parser script
			String ic3FilePath = analysisFolder + File.separator + "jsons" + File.separator + "ic3-" + fileName + ".json";
			String ic3ExitsFilePath = analysisFolder + File.separator + "jsons" + File.separator + "ic3-exits-" + fileName + ".json";
			String iccbotFilePath = analysisFolder + File.separator + "jsons" + File.separator + "iccbotp-" + fileName + ".json";
			String fwFilePath = analysisFolder + File.separator + "jsons" + File.separator + "fw-" + fileName + "_O_.json";
			String fwiFilePath = analysisFolder + File.separator + "jsons" + File.separator + "fw-" + fileName + "_P_.json";
			String faxFilePath = analysisFolder + File.separator + "jsons" + File.separator + "x-" + fileName + ".json";
			String lbFilePath = analysisFolder + File.separator + "jsons" + File.separator + "fw-" + fileName + "_L_.json";
			// annotated json filepath (aFilePath)

			JSONObject ic3obj = null;
			JSONObject ic3exitsobj = null;
			JSONObject iccbotobj = null;
			JSONObject fwobj = null;
			JSONObject fwiobj = null;
			JSONObject faxobj = null;
			JSONObject lbobj = null;
			JSONObject aobj = null;

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
			checkFile = new File(aFilePath);
			if (checkFile.isFile()) {
				aobj = (JSONObject) aparser.parse(new FileReader(aFilePath));
			}
			List jsons;

			if (iccbotobj==null && ic3obj==null && ic3exitsobj==null && fwobj==null && fwiobj==null && faxobj==null && lbobj==null && aobj == null) {
				jsons = null;
				eFile.write(apkName+":missing json:"+newLine);
			} else {
				jsons = new ArrayList<>();
				jsons.add(ic3obj);
				jsons.add(iccbotobj);
				jsons.add(fwobj);
				jsons.add(ic3exitsobj);
				jsons.add(faxobj);
				jsons.add(fwiobj);
				jsons.add(lbobj);
				jsons.add(aobj);
			}

			System.out.println("Analyzing apk " + aFilePath);
			lFile.write("Analyzing apk " + aFilePath+newLine);
			lFile.close();

			Options.v().set_whole_program(true);
			Options.v().set_time(false);
			Options.v().setPhaseOption("jb", "use-original-names:true");
			PackManager.v().getPack("wjtp").add(new Transform("wjtp.constant", new ConstantValueInitTransformer()));
			PackManager.v().getPack("wjtp").apply();
			TargetedPathTransformerSpEvalControlled teval = new TargetedPathTransformerSpEvalControlled(jsons);
			Future future = executor.submit(new Runnable() {
				@Override
				public void run() {
					try {
						teval.main();
					} catch (IOException e) {
						throw new RuntimeException(e);
					}
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

			eFile.close();
			cFile.close();
			tFile.close();
		}
	}
}