package aaa.bbb.ccc.path.analyses.extradata;

import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import aaa.bbb.ccc.path.analyses.ConstantValueInitTransformer;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerSpEval;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerSpEvalIntra;
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

public class StaticEvalUseDriverFolderFolder {

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

		//String apksFolderPath = args[0] + File.separator + "apks";
		String apksFolderFolderPath = args[0];
		String newLine = System.getProperty("line.separator");

//		FileWriter iFile = new FileWriter("intentrich-apks.txt");
//		FileWriter nFile = new FileWriter("notintentrich-apks.txt");
		FileWriter eFile = new FileWriter("error-apks2.txt");
		FileWriter lFile = new FileWriter("log-apks2.txt");
		FileWriter cFile = new FileWriter("compare2.txt");
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
		//c2File.close();
		cFile = new FileWriter("compare2.txt", true);
		cFile.write("apkName,cis,total,phenomenon,ic3,iccbot (A,R,S)"+newLine);
		cFile.close();
		//c2File = new FileWriter("compare2-noev.txt", true);
		//c2File.write("apkName,cis,total,phenomenon,ic3,iccbot"+newLine);
		//c2File.close();
		ccFile = new FileWriter("catsv2.txt", true);
		ccFile.write("apkName,intent control-statements,action,uri,uri-nullness,extras-key,extras-value,bundleExtras-key,bundleExtras-value,category,array-extras-value (A,R,S)"+newLine);
		ccFile.close();

		File targetsFolders = new File(apksFolderFolderPath);
		for (File folder : targetsFolders.listFiles()) {

			String folderPath = folder.getPath();
			String folderName = folder.getName();

			for (File f : folder.listFiles()) {
				String apkFilePath = f.getPath();
				String apkName = f.getName();

				if (!apkFilePath.endsWith("apk")) {
					continue;
				}

				eFile = new FileWriter(folderName+"_error-apks2.txt", true);
				lFile = new FileWriter(folderName+"_log-apks2.txt", true);
				cFile = new FileWriter(folderName+"_compare2.txt", true);
				tFile = new FileWriter(folderName+"_timedout2-apks.txt", true);
				ccFile = new FileWriter(folderName+"_catsv2.txt", true);

				ExecutorService executor = Executors.newSingleThreadExecutor();

				String analysisFolder = args[0]; // root folder with apks and jsons folders
				String fileName = apkName.replaceFirst("[.][^.]+$", "");
				; // apk filename without extension
				//String apkFilePath = analysisFolder + File.separator + "apks" + File.separator + fileName + ".apk";
				// only iccbot and phenomenon have parser script

				List jsons = null;

				System.out.println("Analyzing apk " + apkFilePath);
				lFile.write("Analyzing apk " + apkFilePath + newLine);
				lFile.close();

				//Logger logger = Utils.setupLogger(StaticEvalUseDriverFolder.class, apkName);

				// with extra values

				Options.v().set_whole_program(true);
				Options.v().set_time(false);
				Options.v().setPhaseOption("jb", "use-original-names:true");
				PackManager.v().getPack("wjtp").add(new Transform("wjtp.constant", new ConstantValueInitTransformer()));
				PackManager.v().getPack("wjtp").apply();
				TargetedPathTransformerSpEvalIntra teval = new ExtraDataUseTransformerSpEvalIntra(apkFilePath, jsons, true);

				Future future = executor.submit(new Runnable() {
					@Override
					public void run() {
						// only perform categorization and write to file. Does not add instrumentation code
						Utils.applyWholeProgramSootOptions(apkFilePath);
						try {
							teval.main(folderName);
						} catch (IOException e) {
							throw new RuntimeException(e);
						}
					}
				});
				executor.shutdown();
				try {
					future.get(60, TimeUnit.MINUTES);
				} catch (InterruptedException ie) {
					// Handle the interruption. Or ignore it
				} catch (ExecutionException ee) {
					// Handle the error. Or ignore it.
					eFile.write(apkName + newLine);
				} catch (TimeoutException te) {
					// Handle the timeout. Or ignore it
					tFile.write(apkName + newLine);
				}
				if (!executor.isTerminated())
					// stop the code that hasn't finished
					executor.shutdownNow();

				int action = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCounts.get("action");
				int serial = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCounts.get("serial");
				int uri = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCounts.get("uri");
				int uri_nullness = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCounts.get("uri-nullness");
				int extras_key = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCounts.get("extras-key");
				int extras_value = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCounts.get("extras-value");
				int bundleextras_key = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCounts.get("bundleExtras-key");
				int bundleextras_value = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCounts.get("bundleExtras-value");
				int category = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCounts.get("category");
				int total = action + serial + uri + uri_nullness + extras_key + extras_value + bundleextras_key + bundleextras_value + category;
				ccFile.write(apkName + "," + total);
				ccFile.write("," + action);
				ccFile.write("," + serial);
				ccFile.write("," + uri);
				ccFile.write("," + uri_nullness);
				ccFile.write("," + extras_key);
				ccFile.write("," + extras_value);
				ccFile.write("," + bundleextras_key);
				ccFile.write("," + bundleextras_value);
				ccFile.write("," + category + newLine);

				/*
				int action = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsA.get("action");
				int serial = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsA.get("serial");
				int uri = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsA.get("uri");
				int uri_nullness = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsA.get("uri-nullness");
				int extras_key = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsA.get("extras-key");
				int extras_value = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsA.get("extras-value");
				int bundleextras_key = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsA.get("bundleExtras-key");
				int bundleextras_value = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsA.get("bundleExtras-value");
				int category = ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsA.get("category");
				int total = action + serial + uri + uri_nullness + extras_key + extras_value + bundleextras_key + bundleextras_value + category;
				ccFile.write(apkName + "," + total);
				ccFile.write("," + action);
				ccFile.write("," + serial);
				ccFile.write("," + uri);
				ccFile.write("," + uri_nullness);
				ccFile.write("," + extras_key);
				ccFile.write("," + extras_value);
				ccFile.write("," + bundleextras_key);
				ccFile.write("," + bundleextras_value);
				ccFile.write("," + category);

				action = action + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsR.get("action");
				serial = serial +  ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsR.get("serial");
				uri = uri + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsR.get("uri");
				uri_nullness = uri_nullness + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsR.get("uri-nullness");
				extras_key = extras_key + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsR.get("extras-key");
				extras_value = extras_value + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsR.get("extras-value");
				bundleextras_key = bundleextras_key + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsR.get("bundleExtras-key");
				bundleextras_value = bundleextras_value + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsR.get("bundleExtras-value");
				category = category + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsR.get("category");
				total = action + serial + uri + uri_nullness + extras_key + extras_value + bundleextras_key + bundleextras_value + category;
				ccFile.write("," + total);
				ccFile.write("," + action);
				ccFile.write("," + uri);
				ccFile.write("," + uri_nullness);
				ccFile.write("," + extras_key);
				ccFile.write("," + extras_value);
				ccFile.write("," + bundleextras_key);
				ccFile.write("," + bundleextras_value);
				ccFile.write("," + category);

				action = action + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsS.get("action");
				serial = serial + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsS.get("serial");
				uri = uri + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsS.get("uri");
				uri_nullness = uri_nullness + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsS.get("uri-nullness");
				extras_key = extras_key + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsS.get("extras-key");
				extras_value = extras_value + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsS.get("extras-value");
				bundleextras_key = bundleextras_key + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsS.get("bundleExtras-key");
				bundleextras_value = bundleextras_value + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsS.get("bundleExtras-value");
				category = category + ((TargetedPathTransformerSpEvalIntra) teval).intentCatCountsS.get("category");
				total = action + serial + uri + uri_nullness + extras_key + extras_value + bundleextras_key + bundleextras_value + category;
				ccFile.write("," + total);
				ccFile.write("," + action);
				ccFile.write("," + serial);
				ccFile.write("," + uri);
				ccFile.write("," + uri_nullness);
				ccFile.write("," + extras_key);
				ccFile.write("," + extras_value);
				ccFile.write("," + bundleextras_key);
				ccFile.write("," + bundleextras_value);
				ccFile.write("," + category + newLine);
				 */

				//iFile.close();
				//nFile.close();
				eFile.close();
				cFile.close();
				//c2File.close();
				tFile.close();
				ccFile.close();
			}
		}
	}
}