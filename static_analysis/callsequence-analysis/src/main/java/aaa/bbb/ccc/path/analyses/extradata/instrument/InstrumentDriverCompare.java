package aaa.bbb.ccc.path.analyses.extradata.instrument;

import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class InstrumentDriverCompare {

	//public static int instrumentStatementCnt = 1;
	private static AndroidProcessor androidProcessor = new AndroidProcessor();
	public static void main(String[] args) throws IOException, ParseException {


		StopWatch allPhaseStopWatch = new StopWatch();
		allPhaseStopWatch.start();

		JSONParser ic3parser = new JSONParser();
		JSONParser iccbotparser = new JSONParser();
		JSONParser fwparser = new JSONParser();


		String analysisFolder = args[0]; // root folder with apks and jsons folders
		String fileName = args[1]; // apk filename without extension
		String apkFilePath = analysisFolder + File.separator + "apks" + File.separator + fileName + ".apk";

		Logger logger = Utils.setupLogger(InstrumentDriverCompare.class, fileName + ".apk");

		// only iccbot and phenomenon have parser script
		String ic3FilePath = analysisFolder + File.separator + "jsons" + File.separator + "ic3-" + fileName + ".json";
		String ic3ExitsFilePath = analysisFolder + File.separator + "jsons" + File.separator + "ic3-exits-" + fileName + ".json";
		String iccbotFilePath = analysisFolder + File.separator + "jsons" + File.separator + "iccbotp-" + fileName + ".json";
		String fwFilePath = analysisFolder + File.separator + "jsons" + File.separator + "fw-" + fileName + ".json";

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
		InstrumentTransformerCompare transformer = new InstrumentTransformerCompare(apkFilePath, jsons);

		transformer.run();

		// output analysis result
		System.out.println("Total:");
		System.out.println("    action: " + transformer.totalCompare.get("action"));
		System.out.println("    uri: " + transformer.totalCompare.get("uri"));
		System.out.println("    categories: " + transformer.totalCompare.get("categories"));
		System.out.println("    extras key: " + transformer.totalCompare.get("extras-key"));
		System.out.println("    extras value: " + transformer.totalCompare.get("extras-value"));
		System.out.println("IC3:");
		System.out.println("    action: " + transformer.ic3Compare.get("action"));
		System.out.println("    uri: " + transformer.ic3Compare.get("uri"));
		System.out.println("    categories: " + transformer.ic3Compare.get("categories"));
		System.out.println("    extras key: " + transformer.ic3Compare.get("extras-key"));
		System.out.println("    extras value: " + transformer.ic3Compare.get("extras-value"));
		System.out.println("ICCBot:");
		System.out.println("    action: " + transformer.iccbotCompare.get("action"));
		System.out.println("    uri: " + transformer.iccbotCompare.get("uri"));
		System.out.println("    categories: " + transformer.iccbotCompare.get("categories"));
		System.out.println("    extras key: " + transformer.iccbotCompare.get("extras-key"));
		System.out.println("    extras value: " + transformer.iccbotCompare.get("extras-value"));
		System.out.println("Phenomenon:");
		System.out.println("    action: " + transformer.fwCompare.get("action"));
		System.out.println("    uri: " + transformer.fwCompare.get("uri"));
		System.out.println("    categories: " + transformer.fwCompare.get("categories"));
		System.out.println("    extras key: " + transformer.fwCompare.get("extras-key"));
		System.out.println("    extras value: " + transformer.fwCompare.get("extras-value"));
		// output analysis to log
		logger.debug("Total:");
		logger.debug("    action: " + transformer.totalCompare.get("action"));
		logger.debug("    uri: " + transformer.totalCompare.get("uri"));
		logger.debug("    categories: " + transformer.totalCompare.get("categories"));
		logger.debug("    extras key: " + transformer.totalCompare.get("extras-key"));
		logger.debug("    extras value: " + transformer.totalCompare.get("extras-value"));
		logger.debug("IC3:");
		logger.debug("    action: " + transformer.ic3Compare.get("action"));
		logger.debug("    uri: " + transformer.ic3Compare.get("uri"));
		logger.debug("    categories: " + transformer.ic3Compare.get("categories"));
		logger.debug("    extras key: " + transformer.ic3Compare.get("extras-key"));
		logger.debug("    extras value: " + transformer.ic3Compare.get("extras-value"));
		logger.debug("ICCBot:");
		logger.debug("    action: " + transformer.iccbotCompare.get("action"));
		logger.debug("    uri: " + transformer.iccbotCompare.get("uri"));
		logger.debug("    categories: " + transformer.iccbotCompare.get("categories"));
		logger.debug("    extras key: " + transformer.iccbotCompare.get("extras-key"));
		logger.debug("    extras value: " + transformer.iccbotCompare.get("extras-value"));
		logger.debug("Phenomenon:");
		logger.debug("    action: " + transformer.fwCompare.get("action"));
		logger.debug("    uri: " + transformer.fwCompare.get("uri"));
		logger.debug("    categories: " + transformer.fwCompare.get("categories"));
		logger.debug("    extras key: " + transformer.fwCompare.get("extras-key"));
		logger.debug("    extras value: " + transformer.fwCompare.get("extras-value"));
	}
}