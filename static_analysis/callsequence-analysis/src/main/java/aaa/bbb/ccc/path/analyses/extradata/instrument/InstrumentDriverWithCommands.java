//package aaa.bbb.ccc.path.analyses.extradata.instrument;
//
//import aaa.bbb.ccc.StopWatch;
//import aaa.bbb.ccc.Utils;
//import aaa.bbb.ccc.android.AndroidProcessor;
//import aaa.bbb.ccc.path.analyses.TargetedPathTransformer;
//import aaa.bbb.ccc.path.analyses.TargetedPathTransformerSp;
//import aaa.bbb.ccc.path.analyses.extradata.ExtraDataUseDriver;
//import org.slf4j.Logger;
//import soot.options.Options;
//
//import java.io.File;
//
//public class InstrumentDriverWithCommands {
//
//	public static int instrumentStatementCnt = 1;
//	private static AndroidProcessor androidProcessor = new AndroidProcessor();
//	public static void main(String[] args) {
//
//		StopWatch allPhaseStopWatch = new StopWatch();
//		allPhaseStopWatch.start();
//
//		String apkFilePath = args[0];
//		File apkFile = new File(apkFilePath);
//
//		Logger logger = Utils.setupLogger(ExtraDataUseDriver.class,apkFile.getName());
//		Options.v().set_output_format(Options.output_format_dex);
//
//		Options.v().set_output_format(Options.output_format_dex);
//		TargetedPathTransformerSp transformer = new InstrumentTransformer(apkFilePath);
//
//		StopWatch singlePhaseStopWatch = new StopWatch();
//
//		singlePhaseStopWatch.start();
//
//		//remove the apk file from the sootOutputDir, if exists
//			// !!! those three variables should be in the Utils class
//        String sootOutputDir= "./sootOutput/";
//
//        String adbCmdPath = "/Users/Mahmoud/Tools/android-sdk-macosx/platform-tools/adb";
//        String[] arr = apkFilePath.split(File.separator);
//        String apkName = arr[arr.length-1];
//
//        System.out.println("**** remove the previous instrumented apk, if exists ***********");
//        String[] removeApkArgs = {"rm",sootOutputDir+apkName};
//        Utils.runCmdAsProcess(removeApkArgs);
//
//		transformer.main();
//		singlePhaseStopWatch.stop();
//		logger.debug("path analysis time (milliseconds):" + singlePhaseStopWatch.getElapsedTime());
//
//		allPhaseStopWatch.stop();
//		logger.debug("total runtime for all phases (milliseconds):" + allPhaseStopWatch.getElapsedTime());
//
//
//		logger.debug("**** Sign the new apk app ***********");
//        String keystorePath=sootOutputDir+"mahmoud.keystore";
//        String[] signApkArgs = {"jarsigner","-verbose","-sigalg","SHA1withRSA","-digestalg","SHA1","-keystore",keystorePath,"-storepass","mahmoud","-keypass","mahmoud",sootOutputDir+apkName,"mahmoud"};
//        Utils.runCmdAsProcess(signApkArgs);
//
//        logger.debug("**** uninstall the old version of the app in the emulator");
//        androidProcessor.extractApkMetadata(); //we don't need this heavy process to extract the package name
//        String[] adbUninstallAppArgs = {adbCmdPath,"uninstall",androidProcessor.mainPackageName};
//        Utils.runCmdAsProcess(adbUninstallAppArgs);
//
//        logger.debug("**** install the new instrumenmts app on the emulator");
//        String[] adbInstallAppArgs = {adbCmdPath,"install",sootOutputDir+apkName};
//        Utils.runCmdAsProcess(adbInstallAppArgs);
//
//
//
//		logger.debug("Reached end of path executor driver...");
//	}
//
//}
