//package aaa.bbb.ccc.path.analyses.extradata.instrument;
//
//import aaa.bbb.ccc.StopWatch;
//import aaa.bbb.ccc.Utils;
//import org.slf4j.Logger;
//
//import java.io.BufferedWriter;
//import java.io.File;
//import java.io.FileWriter;
//import java.nio.file.*;
//
///**
// * Created by Mahmoud on 2/12/17.
// */
//public class RunFileTargetsInstrumentTransformerDir {
////    private static String LOG_PATH = "~/IdeaProjects/phenomenon/logs/RunFileTargetsInstrumentTransformerDir.log";
////    private static String WARNING_LOG_PATH = "~/IdeaProjects/phenomenon/logs/RunFileTargetsInstrumentTransformerDir_Warning.log";
//
//    public static void main(String[] args){
//
//        if (args.length!=2){
//            printUsage();
//        }
//
//        String apksPath = args[0];
////        String utilizedApks = apksPath+File.separator+"utilized"; // a directory to move the utilized apk files
//        String targetsPath = args[1];
////        String utilizedTargets = targetsPath+File.separator+"utilized"; //a directory to move the utilized target files
//
////        File dir = new File(apksPath);
//        String[] paths = apksPath.split(File.separator);
//        Logger logger = Utils.setupLogger(RunFileTargetsInstrumentTransformerDir.class,paths[paths.length-1]);
//        logger.info("run RunFileTargetsInstrumentTransformerDir on "+apksPath);
//        logger.info("apk path,target path,instrumentation time(ms)");
//        String apkPath=null;
//        String targetPath=null;
//        File targetsDir = new File(targetsPath);
//
//        try {
//            String apk=null;
//
//            for (String target : targetsDir.list()) {
//                if (target.endsWith(".txt")) {
//                    try {
//                        apk = target.replace("_nic_ic_tgt_units.txt","");
//                        apkPath = apksPath + File.separator + apk;
//                        targetPath = targetsPath + File.separator + target;
//                        if (Files.exists(Paths.get(apkPath))) {
//                            StopWatch stopWatch = new StopWatch();
//                            stopWatch.start();
//                            FileTargetsInstrumentTransformer.main(new String[]{"-a", apkPath, "-t", targetPath});
//                            stopWatch.stop();
//                            logger.info(apkPath + "," + targetPath + "," + stopWatch.getElapsedTime());
//                            //move the apk file and its target files to a different directory
////                            Files.move(Paths.get(apkPath), Paths.get(utilizedApks + File.separator + apk));
////                            Files.move(Paths.get(targetPath), Paths.get(utilizedTargets + File.separator + apk + "_nic_ic_tgt_units.txt"));
//                        } else {
////                            String warnSTatement = "Warning: target file " + targetPath + " for apk " + apk + " is not exists\n";
////                            Files.write(logPath, warnSTatement.getBytes(), StandardOpenOption.APPEND);
//                        }
//                    } catch (Exception x) {
////                        String warnSTatement = "Exception: target file " + targetPath + " for apk " + apk + " "+x.getMessage()+"\n";
////                        Files.write(logPath, warnSTatement.getBytes(), StandardOpenOption.APPEND);
//                    }
//                }
//            }
//        }catch(Exception e){
//            e.printStackTrace();
//        }
//    }
//
//    public static void printUsage(){
//        System.out.println("RunFileTargetsInstrumentTransformerDir apkDir targetDir");
//        System.out.println("Each of apkDir and targetDir should contain a directory called \"utilized\" to copy the utilized apks to it.");
//    }
//}
