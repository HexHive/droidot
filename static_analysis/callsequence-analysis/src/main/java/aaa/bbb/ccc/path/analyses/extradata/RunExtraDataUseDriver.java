package aaa.bbb.ccc.path.analyses.extradata;

import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Date;

 /**
 +  * Created by Mahmoud on 2/10/17.
 +  */
    public class RunExtraDataUseDriver {

//    private static String LOG_PATH = "~/IdeaProjects/phenomenon/logs/RunExtraDataUseDriver.log";

    public static void main(String[] args){

        String dirPath = args[0];
        String targetsPath = args[1];
        File dir = new File(dirPath);
        String[] paths = dirPath.split(File.separator);
        Logger logger = Utils.setupLogger(RunExtraDataUseDriver.class,paths[paths.length-1]);
        logger.info("run RunExtraDataUseDriver on "+dirPath);
        logger.info("apkPath,time(ms)");
        String apkPath;

        try {
//            Path logPath = Paths.get(LOG_PATH);
//            Files.write(logPath, "apkPath,time(ms)\n".getBytes(), StandardOpenOption.CREATE_NEW);

            for (String apk : dir.list()) {
                if (apk.endsWith(".apk")) {
                    apkPath = dirPath + File.separator + apk;
                    StopWatch stopWatch = new StopWatch();
                    stopWatch.start();
                    System.out.println(apkPath);
//                    ExtraDataUseDriver.main(new String[]{apkPath});
                    stopWatch.stop();
                    String logStatement = apkPath + "," + stopWatch.getElapsedTime()+"\n";
//                    Files.write(logPath, logStatement.getBytes(), StandardOpenOption.CREATE_NEW);
                    logger.info(logStatement);
                }
            }

        }catch(Exception e){

        }
    }
}