package aaa.bbb.ccc.path.analyses.extradata;

import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.ConstantValueInitTransformer;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformerSpEval;
import aaa.bbb.ccc.path.analyses.extradata.instrument.WebViewTransformer;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.DirectoryFileFilter;
import org.apache.commons.io.filefilter.RegexFileFilter;
import org.javatuples.Quartet;
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
import java.util.Collection;
import java.util.concurrent.*;

public class WebViewEval {

    public static void main(String[] args) throws IOException, ParseException {

        String apksFolderPath = args[0];
        String newLine = System.getProperty("line.separator");

        FileWriter eFile = new FileWriter("error-apks2.txt");
        eFile.close();
        FileWriter tFile = new FileWriter("timedout2-apks.txt", true);
        tFile.close();
        FileWriter rFile = new FileWriter("webviews.txt");
        rFile.close();
        rFile = new FileWriter("webviews.txt", true);
        rFile.write("apkName,isWebView,isUri"+newLine);
        rFile.close();

        Collection<File> files = FileUtils.listFiles(
                new File(apksFolderPath),
                new RegexFileFilter(".*apk"),
                DirectoryFileFilter.DIRECTORY
        );
        File targetsFolder = new File(apksFolderPath);
        for (File f : files) {
            String apkFilePath = f.getPath();
            String apkName = f.getName();

            eFile = new FileWriter("error-apks2.txt", true);
            tFile = new FileWriter("timedout2-apks.txt", true);
            rFile = new FileWriter("webviews.txt", true);

            ExecutorService executor = Executors.newSingleThreadExecutor();

            WebViewTransformer wt = new WebViewTransformer(apkFilePath);
            FileWriter finalRFile = rFile;
            Future future = executor.submit(new Runnable() {
                @Override
                public void run() {
                    // only perform categorization and write to file. Does not add instrumentation code
                    //Utils.setupDummyMainMethod(false);  // reducedAnalysis:false
                    try {
                        boolean containsWebview = wt.main(finalRFile);
                        if (!containsWebview)  {
                            finalRFile.write(Config.apkFilePath + ",0,0"+System.getProperty("line.separator"));
                        }
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            });
            executor.shutdown();
            try {
                future.get(20, TimeUnit.MINUTES);
            }
            catch (InterruptedException ie) {
                // Handle the interruption. Or ignore it
                System.out.print("");
            }
            catch (ExecutionException ee) {
                // Handle the error. Or ignore it.
                eFile.write(apkName+newLine);
            }
            catch (TimeoutException te) {
                // Handle the timeout. Or ignore it
                tFile.write(apkName+newLine);
            }
            if (!executor.isTerminated()) {
                // stop the code that hasn't finished
                executor.shutdownNow();
            }

            eFile.close();
            tFile.close();
            rFile.close();
        }
    }
}
