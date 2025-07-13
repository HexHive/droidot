package aaa.bbb.ccc;

import aaa.bbb.ccc.android.AndroidProcessor;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.*;

public class GetCategories {

    public static void main(String[] args) throws IOException {
        AndroidProcessor androidProcessor = new AndroidProcessor();
        String apksFolderPath = args[0];
        File targetsFolder = new File(apksFolderPath);
        FileWriter file = new FileWriter("getcategories-apks.txt");
        file.close();
        file = new FileWriter("getcategories-apks.txt", true);
        file.write("apkName,categories\n");
        file.close();
        for (File f : targetsFolder.listFiles()) {
            file = new FileWriter("getcategories-apks.txt", true);
            ExecutorService executor = Executors.newSingleThreadExecutor();
            String name = f.getName();
            String apkName = name.substring(0, name.lastIndexOf('.')) + ".apk";
            String apkFilePath = targetsFolder + File.separator + apkName;
            final int[] totalCategories = new int[1];
            Future future = executor.submit(new Runnable() {
                @Override
                public void run() {
                    totalCategories[0] = androidProcessor.extractApkCategories(apkFilePath);
                }
            });
            executor.shutdown();
            try {
                future.get(20, TimeUnit.MINUTES);
            }
            catch (InterruptedException ie) {
                // Handle the interruption. Or ignore it
            }
            catch (ExecutionException ee) {
                // Handle the error. Or ignore it.
            }
            catch (TimeoutException te) {
                // Handle the timeout. Or ignore it
            }
            if (!executor.isTerminated())
                // stop the code that hasn't finished
                executor.shutdownNow();

            file.write(apkName+","+ totalCategories[0] +"\n");
            file.close();
        }
    }
}