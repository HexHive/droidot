package aaa.bbb.ccc.path.analyses;

import aaa.bbb.ccc.StopWatch;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class AndrolibDriverFolder {

    public static void main(String[] args) throws IOException {
        String apksFolderPath = args[0];
        String newLine = System.getProperty("line.separator");
        FileWriter aFile = new FileWriter("androlib.csv");
        aFile.close();
        FileWriter lFile = new FileWriter("log-androlib.csv");
        lFile.close();
        FileWriter eFile = new FileWriter("err-androlib.csv");
        eFile.close();

        StopWatch timer = new StopWatch();

        File targetsFolder = new File(apksFolderPath);
        for (File f : targetsFolder.listFiles()) {
            aFile = new FileWriter("androlib.csv", true);
            lFile = new FileWriter("log-androlib.csv", true);
            eFile = new FileWriter("err-androlib.csv", true);

            String name = f.getName();
			String apkName = name.substring(0, name.lastIndexOf('.')) + ".apk";
			String apkFilePath = targetsFolder + File.separator + apkName;
			System.out.println("Analyzing apk " + apkFilePath);
            lFile.write(apkFilePath+"\n");
            lFile.close();

            String[] apkArgs = new String[]{"-i", "-j", apkFilePath};
            try {
                timer.start();
                AndrolibDriver.main(apkArgs);
                timer.stop();
                aFile.write(name+","+String.valueOf(timer.getElapsedTime()/1000)+"\n");
            } catch (Exception e) {
                eFile.write(apkFilePath+"\n");
            }
            eFile.close();

            // elapsed time in seconds
            aFile.close();
        }
    }

}
