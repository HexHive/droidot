package aaa.bbb.ccc;

import soot.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.*;


public class GetJimpleNow
{
    public static String apkPath;

    public static void main(String[] args)
    {

        // create out folder if does not exist
        new File("jimples").mkdirs();
        apkPath = args[0];

        System.out.println("### Analyzing APK: " + apkPath);
        Utils.applyWholeProgramSootOptions(apkPath);

        PackManager.v().getPack("jtp").add(new Transform("jtp.getReadableJimple", new BodyTransformer() {
            @Override
            protected void internalTransform(Body b, String phaseName,
                                             Map<String, String> options)
            {
                if(Utils.isAndroidMethod(b.getMethod()))
                    return;

                System.out.println("Method: " + b.getMethod().getSignature());
                // write jimple body to file
                String methodName = b.getMethod().getSignature();
                methodName = methodName.replaceAll("<","_");
                methodName = methodName.replaceAll(">", "_");
                methodName = methodName.replaceAll(":", "_");
                String origin = b.getMethod().getDeclaringClass().getFilePath();
                /*
                if (!origin.startsWith("com.mitake.network")) {
                    return;
                }
                 */
                System.out.println(methodName);

                String newLine = System.getProperty("line.separator");
                String mFilepath = Paths.get("jimples"+ File.separator+origin+"X"+methodName).toString();
                try {
                    // zero-out file content
                    FileWriter f = new FileWriter(mFilepath);
                    f.close();

                    f = new FileWriter(mFilepath);
                    // write Jimple line-by-line
                    Integer lineNumber = 1;
                    Iterator<Unit> units = b.getUnits().iterator();
                    while (units.hasNext()) {
                        Unit unit = units.next();
                        f.write( lineNumber+": "+unit.getJavaSourceStartLineNumber()+": "+unit+newLine);
                        lineNumber += 1;
                    }
                    f.close();
                } catch (IOException e) {
                    return;
                }
            }
        }));
        PackManager.v().runPacks();
    }
}

