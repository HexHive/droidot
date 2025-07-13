package aaa.bbb.ccc.path.analyses;

import com.beust.jcommander.Parameter;

public class FileTargetsOptions {
    @Parameter(names = {"--apk", "-a"}, description = "Path to APK")
    public String apkFilePath;
    @Parameter(names = {"--targets-file", "-t"}, description = "file with targets")
    public String targetsFilePath;
}
