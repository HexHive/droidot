package aaa.bbb.ccc.path.analyses;

import com.beust.jcommander.Parameter;

public class IntentGeneratorOptions extends FileTargetsOptions {

    @Parameter(names = {"--parallel", "-p"}, description = "enables parallel per-target-statement analysis")
    boolean parallelEnabled = false;

    @Parameter(names = {"--limitpaths", "-l"}, description = "use path limiting per target unit---false disables path limiting, true enables it and is the default", arity = 1)
    boolean pathLimitEnabled = true;

    @Parameter(names = {"--targets-folder", "-f"}, description = "folder with target files")
    public String targetsFolder;

    @Parameter(names = {"--apks-folder", "-k"}, description = "folder with apks")
    public String apksFolder;
}
