package aaa.bbb.ccc.path.analyses.extradata;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.*;
import org.slf4j.Logger;
import soot.options.Options;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ExtraDataUseDriverFolder {
	@Parameter(description="APK",required=true)
	private List<String> parameters = new ArrayList<>();

	@Parameter(names = { "--functions", "-f" })
	private List<String> functions = new ArrayList<>();

	@Parameter(names={"--parallel","-p"},description="enables parallel per-target-statement analysis")
	boolean parallelEnabled = false;

	@Parameter(names={"--limitpaths","-l"},description="use path limiting per target unit---false disables path limiting, true enables it and is the default",arity=1)
	boolean pathLimitEnabled = true;

	@Parameter(names = {"--z3py","-z"})
	boolean z3py = false;

	@Parameter(names = {"--sharedprefsanalysis","-s"})
	boolean spAnalysis = false;

	@Parameter(names = {"--jnianalysis","-j"})
	boolean jniAnalysis = false;

	@Parameter(names = {"--androlibanalysis","-a"})
	boolean androlibAnalysis = false;

	@Parameter(names = { "--modelnumbers", "-n" }, description = "numbers of unique models")
	public Integer modelNums = 1;

	@Parameter(names = {"--help","-h"}, help = true)
	private boolean help;



	public static void main(String[] args) throws IOException {
		StopWatch allPhaseStopWatch = new StopWatch();
		allPhaseStopWatch.start();

		ExtraDataUseDriverFolder d = new ExtraDataUseDriverFolder();
		JCommander jCommander = new JCommander(d,args);
		jCommander.setProgramName("JCommanderExample");
		if (d.help) {
			jCommander.usage();
			return;
		}
		FileWriter eFile = new FileWriter("phenomenon-error-apks.txt");
		FileWriter lFile = new FileWriter("phenomenon-log-apks.txt");
		eFile.close();
		lFile.close();

		String newLine = System.getProperty("line.separator");
		String apksFolderPath = d.parameters.get(0);
		File targetsFolder = new File(apksFolderPath);
		for (File apkFile : targetsFolder.listFiles()) {
			String name = apkFile.getName();
			String apkName = name.substring(0, name.lastIndexOf('.')) + ".apk";
			eFile = new FileWriter("phenomenon-error-apks.txt", true);
			lFile = new FileWriter("phenomenon-log-apks.txt", true);

			System.out.println("Analyzing apk " + apkFile);
			Logger logger = Utils.setupLogger(ExtraDataUseDriverFolder.class, apkFile.getName());
			lFile.write("Analyzing apk " + apkFile + newLine);
			lFile.close();

			Options.v().set_output_format(Options.output_format_none);
			Options.v().set_time(false);

			TargetedPathTransformerSp tsp = new ExtraDataUseTransformerSp(apkFile.getPath());

			//tsp.parallelEnabled = d.parallelEnabled;
			tsp.parallelEnabled = true;
			tsp.pathLimitEnabled = d.pathLimitEnabled;

			if (tsp.parallelEnabled) {
				System.out.println("Parallelism is enabled");
			} else {
				System.out.println("Parallelism is disabled");
			}

			StopWatch singlePhaseStopWatch = new StopWatch();

			singlePhaseStopWatch.start();
			// add TargetedPathTransformer to the wjtp pack
			try {
				tsp.main(false);
			} catch (Exception e) {
				eFile.write(apkName+newLine);
			}

			singlePhaseStopWatch.stop();
		}
	}
}