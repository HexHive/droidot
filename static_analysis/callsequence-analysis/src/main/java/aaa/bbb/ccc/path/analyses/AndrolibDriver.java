package aaa.bbb.ccc.path.analyses;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.google.common.collect.Lists;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.extradata.ExtraDataUseTransformerAndrolib;
import aaa.bbb.ccc.path.analyses.extradata.ExtraDataUseTransformerJni;
import aaa.bbb.ccc.path.analyses.extradata.ExtraDataUseTransformerReach;
import aaa.bbb.ccc.path.analyses.getnatives.*;
// import aaa.bbb.ccc.path.analyses.getnatives.OnTheFlyJimpleBasedICFG;
import aaa.bbb.ccc.path.analyses.getnatives.mustcall.MustCallFrontend;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.Stmt;

import java.io.*;
import java.sql.Array;
import java.util.*;

public class AndrolibDriver {

    @Parameter(description="APK", required=true)
	private List<String> parameters = new ArrayList<>();

	@Parameter(names={"--intra", "-i"}, description="perform intra-procedural analysis for specified passes")
	boolean intraFlag = false;

	@Parameter(names={"--empty", "-z"}, description="perform empty analysis")
	boolean emptyFlag = false;


	@Parameter(names={"--ondemand", "-o"}, description="perform inter-procedural analysis with on-demand callgraphs")
	boolean onDemandFlag = false;

	@Parameter(names={"--mustcall", "-m"}, description="(CFG-based) identify methods that MUST be called once a JNI call is reached")
	boolean mustcallFlag = false;

	@Parameter(names={"--findloop", "-l"}, description="(CFG-based) Given a method signature and a callee, this analysis will help " +
            "identify if the callee is called multiple times inside the method specified by the method signature, specifically if it is in a loop. ")
	boolean findLoopFlag = false;

	@Parameter(names={"--idnative", "-n"}, description="[JNI Identification Pass] identify location (class, method, line) and arguments for each JNI call")
	boolean idnativeFlag = false;

	@Parameter(names={"--jnicallseq", "-j"}, description="(CFG-based) [CFG-based State-Aware Pass] identify JNI call sequence")
	boolean jniCallSeqFlag = false;

	@Parameter(names={"--reachable", "-r"}, description="(CFG-based) [CFG-based Reachability Pass] identify function trace from source to sink")
	boolean reachableFlag = false;

	@Parameter(
			names = { "--SourcesSinks", "-s" },
			description = "file containing the sources and sinks",
			arity = 1,
			required = false
	)
	String sourcesSinks;

	@Parameter(names={"--manifestdriven", "-h"}, description="only analyze code exposed in packages in Manifest and what those packages directly import (fuzzy: for imports, up to package path of 2)")
	boolean manifestFlag = false;

	@Parameter(names={"--constraints", "-c"}, description="(CFG-based) identify constraints on the arguments (intent, string, integer) passed to the native side")
	boolean constraintsFlag = false;

	@Parameter(names={"--parallel", "-p"},description="enables parallel per-target-statement analysis")
	boolean parallelEnabled = false;

	@Parameter(names={"--callback"}, description="enable callback (setting “setEnableCallbacks” to true). This only affects whole-program analysis")
	boolean callbackFlag = false;

	@Parameter(
			names = { "--timeout", "-t" },
			description = "modifies the timeout for path extraction in seconds (default: 180 for \"intraprocedural\" and 1800 for \"whole-program\")",
			arity = 1,
			required = false
	)
	int timeout = 0;

	@Parameter(
			names = { "--block-size", "-b" },
			description = "modifies the basic block size filter to avoid path extraction (default: Integer.MAX_VALUE)",
			arity = 1,
			required = false
	)
	int basicBlockSize = Integer.MAX_VALUE;

	@Parameter(
			names = { "--paths-limit", "-e" },
			description = "modifies the paths extraction limit (default: 1000)",
			arity = 1,
			required = false
	)
	int finalPathsLimit = 1000;

	static Logger logger;

    public static void main(String[] args) throws IOException {
		G.reset();
		AndrolibDriver d = new AndrolibDriver();
		JCommander jCommander = new JCommander(d,args);

        String apkFilePath = d.parameters.get(0);
		File apkFile = new File(apkFilePath);
		String apkName = Utils.getApkJsonNameFromPath(apkFilePath);
		Config.apkFilePath = apkFilePath;
		logger = Utils.setupLogger(AndrolibDriver.class, apkFile.getName());
		logger.debug("Analyzing apk " + apkFile.getName());

		//FileWriter aFile = new FileWriter("androlib.csv", true);
		//StopWatch timer = new StopWatch();
		//timer.start();

		// clear out files
		if (d.idnativeFlag) {
			FileWriter writer = new FileWriter("nativesAnalysis"+File.separator+apkName);
			writer.close();
		}
		if (d.jniCallSeqFlag) {
			FileWriter writer = new FileWriter("nativesAnalysis"+File.separator+"CS_"+apkName);
			writer.close();
		}
		if (d.reachableFlag) {
			FileWriter writer = new FileWriter("nativesAnalysis"+File.separator+"R_"+apkName);
			writer.close();
		}
		if (d.constraintsFlag) {
			FileWriter writer = new FileWriter("nativesAnalysis"+File.separator+"phenomenon_"+apkName);
			writer.close();
		}

		if (d.intraFlag) {
			if (d.timeout == 0) {
				d.timeout = 180;  // 3 minutes
			}
			Utils.applyWholeProgramSootOptions(apkFilePath);
			List<nativeFuncInfo> nativeFuncs = new ArrayList<nativeFuncInfo>();  // needs this for a reachability pass option
			Set<JniCallsSummaries> callsSummaries = new LinkedHashSet<JniCallsSummaries>();
			Set<SrcToSinksReach> srcSinkSummaries = new LinkedHashSet<SrcToSinksReach>();
			Set<varToNative> intents2native = new LinkedHashSet<varToNative>();

			Runtime.getRuntime().addShutdownHook(new Thread() {
				public void run() {
					System.out.println("Shutdown hook ran!");
					try {
						Gson gson = new GsonBuilder().disableHtmlEscaping().create();
						if (d.idnativeFlag) {
							Writer idnativeWriter = new FileWriter("nativesAnalysis" + File.separator + apkName, true);
							String idnativeJson = gson.toJson(nativeFuncs);
							idnativeWriter.write(idnativeJson);
							idnativeWriter.flush();
							idnativeWriter.close();
						}
						if (d.jniCallSeqFlag) {
							Writer jniCallWriter = new FileWriter("nativesAnalysis" + File.separator + "CS_" + apkName, true);
							String jniCallJson = gson.toJson(callsSummaries);
							jniCallWriter.write(jniCallJson);
							jniCallWriter.flush();
							jniCallWriter.close();
						}
						if (d.reachableFlag) {
							Writer reachWriter = new FileWriter("nativesAnalysis" + File.separator + "R_" + apkName, true);
							String reachJson = gson.toJson(srcSinkSummaries);
							reachWriter.write(reachJson);
							reachWriter.flush();
							reachWriter.close();
						}
						if (d.constraintsFlag) {
							Writer cWriter = new FileWriter("nativesAnalysis" + File.separator + "phenomenon_" + apkName, true);
							String cJson = gson.toJson(intents2native);
							cWriter.write(cJson);
							cWriter.flush();
							cWriter.close();
						}
					} catch (IOException ioe) {
						//
					}
				}
			});

			for (SootClass curClass : Scene.v().getApplicationClasses()) {
				if (curClass.isJavaLibraryClass()) {
					continue;
				}
				if (Utils.androidPrefixPkgNames.stream().filter(pkg -> curClass.getFilePath().startsWith(pkg)).count() != 0) {
					// exclude Android libraries
					continue;
				}
				for (SootMethod method : curClass.getMethods()) {
					if (d.emptyFlag) {
						continue;
					}

					if (!method.isConcrete()) {
						continue;
					}

					boolean containsNative = false;
					Iterator<Unit> us = method.retrieveActiveBody().getUnits().snapshotIterator();
					while (us.hasNext()) {
						Unit currUnit = us.next();
						Stmt s = (Stmt) currUnit;
						if (s.containsInvokeExpr()) {
							if (s.getInvokeExpr().getMethod().getDeclaration().contains(" native ")) {
								// method contains JNI calls
								containsNative = true;
								break;
							}
						}
					}
					if (!containsNative) {
						continue;
					}

					boolean flagSpecified = false;
					List<nativeFuncInfo> currNativeFuncs = null;
					if (d.idnativeFlag) {
						flagSpecified = true;
						currNativeFuncs = idNative.main(apkFilePath, method);
						nativeFuncs.addAll(currNativeFuncs);
					}
					if (d.jniCallSeqFlag) {
						flagSpecified = true;
						TargetedPathTransformerJni tjni = new ExtraDataUseTransformerJni(apkFilePath);
						tjni.parallelEnabled = d.parallelEnabled;
						tjni.timeout = d.timeout;
						tjni.basicBlockSize = d.basicBlockSize;
						tjni.finalPathsLimit = d.finalPathsLimit;
						Set<JniCallsSummaries> calls = tjni.main(method);
						callsSummaries.addAll(calls);
					}
					if (d.reachableFlag) {
						flagSpecified = true;
						if (d.sourcesSinks != null) {
							TargetedPathTransformerReach treach = new ExtraDataUseTransformerReach(apkFilePath);
							treach.parallelEnabled = d.parallelEnabled;
							treach.timeout = d.timeout;
							treach.basicBlockSize = d.basicBlockSize;
							treach.finalPathsLimit = d.finalPathsLimit;
							String srcsnsinksFilepath = d.sourcesSinks;
							Set<SrcToSinksReach> reaches = treach.run(srcsnsinksFilepath, method);
							srcSinkSummaries.addAll(reaches);
						} else if (d.idnativeFlag) {
							TargetedPathTransformerReach treach = new ExtraDataUseTransformerReach(apkFilePath);
							treach.parallelEnabled = d.parallelEnabled;
							treach.timeout = d.timeout;
							treach.basicBlockSize = d.basicBlockSize;
							treach.finalPathsLimit = d.finalPathsLimit;
							Set<SrcToSinksReach> reaches = treach.run(nativeFuncs, method);
							srcSinkSummaries.addAll(reaches);
						} else {
							jCommander.usage();
							System.out.println("Need to supply SourcesSinks file (-s)");
							System.exit(0);
						}
					}
					if (d.constraintsFlag) {
						flagSpecified = true;
						TargetedPathTransformerAndrolib tandro = new ExtraDataUseTransformerAndrolib(apkFilePath);
						tandro.parallelEnabled = d.parallelEnabled;
						tandro.timeout = d.timeout;
						tandro.basicBlockSize = d.basicBlockSize;
						tandro.finalPathsLimit = d.finalPathsLimit;
						Set<varToNative> vars = tandro.main(method);
						intents2native.addAll(vars);
					}
					if (!flagSpecified) {
						jCommander.usage();
						System.out.println("MUST specify one or more flags to run analysis!");
					}
				}
			}
		} else if (d.onDemandFlag) {
			if (d.timeout == 0) {
				d.timeout = 180;  // 3 minutes per JNI analysis
			}
			boolean flagSpecified = false;
			Set<JniCallsSummaries> callsSummaries = new LinkedHashSet<JniCallsSummaries>();
			List<nativeFuncInfo> nativeFuncs = new ArrayList<nativeFuncInfo>();
			Set<SrcToSinksReach> srcSinkSummaries = new LinkedHashSet<SrcToSinksReach>();
			Set<varToNative> intents2native = new LinkedHashSet<varToNative>();
			List<nativeFuncInfo> currNativeFuncs = null;
			Set<JniCallsSummaries> calls = null;
			Set<varToNative> vars = null;
			Set<SrcToSinksReach> reaches = null;

			Runtime.getRuntime().addShutdownHook(new Thread() {
				public void run() {
					//System.out.println("Shutdown hook ran!");
					try {
						Gson gson = new GsonBuilder().disableHtmlEscaping().create();
						if (d.idnativeFlag) {
							Writer idnativeWriter = new FileWriter("nativesAnalysis" + File.separator + apkName, true);
							String idnativeJson = gson.toJson(nativeFuncs);
							idnativeWriter.write(idnativeJson);
							idnativeWriter.flush();
							idnativeWriter.close();
						}
						if (d.jniCallSeqFlag) {
							Writer jniCallWriter = new FileWriter("nativesAnalysis" + File.separator + "CS_" + apkName, true);
							String jniCallJson = gson.toJson(callsSummaries);
							jniCallWriter.write(jniCallJson);
							jniCallWriter.flush();
							jniCallWriter.close();
						}
						if (d.reachableFlag) {
							Writer reachWriter = new FileWriter("nativesAnalysis" + File.separator + "R_" + apkName, true);
							String reachJson = gson.toJson(srcSinkSummaries);
							reachWriter.write(reachJson);
							reachWriter.flush();
							reachWriter.close();
						}
						if (d.constraintsFlag) {
							Writer cWriter = new FileWriter("nativesAnalysis" + File.separator + "phenomenon_" + apkName, true);
							String cJson = gson.toJson(intents2native);
							cWriter.write(cJson);
							cWriter.flush();
							cWriter.close();
						}
					} catch (IOException ioe) {
						//
					}
				}
			});

			onDemandCallGraphs onDemandCgs = new onDemandCallGraphs(apkFilePath);
			if (d.sourcesSinks != null) {
				onDemandCgs.sourcesMethodSignatures = getSources(d.sourcesSinks);
			}
			//onDemandCgs.cpre = d.cpre;
			List<List<String>> cgs = onDemandCgs.main();
			if (d.emptyFlag) {
				return;
			}

			for (List<String> cg : cgs) {
				List<SootMethod> updatedcg = new ArrayList<>();
				for (String methodName : Lists.reverse(cg)) {
					updatedcg.add(Scene.v().getMethod(methodName));
				}
				if (d.idnativeFlag) {
					flagSpecified = true;

					currNativeFuncs = idNative.main(apkFilePath, updatedcg, true);
					nativeFuncs.addAll(currNativeFuncs);
				}
				if (d.jniCallSeqFlag) {
					flagSpecified = true;
					TargetedPathTransformerJni tjni = new ExtraDataUseTransformerJni(apkFilePath);
					tjni.parallelEnabled = d.parallelEnabled;
					tjni.timeout = d.timeout;
					tjni.basicBlockSize = d.basicBlockSize;
					tjni.finalPathsLimit = d.finalPathsLimit;
					try {
						calls = tjni.main(updatedcg, true);
					} catch (InterruptedException e) {
						throw new RuntimeException(e);
					}
					callsSummaries.addAll(calls);
				}
				if (d.reachableFlag) {
					flagSpecified = true;
					if (d.sourcesSinks != null) {
						TargetedPathTransformerReach treach = new ExtraDataUseTransformerReach(apkFilePath);
						treach.parallelEnabled = d.parallelEnabled;
						treach.timeout = d.timeout;
						treach.basicBlockSize = d.basicBlockSize;
						treach.finalPathsLimit = d.finalPathsLimit;
						String srcsnsinksFilepath = d.sourcesSinks;
						reaches = treach.run(srcsnsinksFilepath, updatedcg, true);
						srcSinkSummaries.addAll(reaches);
					} else if (d.idnativeFlag) {
						TargetedPathTransformerReach treach = new ExtraDataUseTransformerReach(apkFilePath);
						treach.parallelEnabled = d.parallelEnabled;
						treach.timeout = d.timeout;
						treach.basicBlockSize = d.basicBlockSize;
						treach.finalPathsLimit = d.finalPathsLimit;
						reaches = treach.run(nativeFuncs, updatedcg, true);
						srcSinkSummaries.addAll(reaches);
					} else {
						jCommander.usage();
						System.out.println("Need to supply SourcesSinks file (-s)");
						System.exit(0);
					}
				}
				if (d.constraintsFlag) {
					flagSpecified = true;
					TargetedPathTransformerAndrolib tandro = new ExtraDataUseTransformerAndrolib(apkFilePath);
					tandro.parallelEnabled = d.parallelEnabled;
					tandro.timeout = d.timeout;
					tandro.basicBlockSize = d.basicBlockSize;
					tandro.finalPathsLimit = d.finalPathsLimit;
					vars = tandro.main(updatedcg,true);
					intents2native.addAll(vars);
				}
				if (!flagSpecified) {
					jCommander.usage();
					System.out.println("MUST specify one or more flags to run analysis!");
				}
			}

		} else {
			if (d.timeout == 0) {
				d.timeout = 180;  // 3 minutes per JNI analysis
			}

			// whole program analysis
			PackManager.v().getPack("wjtp")
					.add(new Transform("wjtp.androlib", new SceneTransformer() {
						@Override
						protected void internalTransform(String phaseName, Map<String, String> options) {

							Utils.setupDummyMainMethod(apkFilePath, d.callbackFlag, d.manifestFlag);
							if (d.emptyFlag) {
								return;
							}
							System.out.println("callgraph size: " + Scene.v().getCallGraph().size());
							List<SootMethod> rtoMethods = Utils.retrieveRtoMethods();
							System.out.println("rto methods retrieved: " + rtoMethods.size());

							boolean flagSpecified = false;
							List<nativeFuncInfo> nativeFuncs = null;
							if (d.idnativeFlag) {
								flagSpecified = true;
								nativeFuncs = idNative.main(apkFilePath, rtoMethods, false);
							}
							if (d.jniCallSeqFlag) {
								flagSpecified = true;
								TargetedPathTransformerJni tjni = new ExtraDataUseTransformerJni(apkFilePath);
								tjni.parallelEnabled = d.parallelEnabled;
								tjni.timeout = d.timeout;
								tjni.basicBlockSize = d.basicBlockSize;
								tjni.finalPathsLimit = d.finalPathsLimit;
								try {
									tjni.main(rtoMethods, false);
								} catch (InterruptedException e) {
									throw new RuntimeException(e);
								}
							}
							if (d.constraintsFlag) {
								flagSpecified = true;
								TargetedPathTransformerAndrolib tandro = new ExtraDataUseTransformerAndrolib(apkFilePath);
								tandro.parallelEnabled = d.parallelEnabled;
								tandro.timeout = d.timeout;
								tandro.basicBlockSize = d.basicBlockSize;
								tandro.finalPathsLimit = d.finalPathsLimit;
								tandro.main(rtoMethods,false);
							}
							if (d.findLoopFlag) {
								flagSpecified = true;
								// arg 1: method signature
								// arg 2: callee method name
								if (d.parameters.size() == 3) {
									String[] findLoopArgs = new String[]{apkFilePath, d.parameters.get(1), d.parameters.get(2)};
									FindLoops.main(findLoopArgs);
								} else {
									jCommander.usage();
									System.out.println("Need to supply <method signature> and <callee method name> for findLoop");
									System.exit(0);
								}
							}
							if (d.mustcallFlag) {
								flagSpecified = true;
								if (nativeFuncs == null) {
									// did not specify -n
									nativeFuncs = idNative.main(apkFilePath, rtoMethods, false);
								}

								// arg 1: callee method name
								if (d.parameters.size() == 2) {
									MustCallFrontend.main(apkFilePath, d.parameters.get(1), nativeFuncs);
								} else {
									jCommander.usage();
									System.out.println("Need to supply <method signature> and <callee method name> for mustCall");
									System.exit(0);
								}
							}
							if (d.reachableFlag) {
								flagSpecified = true;
								if (d.sourcesSinks != null) {
									TargetedPathTransformerReach treach = new ExtraDataUseTransformerReach(apkFilePath);
									treach.parallelEnabled = d.parallelEnabled;
									treach.timeout = d.timeout;
									treach.basicBlockSize = d.basicBlockSize;
									treach.finalPathsLimit = d.finalPathsLimit;
									String srcsnsinksFilepath = d.sourcesSinks;
									treach.run(srcsnsinksFilepath, rtoMethods, false);
								} else if (d.idnativeFlag) {
									TargetedPathTransformerReach treach = new ExtraDataUseTransformerReach(apkFilePath);
									treach.parallelEnabled = d.parallelEnabled;
									treach.timeout = d.timeout;
									treach.basicBlockSize = d.basicBlockSize;
									treach.finalPathsLimit = d.finalPathsLimit;
									treach.run(nativeFuncs, rtoMethods, false);
								} else {
									jCommander.usage();
									System.out.println("Need to supply SourcesSinks file (-s)");
									System.exit(0);
								}
							}
							if (!flagSpecified) {
								jCommander.usage();
								System.out.println("MUST specify one or more flags to run analysis!");
							}
							System.exit(0);
						}
					}));
			PackManager.v().getPack("wjtp").apply();
		}

		//timer.stop();
        //aFile.write(apkFilePath + "," + String.valueOf(timer.getElapsedTime() / 1000) + "\n");
		//aFile.close();
	}

	public static Set<String> getSources(String filepath) {
		Set<String> sourcesMethodSignatures = new LinkedHashSet<>();
		try(BufferedReader br = new BufferedReader(new FileReader(filepath))) {
			String sMethodSig = br.readLine();
			while (sMethodSig != null) {
				if (!sMethodSig.startsWith("<")) {
					sMethodSig = br.readLine();
					continue;
				}
				String[] sig = sMethodSig.split(" -> ");
				if (sig.length <= 1) {
					continue;
				}
				if (sig[1].equals("_SOURCE_")) {
					sourcesMethodSignatures.add(sig[0]);
				}
				sMethodSig = br.readLine();
			}
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return sourcesMethodSignatures;
	}
}
