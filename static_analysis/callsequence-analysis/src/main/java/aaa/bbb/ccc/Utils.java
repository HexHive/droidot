package aaa.bbb.ccc;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.joran.spi.JoranException;
import com.google.common.collect.Lists;
import aaa.bbb.ccc.android.AndroidProcessor;
import aaa.bbb.ccc.path.analyses.IntentPropagation;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.config.SootConfigForAndroid;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.ide.icfg.OnTheFlyJimpleBasedICFG;
import soot.options.Options;
import soot.tagkit.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.SimpleLocalDefs;
import soot.util.Chain;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


public class Utils {

	public static String androidJAR = System.getenv("ANDROID_HOME") + "/android-19/android.jar";
	//public static List<String> exclude = new ArrayList<>(Arrays.asList("java_6_core.*", "android.*", "com.google.android.*", "com.google.protobuf.*", "com.google.crypto.*", "androidx.*", "dummyMainClass*", "java.*", "kotlin.*", "kotlinx.*"));
	public static List<String> exclude = new ArrayList<>();
	public static List<String> androidPrefixPkgNames = Arrays.asList("android.", "com.google.", "com.android.", "dalvik.", "androidx.", "java.", "javax.", "junit.", "org.apache.", "sun.", "org.eclipse.", "soot.", "org.json.", "org.w3c.dom.", "org.xml.sax.", "org.xmlpull.", "kotlin.", "com.facebook.");
	public static List<String> androidExclude = Arrays.asList("android.*", "com.google.android.*", "com.android.*", "dalvik.*", "androidx.*", "java.*", "javax.*", "junit.*", "org.apache.*", "sun.*", "org.eclipse.*", "org.json.*", "org.w3c.dom.*", "org.xml.sax.*", "org.xmlpull.*", "kotlin.*", "com.facebook.*");
	public static Chain<SootClass> appClasses = null;
	public static Set<String> wantedClasses = null;

    public static InfoflowAndroidConfiguration getFlowDroidConfig(String apkPath, String androidJar, InfoflowConfiguration.CallgraphAlgorithm cgAlgorithm, boolean enableCallback) {
        final InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
        config.getAnalysisFileConfig().setTargetAPKFile(apkPath);
        config.getAnalysisFileConfig().setAndroidPlatformDir(androidJar);
        config.setCodeEliminationMode(InfoflowConfiguration.CodeEliminationMode.NoCodeElimination);
        config.setCallgraphAlgorithm(cgAlgorithm);
		config.setMergeDexFiles(true);
		config.setEnableReflection(true);
		//config.getAccessPathConfiguration().setAccessPathLength(0);
		//config.setFlowSensitiveAliasing(false);
		//config.setStaticFieldTrackingMode(InfoflowConfiguration.StaticFieldTrackingMode.None);
		//config.setTaintAnalysisEnabled(false);
		//config.setEnableExceptionTracking(false);
		//config.getAccessPathConfiguration().setUseRecursiveAccessPaths(true);
		//config.getAccessPathConfiguration().setUseSameFieldReduction(true);
		//config.getAccessPathConfiguration().setUseThisChainReduction(true);
		config.getCallbackConfig().setEnableCallbacks(enableCallback);
        return config;
    }

	public static void applyWholeProgramSootOptions(String apkFilePath) {
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_output_format(Options.output_format_dex);
		//Options.v().set_include_all(true);

		Options.v().set_whole_program(false);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_time(false);
		//Options.v().set_exclude(exclude);
		//Options.v().set_on_the_fly(true);

		//Options.v().set_exclude(exclusionList);
		Options.v().set_no_bodies_for_excluded(true);
		//Options.v().set_show_exception_dests(false);
		Options.v().set_verbose(false);
        Options.v().set_process_multiple_dex(true);
		//PhaseOptions.v().setPhaseOption("cg", "verbose:true");
		Options.v().set_android_jars(System.getenv("ANDROID_HOME"));
		List<String> processDirs = new ArrayList<String>();
		processDirs.add(apkFilePath);
		Options.v().set_process_dir(processDirs);
		// to mitigate an Android problem: https://github.com/soot-oss/soot/issues/1019
		Options.v().set_wrong_staticness(Options.wrong_staticness_fix);

		Options.v().set_keep_line_number(true);
		Options.v().set_coffi(true);
		//PackManager.v().runPacks();
		Scene.v().loadNecessaryClasses();
	}

	public static void applyWholeProgramSootOptions() {
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_output_format(Options.output_format_dex);
		//Options.v().set_output_format(Options.output_format_jimple);
		Options.v().set_process_multiple_dex(true);
		//Options.v().set_whole_program(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_time(false);
		//Options.v().set_on_the_fly(true);
		//Options.v().set_exclude(exclusionList);
		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_show_exception_dests(false);
		Options.v().set_verbose(false);
		//PhaseOptions.v().setPhaseOption("cg", "verbose:true");
		Options.v().set_android_jars(System.getenv("ANDROID_HOME"));
		/*
		Options.v().set_soot_classpath(
				Config.apkFilePath + File.pathSeparator + Config.androidJAR + File.pathSeparator + 	System.getenv("ANDROID_SDKS") + "/extras/android/support/v7/appcompat/libs/android-support-v7-appcompat.jar" + File.pathSeparator
						+ System.getenv("ANDROID_SDKS") + "/extras/android/support/v7/appcompat/libs/android-support-v4.jar");
		 */
		List<String> processDirs = new ArrayList<String>();
		processDirs.add(Config.apkFilePath);
		Options.v().set_process_dir(processDirs);
        // to mitigate an Android problem: https://github.com/soot-oss/soot/issues/1019
		Options.v().set_wrong_staticness(Options.wrong_staticness_fix);
		Options.v().set_keep_line_number(true);
		Options.v().set_coffi(true);
		Scene.v().loadNecessaryClasses();
	}

	public static void setExcludeBySources(Set<String> sourcesMethodSignatures) {
		Hierarchy h = Scene.v().getActiveHierarchy();
		appClasses = Scene.v().getClasses();
		// 0: match package as shown in manifest
		// 1: most coarse-grain: ex, com.
		// 2: second most coarse-grain: ex, com.tech.
		wantedClasses = AndroidProcessor.extractEntryPackages(0);
		//exclude.addAll(Options.v().exclude());
		List<String> notExclude = new ArrayList<>();
		for (SootClass curClass : appClasses) {
			if (androidPrefixPkgNames.stream().filter(pkg -> curClass.getFilePath().startsWith(pkg)).count() != 0) {
				exclude.add(curClass.getFilePath());
				continue;
			}
			Boolean isWanted = false;
			// in manifest?
			for (String wClass : wantedClasses) {
				if (curClass.getFilePath().startsWith(wClass)) {
					isWanted = true;
					break;
				}
			}
			// a class with desired input method call?
			if (!isWanted && !sourcesMethodSignatures.isEmpty()) {
				// check for classes that contain sources
				List<SootMethod> cms = new ArrayList<>(curClass.getMethods()); // to avoid concurrent exception
				for (SootMethod m : cms) {
					Body b;
					try {
						b = m.retrieveActiveBody();
					} catch (RuntimeException e) {
						continue;
					}
					Iterator<Unit> us = b.getUnits().snapshotIterator();
					while (us.hasNext()) {
						Unit currUnit = us.next();
						Stmt currStmt = (Stmt) currUnit;
						if (currStmt.containsInvokeExpr()) {
							InvokeExpr ie = currStmt.getInvokeExpr();
							SootMethod calledMethod = ie.getMethod();

							if (sourcesMethodSignatures.contains(calledMethod.getSignature())) {
								// callee is a specified source
								isWanted = true;
								// all classes that subclass current class is not excluded
								if (curClass.hasOuterClass()) {
									notExclude.add(curClass.getOuterClass().getFilePath());
									for (SootClass subclass : h.getDirectSubclassesOf(curClass.getOuterClass())) {
										notExclude.add(subclass.getFilePath());
									}
								} else {
									for (SootClass subclass : h.getDirectSubclassesOf(curClass)) {
										notExclude.add(subclass.getFilePath());
									}
								}
								break;
							}
						}
					}
					if (isWanted) {
						// break out of method iteration
						// since the exclosing class is already determined to be not excluded
						break;
					}
				}
				if (!isWanted) {
					exclude.add(curClass.getFilePath());
				}
			}
		}
		for (String ne : notExclude) {
			exclude.remove(ne);
		}
	}

	public static void setExclude(Set<String> wantedClasses) {
		appClasses = Scene.v().getClasses();

		String oldOuterClass = "";
		for (SootClass curClass : appClasses) {
			/*
			if (androidPrefixPkgNames.stream().filter(pkg -> curClass.getFilePath().startsWith(pkg)).count() != 0) {
				// exclude Android libraries
				exclude.add(curClass.getFilePath());
				continue;
			}
			 */
			if (wantedClasses == null) {
				// manifestDriven flag not set
				continue;
			}

			String curClassPath = curClass.getFilePath();
			String currOuterClass;
			int dollarIdx = curClassPath.indexOf('$');
			if (dollarIdx != -1) {
				currOuterClass = curClassPath.substring(0, dollarIdx);
			} else {
				currOuterClass = curClassPath;
			}

			Boolean isWanted = false;
			// wantedClasses are packages exposed in Manifest + those packages' imports
			for (String wClass : wantedClasses) {
				if (curClass.getFilePath().startsWith(wClass)) {
					isWanted = true;
					/*
					oldOuterClass = currOuterClass;
					if (exclude.contains(currOuterClass)) {
						// previously excluded package turns out to be important
						exclude.remove(currOuterClass);
					}
					 */
					break;
				}
			}

			if (!isWanted){  // && !oldOuterClass.equals(currOuterClass)) {
				// curClass not in wantedClasses
				exclude.add(currOuterClass);
				//exclude.add(curClass.getFilePath());
			}
		}
	}

	public static void setupDummyMainMethod(String apkFilePath, boolean enableCallback, boolean manifestDriven) {
		String fileName = apkFilePath.substring(apkFilePath.lastIndexOf(File.separator)+1, apkFilePath.lastIndexOf('.'));  // without path and extension
		//applyWholeProgramSootOptions(apkFilePath);

		if (manifestDriven) {
			// 0: match package as shown in manifest
			// 1: most coarse-grain: ex, com.
			// 2: second most coarse-grain: ex, com.tech.
			wantedClasses = AndroidProcessor.extractEntryPackages(0);
			// write to wanted pkgs to file
			try {
				BufferedWriter out = new BufferedWriter(new FileWriter("wip"+ File.separator+fileName+"_pkgs.txt"));
				Iterator it = wantedClasses.iterator();
				while(it.hasNext()) {
					out.write((String) it.next());
					out.newLine();
				}
				out.close();
				//Process p = new ProcessBuilder(System.getProperty("user.dir") + File.separator + "getUsedPkgs.sh", Config.apkFilePath).start();
				String[] cmd = new String[]{"/bin/bash", System.getProperty("user.dir") + File.separator + "getUsedPkgs.sh", Config.apkFilePath};
				Process p = Runtime.getRuntime().exec(cmd);
				InputStreamReader isr = new InputStreamReader(p.getInputStream());
				BufferedReader br = new BufferedReader(isr);
				String lineRead;
				while ((lineRead = br.readLine()) != null) {
					wantedClasses.add(lineRead + ".");
				}
				//p.destroy();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
			setExclude(wantedClasses);
		}

		System.out.println("exclude list done: " + exclude.size());
		InfoflowConfiguration.CallgraphAlgorithm cgAlgorithm = InfoflowConfiguration.CallgraphAlgorithm.CHA;
		Config.apkFilePath = apkFilePath;
		final InfoflowAndroidConfiguration config = getFlowDroidConfig(apkFilePath, Utils.androidJAR, cgAlgorithm, enableCallback);
		SetupApplication app = new SetupApplication(config);
		app.setSootConfig(new SootConfigForAndroid() {
		  @Override
		  public void setSootOptions(Options options, InfoflowConfiguration config) {
			super.setSootOptions(options, config); // explicitly exclude packages for shorter runtime
			options.set_keep_line_number(true);
			options.set_print_tags_in_output(true);
		    options.set_src_prec(soot.options.Options.src_prec_apk);
			options.set_output_format(Options.output_format_dex);
    	    // to mitigate an Android problem: https://github.com/soot-oss/soot/issues/1019
			options.set_wrong_staticness(Options.wrong_staticness_fix);
			//exclude.addAll(options.exclude());
			//exclude.addAll(androidExclude);
			//options.set_exclude(exclude);
			//options.set_on_the_fly(true);
			//options.setPhaseOption("cg.cha", "on");
		    //options.setPhaseOption("cg.spark", "enabled,on-fly-cg:true,rta:false,vta:false");
		    options.set_no_bodies_for_excluded(true); // ban Soot from loading the method bodies even if required for CG construction
			//exclude.addAll(options.exclude());
		    //options.set_exclude(exclude);
			options.set_allow_phantom_refs(true);
			options.set_process_multiple_dex(true);
		    //options.set_polyglot(false);
			options.set_whole_program(true);
			options.set_polyglot(false);
		  }
		});
		//app.getConfig().setMergeDexFiles(true);
		//app.getConfig().setEnableReflection(false);
		//app.setCallbackFile("AndroidCallbacks.txt");
		//applyWholeProgramSootOptions();
		//Scene.v().loadNecessaryClasses();
		//applyWholeProgramSootOptions();
		app.constructCallgraph();
	}

	public static void setupDummyMainMethod() {
		Hierarchy h = Scene.v().getActiveHierarchy();
		// initialize new FlowDroid to retrieve CG with Android lifecycle in mind
		InfoflowConfiguration.CallgraphAlgorithm cgAlgorithm = InfoflowConfiguration.CallgraphAlgorithm.SPARK;
		final InfoflowAndroidConfiguration config = getFlowDroidConfig(Config.apkFilePath, Utils.androidJAR, cgAlgorithm, true);
		SetupApplication app = new SetupApplication(config);
		app.setSootConfig(new SootConfigForAndroid() {
		  @Override
		  public void setSootOptions(Options options, InfoflowConfiguration config) {
			super.setSootOptions(options, config); // explicitly exclude packages for shorter runtime
			options.set_keep_line_number(true);
			options.set_print_tags_in_output(true);
		    options.set_src_prec(Options.src_prec_apk);
			options.set_output_format(Options.output_format_dex);
			//options.setPhaseOption("cg.cha", "on");
		    // to mitigate an Android problem: https://github.com/soot-oss/soot/issues/1019
		    options.set_wrong_staticness(Options.wrong_staticness_fix);
		    options.set_no_bodies_for_excluded(true);  // ban Soot from loading the method bodies even if required for CG construction
			//exclude.addAll(options.exclude());
		    //options.set_exclude(exclude);
			//exclude.addAll(androidExclude);
			//options.set_exclude(exclude);
			options.set_allow_phantom_refs(true);
		    options.set_polyglot(false);
			options.set_whole_program(true);
			options.set_process_multiple_dex(true);
			//options.set_android_api_version(23);
			options.set_include_all(true);
		  }
		});
		app.constructCallgraph();
	}

	public static List<SootMethod> setupDummyMainMethodWithCallGraph() {
		// initialize new FlowDroid to retrieve CG with Android lifecycle in mind
		InfoflowConfiguration.CallgraphAlgorithm cgAlgorithm = InfoflowConfiguration.CallgraphAlgorithm.CHA;
		final InfoflowAndroidConfiguration config = getFlowDroidConfig(Config.apkFilePath, Utils.androidJAR, cgAlgorithm, true);
		SetupApplication app = new SetupApplication(config);
		//SetupApplication app = new SetupApplication(Config.androidJAR, Config.apkFilePath);
		app.setSootConfig(new SootConfigForAndroid() {
		  @Override
		  public void setSootOptions(Options options, InfoflowConfiguration config) {
			super.setSootOptions(options, config); // explicitly exclude packages for shorter runtime
			options.set_keep_line_number(true);
			//options.set_print_tags_in_output(true);
		    options.set_src_prec(Options.src_prec_apk);
			options.set_output_format(Options.output_format_dex);
			//options.setPhaseOption("cg.cha", "on");
		    // to mitigate an Android problem: https://github.com/soot-oss/soot/issues/1019
		    //options.set_wrong_staticness(Options.wrong_staticness_fix);
		    //options.set_no_bodies_for_excluded(true);  // ban Soot from loading the method bodies even if required for CG construction
			//exclude.addAll(options.exclude());
			options.set_android_jars(System.getenv("ANDROID_HOME"));
			options.set_soot_classpath(Config.apkFilePath + File.pathSeparator + androidJAR + File.pathSeparator + 	System.getenv("ANDROID_SDKS") + "/extras/android/support/v7/appcompat/libs/android-support-v7-appcompat.jar" + File.pathSeparator
						+ System.getenv("ANDROID_SDKS") + "/extras/android/support/v7/appcompat/libs/android-support-v4.jar");
			List<String> processDirs = new ArrayList<String>();
			processDirs.add(Config.apkFilePath);
			options.set_process_dir(processDirs);
//		    options.set_exclude(exclude);
			options.set_allow_phantom_refs(true);
			options.set_whole_program(true);
		    options.set_coffi(true);
		    //options.set_polyglot(false);
			options.set_process_multiple_dex(true);
			//options.set_include_all(true);
		  }
		});
		app.constructCallgraph();
		CHATransformer.v().transform();
		List<SootMethod> rtoMethods = getMethodsInReverseTopologicalOrder();
		System.out.println("cg size: " + rtoMethods.size());
		return rtoMethods;
	}

	public static boolean extendFromActivity(String className)  {
		SootClass currClass = Scene.v().getSootClass(className);
		while (currClass.hasSuperclass()) {
			currClass = currClass.getSuperclass();
			String currClassStr = currClass.getName();
			Set<String> activityClasses = new HashSet<String>(Arrays.asList("android.preference.PreferenceActivity", "android.app.ListActivity"));
			if (activityClasses.contains(currClassStr)) {
				return true;
			}
			if (androidPrefixPkgNames.stream().map(currClassStr::startsWith).reduce(false, (res, curr) -> res || curr)) {
				// extended from android system/framework class
				// if we keep going, we can go deep
				break;
			}
		}
		return false;
	}

	public static List<SootMethod> retrieveRtoMethods() {
		Hierarchy h = Scene.v().getActiveHierarchy();
		List<SootMethod> nonLifeCycleEntryPoints = new ArrayList<SootMethod>();
		for (SootClass c : Scene.v().getApplicationClasses()) {
			if (c.isInterface() || c.getPackageName().startsWith("android.")) {
				// Don't care about non-implementation
				// Don't care about non-user code
				continue;
			}
			for (SootClass superClass : h.getSuperclassesOfIncluding(c)) {
				if (superClass.isInterface()) {
					continue;
				}
				if (superClass.getName().equals("android.support.v4.content.Loader")) {
					for (SootMethod m : c.getMethods()) {
						if (m.isConcrete() && m.getName().startsWith("on")) {
							nonLifeCycleEntryPoints.add(m);
						}
					}
				}
			}
		}
		List<SootMethod> newEntryPoints = new ArrayList<SootMethod>(Scene.v().getEntryPoints());
		newEntryPoints.addAll(nonLifeCycleEntryPoints);
		Scene.v().setEntryPoints(newEntryPoints);
		Options.v().set_time(false);
		CHATransformer.v().transform();

		List<SootMethod> rtoMethods = getMethodsInReverseTopologicalOrder();

		// dynamic registration
		/*
		Set<SootClass> dynRegReceivers = new LinkedHashSet<SootClass>();  // EX: BroadcastReceivers
		List<SootMethod> dynRegReceiverEntryPoints = new ArrayList<SootMethod>();
		for (SootMethod m : rtoMethods) {
			if (m.hasActiveBody()) {
				Body b = m.retrieveActiveBody();
				for (Unit u : b.getUnits()) {
					Stmt s = (Stmt) u;
					if (s.containsInvokeExpr()) {
						InvokeExpr ie = s.getInvokeExpr();
						if (ie.getMethod().getDeclaringClass().isInterface()) {
							continue;
						}

						for (SootClass superClass : h.getSuperclassesOfIncluding(ie.getMethod().getDeclaringClass())) {
							if (superClass.getName().equals("android.content.Context")) {
								if (ie.getMethod().getName().equals("registerReceiver")) {
									String registeredType = ie.getArg(0).getType().toString();

									SootClass receiverClass = Scene.v().getSootClass(registeredType);
									dynRegReceivers.add(receiverClass);
									for (SootMethod regTypeMethod : receiverClass.getMethods()) {
										if (regTypeMethod.getName().startsWith("on") && regTypeMethod.isConcrete()) {
											dynRegReceiverEntryPoints.add(regTypeMethod);
										}
									}
								}
							}
						}
					}
				}
			}
		}

		if (!dynRegReceiverEntryPoints.isEmpty()) {
			newEntryPoints.addAll(dynRegReceiverEntryPoints);
			Options.v().set_time(false);
			CHATransformer.v().transform();
			rtoMethods = getMethodsInReverseTopologicalOrder();
		}
		 */

		return rtoMethods;
	}

	public static String getApkJsonNameFromPath(String apkFilepath) {
        Path p = Paths.get(apkFilepath);
        String apkName = p.getFileName().toString();
		apkName = apkName.substring(0, apkName.lastIndexOf('.')) + ".json";
		return apkName;
	}
	
	public static void setupAndroidAppForBody() {
		Config.applyBodySootOptions();
		Scene.v().loadNecessaryClasses();
	}

	public static String createTabsStr(int tabs) {
		String tabsStr = "";
		for (int i=0;i<tabs;i++) {
			tabsStr += "\t";
		}
		return tabsStr;
	}

	public static Boolean isUserMethod(SootMethod method) {
		if (!Utils.isApplicationMethod(method)) {
			return false;
		}
		if (Utils.isAndroidMethod(method)) {
			return false;
		}
		if (!method.isConcrete()) {
			return false;
		}
		if (method.isPhantom()) {
			return false;
		}
		return true;
	}

	public static Boolean isUserMethodAndrolib(SootMethod method) {
		if (!Utils.isApplicationMethod(method)) {
			return false;
		}
		if (Utils.isAndroidMethodAndroLib(method)) {
			return false;
		}
		if (!method.isConcrete()) {
			return false;
		}
		if (method.isPhantom()) {
			return false;
		}
		return true;
	}

	public static boolean isAndroidMethod(SootMethod sootMethod){
        String clsSig = sootMethod.getDeclaringClass().getName();
        return androidPrefixPkgNames.stream().map(clsSig::startsWith).reduce(false, (res, curr) -> res || curr);
    }

	public static boolean isAndroidMethodAndroLib(SootMethod sootMethod){
		String clsSig = sootMethod.getDeclaringClass().getName();
		if (clsSig.equals("android.os.AsyncTask")) {
			// need to model AsyncTask
			return false;
		}
		if (clsSig.equals("java.lang.Runnable")) {
			// need to model Runnable
			return false;
		}
		return androidPrefixPkgNames.stream().map(clsSig::startsWith).reduce(false, (res, curr) -> res || curr);
	}

	public static List<SootMethod> getMethodsInReverseTopologicalOrder() {
		List<SootMethod> entryPoints = Scene.v().getEntryPoints();
		CallGraph cg = Scene.v().getCallGraph();
		List<SootMethod> topologicalOrderMethods = new ArrayList<SootMethod>();

		Queue<SootMethod> methodsToAnalyze = new LinkedList<SootMethod>();
		//Map<SootMethod, Integer> methodCounts = new ConcurrentHashMap<>();

		// DFS traversal
		// add SootMethod to topologicalOrderMethods
		// if SootMethod is Application method and contains method body
		for (SootMethod entryPoint : entryPoints) {
			if (isApplicationMethod(entryPoint)) {
				methodsToAnalyze.add(entryPoint);
				while (!methodsToAnalyze.isEmpty()) {
					SootMethod method = methodsToAnalyze.poll();
					if (!topologicalOrderMethods.contains(method)) {
						//if (!methodCounts.containsKey(method) || methodCounts.get(method) != 2) {
						try {
							Body b = method.retrieveActiveBody();
							PatchingChain chains = b.getUnits();
							if (chains.size() != 0) {
								topologicalOrderMethods.add(method);
								/*
								if (!methodCounts.containsKey(method)) {
									methodCounts.put(method, 1);
								} else {
									methodCounts.put(method, methodCounts.get(method)+1);
								}
								 */
								for (Edge edge : getOutgoingEdges(method, cg)) {
									SootMethod edgeMethod = edge.tgt();
									if (!topologicalOrderMethods.contains(edgeMethod)) {
										if (isAndroidMethod(edgeMethod) || edgeMethod.getDeclaration().contains(" native ")) {
											continue;
										}
										methodsToAnalyze.add(edgeMethod);
									}
								}
							}
						} catch (Exception e) {
							continue;
						}
					}
				}
			}
		}

		// reverse DFS traversal
		// a child method is at an earlier index than its parent method
		List<SootMethod> rtoMethods = Lists.reverse(topologicalOrderMethods);
		return rtoMethods;
	}

	public static String getConstant(Value val, SimpleLocalDefs localDefs, Unit ieDefUnit) {
		String ret = null;
		if (val instanceof StringConstant) {
			ret = val.toString();
		} else if (val instanceof Local) {
			// extract string constant
			List<Unit> valDefs = localDefs.getDefsOfAt((Local)val, ieDefUnit);
			for (Unit valDef : valDefs) {
				if (valDef instanceof DefinitionStmt) {
					DefinitionStmt valDefStmt = (DefinitionStmt) valDef;
					if (valDefStmt instanceof JAssignStmt) {
						JAssignStmt valAssignStmt = (JAssignStmt) valDefStmt;
						if (valAssignStmt.containsFieldRef()) {
							SootField valField = valAssignStmt.getFieldRef().getField();
							if (valField.getType().toString().equals("java.lang.String")) {
								StringConstantValueTag str = (StringConstantValueTag) valField.getTag("StringConstantValueTag");
								if (str != null) {
									ret = str.getConstant().value;
								}
							}
						}
					}
				}
			}
		}
		if (ret != null) {
			ret = ret.replaceAll("^\"|\"$", "");
		}
		return ret;
	}

	public static List<SootMethod> getMethodsInReverseTopologicalOrder(Boolean payloadAsArg) {
		List<SootMethod> entryPoints = Scene.v().getEntryPoints();
		CallGraph cg = Scene.v().getCallGraph();
		List<SootMethod> topologicalOrderMethods = new ArrayList<SootMethod>();

		Queue<SootMethod> methodsToAnalyze = new LinkedList<SootMethod>();
		//Map<SootMethod, Integer> methodCounts = new ConcurrentHashMap<>();

		// DFS traversal
		// add SootMethod to topologicalOrderMethods
		// if SootMethod is Application method and contains method body
		for (SootMethod entryPoint : entryPoints) {
			if (isApplicationMethod(entryPoint)) {
				methodsToAnalyze.add(entryPoint);
				while (!methodsToAnalyze.isEmpty()) {
					SootMethod method = methodsToAnalyze.poll();
					if (!topologicalOrderMethods.contains(method)) {
					//if (!methodCounts.containsKey(method) || methodCounts.get(method) != 2) {
						try {
							Body b = method.retrieveActiveBody();
							PatchingChain chains = b.getUnits();
							if (chains.size() != 0) {
								// annotate method added to the topological order list
								UnitGraph ug = new ExceptionalUnitGraph(b);
								List<String> taintedArgs;
								if (method.hasTag("StringTag")) {
									// method has tainted parameters
									// taint whatever those parameters taint
									String taintedArgsStr = String.valueOf(method.getTag("StringTag"));
									taintedArgs = Arrays.asList(taintedArgsStr.split("\\s*,\\s*"));
								} else {
									taintedArgs = new ArrayList<>();
								}
								IntentPropagation ip = new IntentPropagation(ug, method, taintedArgs, true);
								annotateCallee(ip, b, payloadAsArg);
								topologicalOrderMethods.add(method);
								/*
								if (!methodCounts.containsKey(method)) {
									methodCounts.put(method, 1);
								} else {
									methodCounts.put(method, methodCounts.get(method)+1);
								}
								 */
								for (Edge edge : getOutgoingEdges(method, cg)) {
									SootMethod edgeMethod = edge.tgt();
									if (!topologicalOrderMethods.contains(edgeMethod)) {
										if (isAndroidMethod(edgeMethod) || edgeMethod.getDeclaration().contains(" native ")) {
											continue;
										}
										methodsToAnalyze.add(edgeMethod);
									}
								}
							}
						} catch (Exception e) {
							continue;
						}
					}
				}
			}
		}

		// reverse DFS traversal
		// a child method is at an earlier index than its parent method
		List<SootMethod> rtoMethods = Lists.reverse(topologicalOrderMethods);
		return rtoMethods;
	}

	public static void annotateCallee(IntentPropagation ip, Body b, Boolean payloadAsArg) {
		PatchingChain<Unit> units = b.getUnits();
		for (Unit u : units) {
			// add callee to methodsToAnalyze if
			// (1) callee argument is data dependent on Intent
			// (2) callee return value is data dependent on Intent
			// for (1), we annotate the method
			// for (2), we annotate the return stmt/unit
			Stmt s = (Stmt) u;
			if (s.containsInvokeExpr()) {
				Boolean extendToCallee = false;
				InvokeExpr ie = getInvokeExpr(s);
				if (ie == null) {
					continue;
				}
				if (Utils.isAndroidMethod(ie.getMethod())) {
					continue;
				}
				// iflow for Intent flow hahaa
				FlowSet iflow = (FlowSet) ip.getFlowBefore(u);
				if (!iflow.isEmpty()) {
					// Values data dependent on Intent flow to this callee instruction
					// Check if callee parameters intersect with those Values
					List<String> intentRelatedParams = new ArrayList<>();
					if (!payloadAsArg) {
						// extend callee if a callee paramter is an Intent
						List<Type> paramTypes = ie.getMethod().getParameterTypes();
						for (Type t : paramTypes) {
							if (t.toString().equals("android.content.Intent")) {
								// arg is data dependent on Intent
								intentRelatedParams.add("2");
								extendToCallee = true;
							} else {
								// arg is not data dependent on Intent
								intentRelatedParams.add("0");
							}
						}
					} else {
						// extend callee if a callee parameter is data-dependent on Intent
						List<Value> args = ie.getArgs();
						for (Value arg : args) {
							if (iflow.contains(arg)) {
								// arg is data dependent on Intent
								if (arg.getType().toString().equals("android.content.Intent")) {
									// arg is Intent
									intentRelatedParams.add("2");
								} else {
									// arg is data-dependent on Intent
									intentRelatedParams.add("1");
								}
								extendToCallee = true;
							} else {
								// arg is not data dependent on Intent
								intentRelatedParams.add("0");
							}
						}
					}
					if (extendToCallee) {
						// (1) add annotation on which arguments are data dependent on Intent
						// (2) add annotation on the callee statement for unitNeedsAnalysis
						// annotate for (1)
						SootMethod calleeMethod = ie.getMethod();
						String intentRelatedParamsStr = String.join(",", intentRelatedParams);
						Tag t = new StringTag(intentRelatedParamsStr);
						calleeMethod.addTag(t);
						// extend callgraph
						// annotate for (2)
						Tag t2 = new StringTag("isIntentDependent");
						u.addTag(t2);
					}
				}
			}

		}
	}

	public static InvokeExpr getInvokeExpr(Stmt s) {
		if (s instanceof AssignStmt) {
			AssignStmt assignStmt = (AssignStmt) s;
			if (assignStmt.getRightOp() instanceof InvokeExpr) {
				return (InvokeExpr)assignStmt.getRightOp();
			}
		} else if (s.containsInvokeExpr()) {
			return s.getInvokeExpr();
		}
		return null;
	}

	public static boolean isApplicationMethod(SootMethod method) {
		Chain<SootClass> applicationClasses = Scene.v().getApplicationClasses();
		for (SootClass appClass : applicationClasses) {
			if (appClass.getMethods().contains(method)) {
				return true;
			}
		}
		return false;
	}
	
	public static SootClass getLibraryClass(String className) {
		Chain<SootClass> libraryClasses = Scene.v().getLibraryClasses();
		for (SootClass libClass : libraryClasses) {
			if (libClass.getName().equals(className)) {
				return libClass;
			}
		}
		return null;
	}

	public static List<Edge> getOutgoingEdges(SootMethod method, CallGraph cg) {
		Iterator<Edge> edgeIterator = cg.edgesOutOf(method);
		// Google's com.google.common.collect contains functionalities to convert iterator to list
		List<Edge> outgoingEdges = Lists.newArrayList(edgeIterator);
		return outgoingEdges;
	}
	
	public static void printInputStream(InputStream is) throws IOException {
		InputStreamReader isr = new InputStreamReader(is);
		BufferedReader br = new BufferedReader(isr);
		String line;
		while ((line = br.readLine()) != null) {
			System.out.println(line);
		}
	}
	
	public static void runCmdAsProcess(String[] cmdArr) {
		List<String> cmd = Arrays.asList(cmdArr);

		ProcessBuilder builder = new ProcessBuilder(cmd);
		Map<String, String> environ = builder.environment();

		Process process;
		try {
			process = builder.start();

			InputStream is = process.getInputStream();
			System.out.println("normal output: ");
			Utils.printInputStream(is);
			
			InputStream es = process.getErrorStream();
			System.out.println("error output: ");
			Utils.printInputStream(es);

			System.out.println("Program terminated!");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static BytecodeOffsetTag extractByteCodeOffset(Unit unit) {
		for (Tag tag : unit.getTags()) {
			if (tag instanceof BytecodeOffsetTag) {
				BytecodeOffsetTag bcoTag = (BytecodeOffsetTag) tag;
				return bcoTag;
			}
		}
		return null;
	}

	public static SourceLineNumberTag extractSourceLineNumber(Unit unit) {
		for (Tag tag : unit.getTags()) {
		  if (tag instanceof SourceLineNumberTag) {
			SourceLineNumberTag srcTag = (SourceLineNumberTag) tag;
			return srcTag;
		  }
		}
		return null;
	}

	public static Logger setupLogger(@SuppressWarnings("rawtypes") Class inClass, String apkName) {
		LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
	    JoranConfigurator configurator = new JoranConfigurator();
	    lc.reset();
	    lc.putProperty("toolName", inClass.getName());
	    lc.putProperty("apkName",apkName);
	    configurator.setContext(lc);
	    try {
			configurator.doConfigure("logback-fileAppender.xml");
		} catch (JoranException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	    Logger logger = LoggerFactory.getLogger(inClass);

	    return logger;
	}

	public static Logger setupVerboseLogger(@SuppressWarnings("rawtypes") Class inClass, String apkName) {
		LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
		JoranConfigurator configurator = new JoranConfigurator();
		lc.reset();
		lc.putProperty("toolName", inClass.getName());
		lc.putProperty("apkName",apkName);
		configurator.setContext(lc);
		try {
			configurator.doConfigure("logback-fileAppender-verbose.xml");
		} catch (JoranException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		Logger logger = LoggerFactory.getLogger(inClass);
		return logger;
	}
	
	public static void printTagsOfMethod(Logger logger, SootMethod method) {
		for (Unit unit : method.getActiveBody().getUnits()) {
			if (!unit.getTags().isEmpty()) {
				for (Tag tag : unit.getTags()) {
					logger.debug("unit: " + unit);
					logger.debug("\ttag: " + tag.getName() + "," + tag.toString());
				}
			}
		}

	}
	
	public static void makeFileEmpty(String filename) {
		BufferedWriter writer;
		try {
			writer = Files.newBufferedWriter(Paths.get(filename), Charset.defaultCharset());
			writer.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static String getFullCompName(String packageName, String compName) {
		if (compName.startsWith(".")) {
			return packageName + compName; // if the component name has a "." at the beginning just concatenate it with the packageName
		}
		else if (compName.contains(".")) { // if the component has a "." anywhere else, return just the component name
			return compName;
		}
		else {
			return packageName + "." + compName; // if the component does not match the previous two conditions, then concatenate with the package name and add the "."
		}
	}
	
	public static void deletePathIfExists(Path path) {
		if (Files.exists(path)) {
			try {
				Files.delete(path);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	public static InvokeExpr getInvokeExprOfAssignStmt(Unit unit) {
		if (unit instanceof AssignStmt) {
			AssignStmt assignStmt = (AssignStmt)unit;
			if (assignStmt.getRightOp() instanceof InvokeExpr) {
				InvokeExpr invokeExpr = (InvokeExpr)assignStmt.getRightOp();
				return invokeExpr;
			}
		}
		return null;

	}

	public static void storeIntentControlledTargets(File apkFile, Logger logger, Set<Triplet<Unit, BytecodeOffsetTag, SootMethod>> targets) {
		String targetsFilename = apkFile.getName() + "_ic_tgt_units.txt";
		logger.debug("Saving intent-controlled targets to " + targetsFilename);

		try {
			PrintWriter writer = new PrintWriter(targetsFilename);
			for (Triplet<Unit,BytecodeOffsetTag,SootMethod> target : targets) {
				writer.write(target.getValue1() + "#" + target.getValue2() + "\n");
			}
			writer.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	public static void storeIntentControlledTargetsWithSpecialKeys(File apkFile,
																   Logger logger,
																   Set<Quartet<Unit, BytecodeOffsetTag, SootMethod,String>> targets,
																   String abbrv) {
		String targetsFilename = apkFile.getName() + "_" + abbrv + "_ic_tgt_units.txt";
		logger.debug("Saving intent-controlled targets to " + targetsFilename);
		System.out.println("Current working directory: " + System.getProperty("user.dir"));
		System.out.println("Saving intent-controlled targets to " + targetsFilename);

		try {
			PrintWriter writer = new PrintWriter(targetsFilename);
			int i=0;
			for (Quartet<Unit, BytecodeOffsetTag, SootMethod, String> target : targets) {
				writer.write(target.getValue1() + "#" + target.getValue2() + "#" + target.getValue3() + "\n");
				i++;
			}
			writer.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

}
