package aaa.bbb.ccc.path.analyses.extradata.instrument;

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import aaa.bbb.ccc.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.Body;
import soot.Local;
import soot.PackManager;
import soot.PatchingChain;
import soot.RefType;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Jimple;
import soot.jimple.ReturnStmt;
import soot.jimple.StaticInvokeExpr;
import soot.jimple.StringConstant;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.options.Options;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.TargetedPathTransformer;

public class InstrumentAppSceneTrans extends SceneTransformer{
	public final static String androidJAR = System.getenv("ANDROID_HOME") + File.separator +"android-32" + File.separator + "android.jar";
	public static String apkFilePath;
	static Logger logger = LoggerFactory.getLogger(TargetedPathTransformer.class);

	public static void main(String[] args) {
		apkFilePath = args[0];
		Config.apkFilePath = args[0];
		//prefer Android APK files// -src-prec apk
		Options.v().set_src_prec(Options.src_prec_apk);		
		//output as APK, too//-f J
		Options.v().set_output_format(Options.output_format_dex);		
        // resolve the PrintStream and System soot-classes
		Scene.v().addBasicClass("java.io.PrintStream",SootClass.SIGNATURES);
        Scene.v().addBasicClass("java.lang.System",SootClass.SIGNATURES);
        Scene.v().addBasicClass("android.util.Log",SootClass.SIGNATURES);
        Options.v().set_android_jars(System.getenv("ANDROID_HOME"));
		Options.v().set_soot_classpath(apkFilePath + File.pathSeparator + androidJAR);
		List<String> processDirs = new ArrayList<String>();
		processDirs.add(apkFilePath);
		Options.v().set_process_dir(processDirs);
		Options.v().set_whole_program(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_time(true);
		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_show_exception_dests(false);
		//Options.v().set_print_tags_in_output(true);
		Options.v().set_verbose(false);
		//PhaseOptions.v().setPhaseOption("cg", "verbose:true");
		Options.v().set_android_jars(System.getenv("ANDROID_HOME"));
		Options.v().set_keep_line_number(true);
		Options.v().set_coffi(true);
		Scene.v().loadNecessaryClasses();
		Options.v().setPhaseOption("jb", "use-original-names:true");
		
		new InstrumentAppSceneTrans();
		

	}
	public InstrumentAppSceneTrans(){
        String sootOutputDir="/Users/Mahmoud/Documents/eclipseWorkspace/pathexecutor/sootOutput/";
        String[] arr = apkFilePath.split(File.separator);
        String apkName = arr[arr.length-1];

        System.out.println("**** remove the previous instrumented apk, if exists ***********");
        String[] removeApkArgs = {"rm",sootOutputDir+apkName};
        Utils.runCmdAsProcess(removeApkArgs);

		PackManager.v().getPack("wjtp").add(new Transform("wjtp.instrumentApp", this));		
        PackManager.v().getPack("wjtp").apply();
        Options.v().force_overwrite(); // allows the PackManager to override the existing apk file BUT it's not working :(
        Options.v().set_output_format(Options.output_format_dex);
        PackManager.v().writeOutput(); //write instrumented apk to sootOutputDir
        
        


        System.out.println("**** Sign the new apk app ***********");

        String keystorePath=sootOutputDir+"mahmoud.keystore";
        String[] signApkArgs = {"jarsigner","-verbose","-sigalg","SHA1withRSA","-digestalg","SHA1","-keystore",keystorePath,"-storepass","mahmoud","-keypass","mahmoud",sootOutputDir+apkName,"mahmoud"};
        Utils.runCmdAsProcess(signApkArgs);
        
        System.out.println("**** uninstall the old version of the app in the emulator");
        String appPkg = "pathtestsapp"; //to get thsi package name use the command $ aapt dump badging PathTestsApp.apk
        String adbCmdPath = "/Users/Mahmoud/Tools/android-sdk-macosx/platform-tools/adb";
        String[] adbUninstallAppArgs = {adbCmdPath,"uninstall",appPkg};
        Utils.runCmdAsProcess(adbUninstallAppArgs);
        System.out.println("**** install the new instrumenmts app on the emulator");
        String[] adbInstallAppArgs = {adbCmdPath,"install",sootOutputDir+apkName};
        Utils.runCmdAsProcess(adbInstallAppArgs);

	}
		@Override
			//protected void internalTransform(final Body b, String phaseName, @SuppressWarnings("rawtypes") Map options) {
		protected void internalTransform(String phaseName,Map<String, String> options) {
			Utils.setupDummyMainMethod();
			CHATransformer.v().transform();
			
			JimpleBasedInterproceduralCFG icfg = new JimpleBasedInterproceduralCFG();
			
			List<SootMethod> rtoMethods = Utils.getMethodsInReverseTopologicalOrder();
			
			for (SootMethod method : rtoMethods){
				if (method.hasActiveBody()){
					logger.debug("SootMethod> "+method.getSignature() +" has no avtive body");
					final Body b = method.getActiveBody();
					final PatchingChain<Unit> units = b.getUnits();
					//important to use snapshotIterator here
					for(Iterator<Unit> iter = units.snapshotIterator(); iter.hasNext();) {
						
						final Unit u = iter.next();
						
						
						
						u.apply(new AbstractStmtSwitch() {
							public void caseInvokeStmt(InvokeStmt stmt) {
								
								InvokeExpr invokeExpr = stmt.getInvokeExpr();
								if(invokeExpr.getMethod().getName().equals("onResume")) {
									System.out.println("**** Unit: "+u.toString() +" ,in method:"+invokeExpr.getMethod().toString());
									
									Local tmpRef = addTmpRef(b);
									Local tmpString = addTmpString(b);
									
									//insert a system.out.println("") instrument statement
									  // insert "tmpRef = java.lang.System.out;" 
							        units.insertBefore(Jimple.v().newAssignStmt( 
							                      tmpRef, Jimple.v().newStaticFieldRef( 
							                      Scene.v().getField("<java.lang.System: java.io.PrintStream out>").makeRef())), u);
	
							        // insert "tmpLong = 'HELLO';" 
							        units.insertBefore(Jimple.v().newAssignStmt(tmpString, 
							                      StringConstant.v("Mahmoud: System output Instrumentrumentation")), u);
							        
							        // insert "tmpRef.println(tmpString);" 
							        SootMethod toCall = Scene.v().getSootClass("java.io.PrintStream").getMethod("void println(java.lang.String)");                    
							        units.insertBefore(Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr(tmpRef, toCall.makeRef(), tmpString)), u);
							        //check that we did not mess up the Jimple
							        b.validate();
							        
	
							        
							        //insert a log.i instrument statement						        
									SootMethod log = Scene.v().getMethod("<android.util.Log: int i(java.lang.String,java.lang.String)>");
									Value logMessage = StringConstant.v("Mahmoud: log.i instrumentation");
									Value logType = StringConstant.v("LogInfoInstrument");
									Value logMsg = logMessage;
					                 //make new static invokement
									StaticInvokeExpr newInvokeExpr = Jimple.v().newStaticInvokeExpr(log.makeRef(), logType, logMsg);
	                                // turn it into an invoke statement
	                                //insert into chain
	                                //units.insertBefore(incStmt, u);
	                                List<Unit> listToInsert = new ArrayList<Unit>();
	                                listToInsert.add(Jimple.v().newInvokeStmt(newInvokeExpr));
	                                b.getUnits().insertBefore(listToInsert, u);
	
	                                //check that we did not mess up the Jimple
							        b.validate();
								}
							}
							public void caseReturnStmt(ReturnStmt stmt){
								//System.out.println("**** Unit: "+u.toString() +" is a return statement");
								
							}
							
						}
						);
						
					}
				}
			}


				
				

				
			}

    private static Local addTmpRef(Body body)
    {
        Local tmpRef = Jimple.v().newLocal("tmpRef", RefType.v("java.io.PrintStream"));
        body.getLocals().add(tmpRef);
        return tmpRef;
    }
    
    private static Local addTmpString(Body body)
    {
        Local tmpString = Jimple.v().newLocal("tmpString", RefType.v("java.lang.String")); 
        body.getLocals().add(tmpString);
        return tmpString;
    }

}
