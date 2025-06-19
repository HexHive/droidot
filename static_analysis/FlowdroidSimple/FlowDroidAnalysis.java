

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Body;
import soot.UnitBox;
import soot.Unit;
import soot.ValueBox;
import soot.Value;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.internal.*;
import soot.jimple.internal.JAssignStmt.LinkedRValueBox;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.jimple.JimpleBody;
import soot.util.HashChain;
import soot.jimple.infoflow.android.config.SootConfigForAndroid;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class FlowDroidAnalysis {
	

	    private final static String USER_HOME = System.getProperty("user.home");
	    // for the server
	    private static String androidJar = "/usr/lib/android-sdk/platforms";
	    //private static String androidJar = USER_HOME + "/Android/Sdk/platforms";
	    // the number of forward searches for looking for native calls inside a body
	    private static int bodyNativeSearchDepth = 3;
	    // the number of backward searches for building the callsequence
	    private static int callgraphBackwardSearchDepth = 2;
	    
	    public static List<String> androidExclude = Arrays.asList("android.*", "com.google.android.*", "com.android.*", "dalvik.*", "androidx.*", "java.*", "javax.*", "junit.*", "org.apache.*", "sun.*", "org.eclipse.*", "org.json.*", "org.w3c.dom.*", "org.xml.sax.*", "org.xmlpull.*", "kotlin.*");
	    public static List<String> exclude = new ArrayList<>();


	    public static void main(String[] args){
	    	if(args.length != 2){
	    		System.out.println("Usage: [path_to_appfolder]");
	    		System.out.println("retrieves the native function signatures and simple argument contraints");
	    	}
	        String appPath = args[0];
	        String apkPath = appPath + "/base.apk";
	        // Setup InfoFlowConfiguration
	        InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
	        config.getAnalysisFileConfig().setTargetAPKFile(apkPath);
	        config.getAnalysisFileConfig().setAndroidPlatformDir(androidJar);
	        config.setCodeEliminationMode(InfoflowConfiguration.CodeEliminationMode.NoCodeElimination);
	        config.setEnableReflection(false);
	        config.getCallbackConfig().setEnableCallbacks(false);
	        config.setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
	        config.setMergeDexFiles(true);
	        // Create SetupApplication from flowdroid
	        SetupApplication app = new SetupApplication(config);
	        app.setSootConfig(new SootConfigForAndroid() {
                @Override
                public void setSootOptions(Options options, InfoflowConfiguration config) {
                      super.setSootOptions(options, config); // explicitly exclude packages for shorter runtime
                      options.set_keep_line_number(true);
                      options.set_print_tags_in_output(true);
                  options.set_src_prec(soot.options.Options.src_prec_apk);
          // to mitigate an Android problem: https://github.com/soot-oss/soot/issues/1019
                      options.set_wrong_staticness(Options.wrong_staticness_fix);
                      //exclude.addAll(options.exclude());

                      // COMMENT THOSE FOR BLACKLIST
                      exclude.addAll(androidExclude);
                      Scene.v().forceResolve("androidx.core.app.JobIntentService", SootClass.BODIES);
                      options.set_exclude(exclude);

                      //options.set_on_the_fly(true);
                      //options.setPhaseOption("cg.cha", "on");
                  //options.setPhaseOption("cg.spark", "enabled,on-fly-cg:true,rta:false,vta:false");
                  options.set_no_bodies_for_excluded(true); // ban Soot from loading the method bodies even if required for CG construction
                      //exclude.addAll(options.exclude());
                  //options.set_exclude(exclude);
                      options.set_allow_phantom_refs(true);
                  //options.set_polyglot(false);
                      options.set_whole_program(true);
                }
              });

	        // need to call this first, otherwise I'm not able to interact with the soot api
	        // doesn't terminate for larger apps: TODO: play with settings to find something stable
	        app.constructCallgraph();
	        List<SootMethod> nativeMethods = findAllNativeFunctions();
	        if(true) {	        	
		        try{
		        	// write output to path
		        	String nativeMethods_output = "";
		        	for(SootMethod nativeMethod : nativeMethods) {
		        		nativeMethods_output = nativeMethods_output + soot2androlibMethod(nativeMethod) + "\n";
		        	}
		        	String signatures_pattern = appPath + "/signatures_pattern_soot.txt";
		        	FileOutputStream outputStream = new FileOutputStream(signatures_pattern, false);
		        	byte[] strToBytes = nativeMethods_output.getBytes();
		            outputStream.write(strToBytes);
		            outputStream.close();
		        }
		        catch (IOException e){
		            e.printStackTrace();
		            System.exit(-1);
		        }
	        }
	        if(true) {
	        	String all_constraints = "";
	        	for(SootMethod nativeMethod : nativeMethods) {
	        		all_constraints = all_constraints + findArgumentConstraints(nativeMethod);
	        	}
	        	try{
		        	// write output to path
		        	String static_analysis = appPath + "/static_analysis";
		        	Files.createDirectories(Paths.get(static_analysis));
		        	String constraint_output = static_analysis + "/simple_argument_constraints.txt";
		        	FileOutputStream outputStream = new FileOutputStream(constraint_output, false);
		        	byte[] strToBytes = all_constraints.getBytes();
		            outputStream.write(strToBytes);
		            outputStream.close();
		        }
		        catch (IOException e){
		            e.printStackTrace();
		            System.exit(-1);
		        }     	
	        }
	    }
	    
	    public static void applyWholeProgramSootOptions(String apkFilePath) {
            Options.v().set_src_prec(Options.src_prec_apk);
            //Options.v().set_output_format(Options.output_format_dex);
            //Options.v().set_include_all(true);

            Options.v().set_whole_program(true);
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

	    
	    public static List<SootMethod> findNativeCallsinBody(SootMethod sootMethod, int depth){
	    	// look through a methods native body and retrieve the native calls 
	    	List<SootMethod> output = new ArrayList<>();
	    	if(depth == 0) {
	    		return output;
	    	}
	    	if(sootMethod.isJavaLibraryMethod()) {
	    		return output;
	    	}
	    	Body body;
	    	try {
	    		body = sootMethod.retrieveActiveBody();
	    	} catch(java.lang.RuntimeException e) {
	    		// something went wrong, most likely does not have an active body
	    		System.out.println("[-] something went wrong, while looking for active body, skipping...");
	    		return output;
	    	}
	    	for(Unit unit : body.getUnits()){
                // figure out what type this is
	    		// to handle things like a = nativveFunction(), need to 
	    		// JAssignStmt.rightBox.value.methodRef
	    		if(unit instanceof JAssignStmt) {
	    			ValueBox valuebox;
	    			try {
	    				valuebox = ((JAssignStmt) unit).getInvokeExprBox();
	    			} catch(java.lang.RuntimeException e) {
	    				// if the assignstatement does not have an invokeexpression
	    				// just skip this unit
	    				continue;
	    			}
	    			if(valuebox instanceof LinkedRValueBox){
                        Value method2 = valuebox.getValue();
                        if(method2 instanceof JStaticInvokeExpr || method2 instanceof JVirtualInvokeExpr){
                            InvokeExpr meethod3 = (InvokeExpr)method2;
                            SootMethod method = meethod3.getMethod();
                            SootClass declaringClass = method.getDeclaringClass();
                            if(declaringClass.getName().indexOf("java.") != -1 || declaringClass.getName().indexOf("android.") != -1){
                                // we don't care about native functions of the JVM or of android
                                continue;
                            }
                            if(method.isNative()){
                                output.add(method);
                                continue;
                            }
                            output.addAll(findNativeCallsinBody(method, depth-1));
                        }                           
                    }  
	    		}
                if(unit instanceof JInvokeStmt){
                    // it's a function call!
                    for(ValueBox valuebox : unit.getUseBoxes()){
                        // look for invokeexpr to extract the method
                        if(valuebox instanceof InvokeExprBox){
                            Value method2 = valuebox.getValue();
                            if(method2 instanceof JStaticInvokeExpr || method2 instanceof JVirtualInvokeExpr){
                                InvokeExpr meethod3 = (InvokeExpr)method2;
                                SootMethod method = meethod3.getMethod();
                                SootClass declaringClass = method.getDeclaringClass();
                                if(declaringClass.getName().indexOf("java.") != -1 || declaringClass.getName().indexOf("android.") != -1){
                                    // we don't care about native functions of the JVM or of android
                                    continue;
                                }
                                if(method.isNative()){
                                    output.add(method);
                                    continue;
                                }
                                output.addAll(findNativeCallsinBody(method, depth-1));
                            }                           
                        }                        
                    }                  
                }     
	    	}
	    	return output;	    		    
	    } 
	    
	    public static List<SootMethod> findAllNativeFunctions() {
	    	// look through entire app and find the native functions
	    	List<SootMethod> nativeMethods = new ArrayList<>();
	    	for (SootClass sootClass : Scene.v().getClasses()) {
	            for(SootMethod sootMethod : sootClass.getMethods()){
	            	if(sootMethod.isNative()) {
		            	SootClass declaringClass = sootMethod.getDeclaringClass();
	            		if(declaringClass.getName().indexOf("java.") == -1 && declaringClass.getName().indexOf("android.") == -1){
	                        // we don't care about native functions of the JVM or of android
	            			nativeMethods.add(sootMethod);
	                    }	            		
	            	}	  
	            }	          
	    	}
	    	return nativeMethods;
	    }
	    
	    public static List<SootMethod> ExtractNativeFromEdge(Edge edge, int depth){
	    	// iterate over the edge.src().body, until reaching the edg.tgt() method, follow calls up to depth
	    	// return all native functions found
	    	SootMethod srcMethod = edge.src();
	    	SootMethod dstMethod = edge.tgt();
	    	List<SootMethod> output = new ArrayList<>();
	    	if(srcMethod.isJavaLibraryMethod()) {
	    		return output;
	    	}
	    	Body body;
	    	try {
	    		body = srcMethod.retrieveActiveBody();
	    	} catch(java.lang.RuntimeException e) {
	    		// something went wrong, most likely does not have an active body
	    		System.out.println("[-] something went wrong, while looking for active body, skipping...");
	    		return output;
	    	}
	    	
	    	return output;
	    }
	    
	    public static String findArgumentConstraints(SootMethod method) {
	    	// do some bottom up analysis to hopefully get some constraints on the input
	    	String output = "";
	    	List<Edge> incomingEdges = findUsage(method);
	    	// First check, look for immediates with values in the method context
	    	for(Edge edge : incomingEdges) {
	    		Unit unit = edge.srcUnit();
	    		if(unit instanceof JInvokeStmt) {
	    			JInvokeStmt jstmt = (JInvokeStmt)unit;
	    			InvokeExpr invokeExpr = jstmt.getInvokeExpr();
	    			List<Value> args = invokeExpr.getArgs();
	    			int index = 0;
	    			for(Value argument : args) {
	    				if(argument instanceof Immediate && !(argument instanceof JimpleLocal)) {
	    					System.out.println("[:)] found constant for native function at index : " + index + method.toString() + argument.toString());
	    					output = output + "native_function_constant: " +method.toString() + ":" + index + ":" + argument.toString() + "\n";
	    				}
	    				if(argument instanceof Immediate && argument instanceof JimpleLocal) {
	    					Body body;
	    					try {
	    			    		body = edge.getSrc().method().retrieveActiveBody();
	    			    		// search through the active body of the calling edge and look for some constraints
		    					String out = findArgConstraints(method, body, argument, index, args, unit);
		    					if(!(out.equals("NONE"))) {
		    						output = output + out + "\n";
		    					}
	    			    	} catch(java.lang.RuntimeException e) {
	    			    		// something went wrong, most likely does not have an active body
	    			    		System.out.println("[-] something went wrong, while looking for active body, skipping...");
	    			    	}
	    				}
	    				if(argument instanceof Immediate && argument instanceof JimpleLocal) {
	    					// try to figure out the type of this argument
	    					Type type = argument.getType();
	    					System.out.println("[:)] class found for native function at index : " + index + method.toString() + type.toString());
	    					output = output + "native_function_argumentclass: " +method.toString() + ":" + index + ":" + type.toString() + "\n";

	    				}
	    				index += 1;
	    			}
	    			continue;
	    		}
	    		if(unit instanceof JAssignStmt) {
	    			ValueBox valuebox;
	    			try {
	    				valuebox = ((JAssignStmt) unit).getInvokeExprBox();
	    			} catch(java.lang.RuntimeException e) {
	    				// if the assignstatement does not have an invokeexpression
	    				// just skip this unit
	    				continue;
	    			}
	    			if(valuebox instanceof LinkedRValueBox){
                        Value method2 = valuebox.getValue();
                        if(method2 instanceof JStaticInvokeExpr || method2 instanceof JVirtualInvokeExpr){
                            InvokeExpr invokeExpr = (InvokeExpr)method2;
                            List<Value> args = invokeExpr.getArgs();
        	    			int index = 0;
        	    			for(Value argument : args) {
        	    				if(argument instanceof Immediate && !(argument instanceof JimpleLocal)) {
        	    					System.out.println("[:)] found constant for native function at index : " + index + method.toString() + argument.toString());
        	    					output = output + "native_function_constant: " +method.toString() + ":" + index + ":" + argument.toString() + "\n";
        	    				}
        	    				if(argument instanceof Immediate && argument instanceof JimpleLocal) {
        	    					Body body;
        	    					try {
        	    			    		body = edge.getSrc().method().retrieveActiveBody();
        	    			    		// search through the active body of the calling edge and look for some constraints
        		    					String out = findArgConstraints(method, body, argument, index, args, unit);
        		    					if(!(out.equals("NONE"))) {
        		    						output = output + out + "\n";
        		    					}
        	    			    	} catch(java.lang.RuntimeException e) {
        	    			    		// something went wrong, most likely does not have an active body
        	    			    		System.out.println("[-] something went wrong, while looking for active body, skipping...");
        	    			    	}
        	    				}
        	    				if(argument instanceof Immediate && argument instanceof JimpleLocal) {
        	    					// try to figure out the type of this argument
        	    					Type type = argument.getType();
        	    					System.out.println("[:)] class found for native function at index : " + index + method.toString() + type.toString());
        	    					output = output + "native_function_argumentclass: " +method.toString() + ":" + index + ":" + type.toString() + "\n";

        	    				}
        	    				index += 1;
        	    			}
        	    			continue;
                        }
	    			}
	    		}
	    	}
	    	
	    	return output;
	    }
	    
	    public static String findArgConstraints(SootMethod method, Body body, Value argument, int index, List<Value> args, Unit original_unit) {
	    	if(argument.getType().toString().equals("int")) {
	    		// integer argument -> check if it is a length
	    		// TODO check for filedescriptor
	    		String arg_name = argument.toString();
	    		Unit unit = get_unit_for_var_before_unit(body, original_unit, arg_name);
	    		if(unit != null) {
	    			// our arg is assigned here
    				if(unit instanceof JAssignStmt) {
    					JAssignStmt assignStmt = (JAssignStmt)unit;
    					ValueBox rside = assignStmt.getRightOpBox();
    					Value rside2 = rside.getValue();
    					if(rside2 instanceof JLengthExpr) {
    						// we're assigning our to the length of something arg = lengthof lengthof_arg
    						JLengthExpr rside3 = (JLengthExpr)rside2;
    						String lengthof_arg = rside3.getOpBox().getValue().toString();
    						int arg_index = find_in_args(args, lengthof_arg);
    						if(arg_index != -1) {
    							System.out.println("[!] length dependency" + method.toString() + "found a length dependency between: args[" + index + "] = len(args["+ arg_index+"]");
    							return "[!] length dependency" + method.toString() + "found a length dependency between: args[" + index + "] = len(args["+ arg_index+"]";
    						}
    					}
    				}
	    		} 		
	    	}
	    	if(argument.getType().toString().equals("java.lang.String")) {
	    		// string argument -> check if path
	    		String arg_name = argument.toString();
	    		Unit unit = get_unit_for_var_before_unit(body, original_unit, arg_name);
	    		if(unit != null) {
	    			if(unit instanceof JAssignStmt) {
    					JAssignStmt assignStmt = (JAssignStmt)unit;
    					ValueBox rside = assignStmt.getRightOpBox();
    					Value rside2 = rside.getValue();
    					if(rside2 instanceof JVirtualInvokeExpr) {
    						// arg = virtualinvoke ...
    						JVirtualInvokeExpr rside3 = (JVirtualInvokeExpr)rside2;
    						SootMethod rside_meth = rside3.getMethod();
    						String rcls = rside_meth.getDeclaringClass().toString();
    						String rfname = rside_meth.getName().toString();
    						if(is_filepath(rcls, rfname)) {
    							System.out.println("[!] filepath constraint" + method.toString() + "found a filepath constraint for arg at index: " + index);
    							return "[!] filepath constraint" + method.toString() + "found a filepath constraint for arg at index: " + index;
    						}
    					}
    				}
	    		}
	    	}
	    	return "NONE";
	    }
	    
	    
	    public static Unit get_unit_for_var_before_unit(Body body, Unit targetUnit, String arg_name) {
	    	String assign_arg = arg_name + " =";
	    	Unit mostrecentUnit = null;
	    	for(Unit unit : body.getUnits()){
	    		if(unit.toString().equals(targetUnit.toString())) {
	    			break;
	    		}
	    		if(unit.toString().contains(assign_arg)) {
	    			mostrecentUnit = unit;
	    		}
	    	}
	    	return mostrecentUnit;
	    }
	    
	    public static boolean is_filepath(String cls, String method) {
	    	if(cls.equals("java.io.File")) {
	    		if(method.equals("getPath") || method.equals("getAbsolutePath") || method.equals("getCanonicalPath") 
	    				|| method.equals("getAbsoluteFile")) {
	    			return true;
	    		}
	    	}
	    	return false;
	    }
	    
	    public static int find_in_args(List<Value> args, String search_arg){
	    	int i = 0;
	    	for(Value arg : args){
	    		if(search_arg == arg.toString()) return i;
	    		i ++;
	    	}
	    	return -1;
	    }
	    
	    public static List<List<Edge>> usageSequenceRecurse(SootMethod method, int depth){
	    	// follow the edges up, returns a list of call sequences
	    	List<List<Edge>> allSequences = new ArrayList<>();
	    	if(depth == 0) {
	    		allSequences.add(new ArrayList<Edge>());
	    		return allSequences;
	    	}
	    	List<Edge> incomingEdges = findUsage(method);
	    	for(Edge inc : incomingEdges) {
	    		SootMethod parent = inc.src();
	    		List<List<Edge>> sequenceList = usageSequenceRecurse(parent, depth-1);
	    		for(List<Edge> callsequence : sequenceList) {
	    			// add the current edge to the callsequence list at the beginning
	    			callsequence.add(0, inc);
	    		}
	    		allSequences.addAll(sequenceList);
	    	}
	    	return allSequences;
	    }
	    
	    public static List<Edge> findUsage(SootMethod method){
	    	// find out where the method is used
	    	List<Edge> incomingEdges = new ArrayList<Edge>();
	    	CallGraph callgraph = Scene.v().getCallGraph();
	    	Iterator<Edge> it = callgraph.edgesInto(method);
	    	while(it.hasNext()) {
	    		Edge edge = it.next();
	    		incomingEdges.add(edge);
	    	}
	    	return incomingEdges;
	    }
	  	    
	    public static String soot2androlibMethod(SootMethod method) {
	    	// convert a sootMethod to the mangeld Java JNI name + list of arguments. 
	    	// same as output from jadx + qdox
	    	String prefix = "Java";
	    	String className = method.getDeclaringClass().getName();
	    	className = className.replace("_", "_1");
	    	className = className.replace(".", "_");
	    	String functionName = method.getName();
	    	functionName = functionName.replace("_", "_1");
	    	String returnType = getBaseType(method.getReturnType().toString());
	    	String arguments = "";
	    	for(Type param : method.getParameterTypes()) {
	    		arguments = arguments + getBaseType(param.toString()) + ",";
	    	}	
	    	return prefix + "_"  + className + "_" + functionName + " " + returnType + ":" + arguments;
	    }
	    
	    public static String getBaseType(String type) {
	    	// split string and get the last element java.lang.String -> String
	    	return type.substring(type.lastIndexOf('.') + 1);
	    }
}

