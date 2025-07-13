package aaa.bbb.ccc.path.analyses.extradata.instrument;

import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.Globals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.options.Options;
import soot.tagkit.BytecodeOffsetTag;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;

import static aaa.bbb.ccc.path.analyses.extradata.ExtraDataUseTransformerSp.isBundleFromIntent;
import static soot.SootClass.SIGNATURES;

public class WebViewTransformer {
    Map<Unit, Boolean> doesUnitNeedAnalysisSummary = new LinkedHashMap<Unit, Boolean>();
    static Set<String> methodsToFilter = new HashSet<String>(Arrays.asList("onNewIntent"));
    static Logger logger = LoggerFactory.getLogger(InstrumentTransformer.class);
    protected int instrumentStatementCnt = 0;
    protected int intentControlledStatementCnt = 0;
    protected JimpleBasedInterproceduralCFG icfg;

    public int getInstrumentStmtCount() {
        return instrumentStatementCnt;
    }

    public int getIntentControlledStatementCnt() {
        return intentControlledStatementCnt;
    }

    public WebViewTransformer(String apkFilePath) {
        G.reset();
        Config.apkFilePath = apkFilePath;
    }

    public boolean main(FileWriter fw) throws IOException {
        Utils.applyWholeProgramSootOptions(Config.apkFilePath);
        for (SootClass curClass : Scene.v().getClasses()) {
            if (curClass.isJavaLibraryClass()) {
                continue;
            }
            if (Utils.androidPrefixPkgNames.stream().filter(pkg -> curClass.getFilePath().startsWith(pkg)).count() != 0) {
                // exclude Android libraries
                continue;
            }
            for (SootMethod method : curClass.getMethods()) {
                if (Utils.isAndroidMethod(method)) {
                    continue;
                }
                UnitGraph unitGraph = null;
                SimpleLocalDefs defs = null;
                Body body;
                try {
                    body = method.retrieveActiveBody();
                } catch (Exception e) {
                    continue;
                }
                unitGraph = new ExceptionalUnitGraph(body);
                synchronized (method) {
                    defs = new SimpleLocalDefs(unitGraph);
                }
                //System.out.println("> " + method.getSignature());
                for (Unit u : body.getUnits()) {
                    //System.out.println(">>> " + u.toString());
                    Stmt s = (Stmt) u;
                    if (s.containsInvokeExpr()) {
                        InvokeExpr ie = s.getInvokeExpr();
                        SootMethod calledMethod = ie.getMethod();
                        if (calledMethod.getName().equals("loadUrl") && calledMethod.getDeclaringClass().getName().equals("android.webkit.WebView") && calledMethod.getParameterCount() > 0) {
                            Value val = ie.getArg(0);
                            if (val instanceof Local) {
                                Local loc = (Local) val;
                                for (Unit argDef : defs.getDefsOfAt(loc, u)) {
                                    InvokeExpr argDefIe = Utils.getInvokeExprOfAssignStmt(argDef);
                                    if (argDefIe == null) {
                                        continue;
                                    }
                                    Boolean isUri = false;
                                    if (!argDefIe.getMethod().getDeclaringClass().getName().equals("android.net.Uri") && !argDefIe.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                                        // source not from URI
                                        continue;
                                    }
                                    if (argDefIe.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                                        fw.write(Config.apkFilePath + ",1,0"+System.getProperty("line.separator"));
                                        return true;
                                    }
                                    if (argDefIe instanceof InstanceInvokeExpr) {
                                        // URI base exists
                                        InstanceInvokeExpr argDefIie = (InstanceInvokeExpr) argDefIe;
                                        if (argDefIie.getBase() instanceof Local) {
                                            Local uri = (Local) argDefIie.getBase();
                                            for (Unit maybeIntent : defs.getDefsOfAt(uri, argDef)) {
                                                InvokeExpr maybeIntentIe = Utils.getInvokeExprOfAssignStmt(maybeIntent);
                                                if (maybeIntentIe == null) {
                                                    continue;
                                                }
                                                if (!maybeIntentIe.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                                                    // not from Intent
                                                    continue;
                                                }
                                                fw.write(Config.apkFilePath + ",1,1"+System.getProperty("line.separator"));
                                                return true;
                                            }
                                        }
                                    }

                                }
                            }
                        }

                    }
                }

            }
        }
        return false;
    }
}
