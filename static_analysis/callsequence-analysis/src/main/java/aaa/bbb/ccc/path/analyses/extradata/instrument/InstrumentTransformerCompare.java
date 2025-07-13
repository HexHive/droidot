package aaa.bbb.ccc.path.analyses.extradata.instrument;

import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.path.analyses.ConstantValueInitTransformer;
import aaa.bbb.ccc.path.analyses.Globals;
import aaa.bbb.ccc.path.analyses.extradata.ExtraDataUseTransformerSp;
import org.javatuples.Pair;
import org.javatuples.Quartet;
import org.javatuples.Triplet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.options.Options;
import soot.tagkit.StringConstantValueTag;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.scalar.ConstantInitializerToTagTransformer;
import soot.toolkits.scalar.ConstantValueToInitializerTransformer;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.util.*;
import java.util.regex.Pattern;

import static soot.SootClass.SIGNATURES;

public class InstrumentTransformerCompare extends SceneTransformer {

	Map<Unit,Boolean> doesUnitNeedAnalysisSummary = new LinkedHashMap<Unit,Boolean>();
	static Logger logger = LoggerFactory.getLogger(InstrumentTransformerCompare.class);
	protected int instrumentStatementCnt=0;

    int controlDepPaths = 0;
    int intentControlDepPaths = 0;
    Map<String,Integer> intentCatCounts = new LinkedHashMap<String,Integer>();

    Quartet<JSONObject,JSONObject,JSONObject,JSONObject> jsons = null;
    //int iccbotCompare = 0;
    //int ic3Compare = 0;
    //int fwCompare = 0;
    Map<String,Integer> fwCompare = new LinkedHashMap<String,Integer>();
    Map<String,Integer> ic3Compare = new LinkedHashMap<String,Integer>();
    Map<String,Integer> iccbotCompare = new LinkedHashMap<String,Integer>();
    Map<String,Integer> totalCompare = new LinkedHashMap<String,Integer>();

	public int getInstrumentStmtCount() {
		return instrumentStatementCnt;
	}

	public InstrumentTransformerCompare(String apkFilePath, Quartet<JSONObject, JSONObject, JSONObject, JSONObject> jsons) {
//		super(apkFilePath);
        G.reset();
        Config.apkFilePath = apkFilePath;

        intentCatCounts.put("action", 0);
        intentCatCounts.put("uri", 0);
        intentCatCounts.put("uri-nullness", 0);
        intentCatCounts.put("extras-key", 0);
        intentCatCounts.put("extras-value", 0);
        intentCatCounts.put("bundleExtras-key", 0);
        intentCatCounts.put("bundleExtras-value", 0);
        intentCatCounts.put("category", 0);
        intentCatCounts.put("array-extras-value", 0);
        this.jsons = jsons;

        fwCompare.put("action", 0);
        fwCompare.put("uri", 0);
        fwCompare.put("extras-key", 0);
        fwCompare.put("extras-value", 0);
        fwCompare.put("categories", 0);
        iccbotCompare.put("action", 0);
        iccbotCompare.put("uri", 0);
        iccbotCompare.put("extras-key", 0);
        iccbotCompare.put("extras-value", 0);
        iccbotCompare.put("categories", 0);
        ic3Compare.put("action", 0);
        ic3Compare.put("uri", 0);
        ic3Compare.put("extras-key", 0);
        ic3Compare.put("extras-value", 0);
        ic3Compare.put("categories", 0);
        totalCompare.put("action", 0);
        totalCompare.put("uri", 0);
        totalCompare.put("extras-key", 0);
        totalCompare.put("extras-value", 0);
        totalCompare.put("categories", 0);
	}

    public Boolean checkIfUnitUsesIntentPayload(Unit inUnit,
                                                SimpleLocalDefs localDefs,
                                                StringBuilder messageType,
                                                Boolean containsNullComp,
                                                SootMethod method,
                                                String currClassName,
                                                Triplet debugInfo) {
        // only check intent-controlled statements phenomenon model. Good for catching bugs
        Stmt inStmt = (Stmt)inUnit;
        Pair<String,String> noModel = null;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            Boolean x = isIntentPayloadExtractionMethod(localDefs, inUnit, ie, messageType, containsNullComp, method, currClassName, debugInfo, noModel);
            if (x != null && x == true) {
                // inUnit is an intent extraction instruction
                return x;
            }
        }

        // for invoke expr:
        // check if any arg is an intent payload.
        // check if base is an intent payload. If base is. Only return true for base operations that we model: str.len, str.equals
        // for others:
        // use original approach
        if (inUnit instanceof AssignStmt && ((AssignStmt) inUnit).getRightOp() instanceof InvokeExpr) {
            AssignStmt as = (AssignStmt) inUnit;
            InvokeExpr ie = (InvokeExpr) as.getRightOp();

            boolean isModel = false; // TODO: isModel temporary set to true
            // TODO: compare action value and not just action
            // only return true for base operation we model
            // even if base is an intent payload, if we do not model the operation then we do not model it
            // NOTE: implement differently in ExtraDataUseTransformerSp. In ExtraDataUseTransfomerSp, the check
            //       for modelled operation is performed after the defUnits loop. Here it is performed before
            //       so our intentCatCounts do not increment when operation on the payload is not modelled
            if (ie.getMethod().getDeclaringClass().toString().equals("java.lang.String")) {
                if (ie.getMethod().getName().equals("length")) {
                    isModel = true;
                } else if (ie.getMethod().getName().equals("equals")) {
                    isModel = true;
                }
            }
            if (!isModel) {
                noModel = new Pair<>(ie.getMethod().getDeclaringClass().toString(), ie.getMethod().getName());
            }

            // check args
            if (isModel) {
                // ex: "action.ex".equals(x) where x is the action string
                List<Value> args = ie.getArgs();
                for (Value arg : args) {
                    if (arg instanceof Local) {
                        List<Unit> defUnits = localDefs.getDefsOfAt((Local) arg, inUnit);
                        for (Unit defUnit : defUnits) {
                            InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
                            if (invokeExpr == null) {
                                continue;
                            }
                            Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp, method, currClassName, debugInfo, noModel);
                            if (x != null && x == true)
                                return x;
                        }
                    }
                }
            }
            // check base
            if (ie instanceof InstanceInvokeExpr) {
                // base exists
                InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
                if (iie.getBase() instanceof Local) {
                    Local base = (Local) iie.getBase();
                    List<Unit> defUnits = localDefs.getDefsOfAt(base, inUnit);
                    for (Unit defUnit : defUnits) {
                        InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
                        if (invokeExpr == null) {
                            continue;
                        }
                        if (isModel) {
                            Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp, method, currClassName, debugInfo, noModel);
                            if (x != null && x == true) {
                                return x;
                            }
                        }

                    }
                }
            }
        } else {
            // not an invoke expr
            List<ValueBox> uses = inUnit.getUseBoxes();  // list of Boxes containing Values in unit `inUnit`
            for (ValueBox use : uses) {
                if (use.getValue() instanceof Local) {
                    Local local = (Local) use.getValue();
                    List<Unit> defUnits = localDefs.getDefsOfAt(local, inUnit);
                    for (Unit defUnit : defUnits) {
                        InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
                        if (invokeExpr == null) {
                            continue;
                        }
                        Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp, method, currClassName, debugInfo, noModel);
                        if (x != null && x == true)
                            return x;
                    }
                }
            }
        }
        return null;
    }

    /*
    public Boolean checkIfUnitUsesIntentPayloadOg(Unit inUnit,
                                                SimpleLocalDefs localDefs,
                                                StringBuilder messageType,
                                                Boolean containsNullComp,
                                                SootMethod method,
                                                String currClassName,
                                                Triplet debugInfo) {
        Stmt inStmt = (Stmt)inUnit;
        if (inStmt.containsInvokeExpr()) {
            InvokeExpr ie = inStmt.getInvokeExpr();
            Boolean x = isIntentPayloadExtractionMethod(localDefs, inUnit, ie, messageType, containsNullComp, method, currClassName, debugInfo);
            if (x != null && x == true) {
                // inUnit is an intent extraction instruction
                return x;
            }
        }

        // not an invoke expr
        List<ValueBox> uses = inUnit.getUseBoxes();  // list of Boxes containing Values in unit `inUnit`
        for (ValueBox use : uses) {
            if (use.getValue() instanceof Local) {
                Local local = (Local) use.getValue();
                List<Unit> defUnits = localDefs.getDefsOfAt(local, inUnit);
                for (Unit defUnit : defUnits) {
                    InvokeExpr invokeExpr = Utils.getInvokeExprOfAssignStmt(defUnit);
                    if (invokeExpr == null) {
                        continue;
                    }
                    Boolean x = isIntentPayloadExtractionMethod(localDefs, defUnit, invokeExpr, messageType, containsNullComp, method, currClassName, debugInfo);
                    if (x != null && x == true)
                        return x;
                }
            }
        }
        return null;
    }
     */

    public static boolean isBundleFromIntent(SimpleLocalDefs localDefs, Unit defUnit, InvokeExpr invokeExpr, StringBuilder messageType) {
        if (invokeExpr instanceof InstanceInvokeExpr) {
            InstanceInvokeExpr instanceInvokeExpr = (InstanceInvokeExpr)invokeExpr;
            if (instanceInvokeExpr.getBase() instanceof Local) {
                Local base = (Local)instanceInvokeExpr.getBase();
                List<Unit> baseDefs = localDefs.getDefsOfAt(base, defUnit);
                for (Unit baseDef : baseDefs) {
                    InvokeExpr baseInvokeExpr = Utils.getInvokeExprOfAssignStmt(baseDef);
                    if (baseInvokeExpr != null) {
                        if (Globals.getBundleMethodsSet.contains(baseInvokeExpr.getMethod().getName())) {
                            if (baseInvokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                                messageType.append(baseInvokeExpr.getMethod().getName()+".");
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    public static String getIeArg(InvokeExpr ie, SimpleLocalDefs localDefs, Unit ieDefUnit) {
        Value arg = ie.getArg(0);
        String ret = null;
        if (arg instanceof StringConstant) {
            ret = arg.toString();
        } else if (arg instanceof Local) {
            // extract string constant
            List<Unit> argDefs = localDefs.getDefsOfAt((Local)arg, ieDefUnit);
            for (Unit argDef : argDefs) {
                if (argDef instanceof DefinitionStmt) {
                    DefinitionStmt argDefStmt = (DefinitionStmt) argDef;
                    if (argDefStmt instanceof JAssignStmt) {
                        JAssignStmt argAssignStmt = (JAssignStmt) argDefStmt;
                        if (argAssignStmt.containsFieldRef()) {
                            SootField argField = argAssignStmt.getFieldRef().getField();
                            if (argField.getType().toString().equals("java.lang.String")) {
                                StringConstantValueTag str = (StringConstantValueTag) argField.getTag("StringConstantValueTag");
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

    public void ic3CanIdExit(String attr, String arg, String methodSignature, String currClassName) {
        // TODO: need to pre-process ic3 output so components contain information in exit-points
        // action, URI, and categories IC3 identifies is at the component-level
        // only extras are at the method-level. methodSignature is relevant for extras
        // (with the exception if the extra is extracted from exit_points)
        // action, URI, and categories are identified based on manifest's intent filters
        JSONObject ic3exitsobj = jsons.getValue3();
        if (ic3exitsobj == null) {
            return;
        }
        if (!ic3exitsobj.keySet().contains(currClassName)) {
            return;
        }
        JSONObject comp = (JSONObject) ic3exitsobj.get(currClassName);

        String key = null;
        String extrasType = null;
        if (attr.equals("uri-nullness")) {
           // "kind": "TYPE",
           key = "URI";
        } else if (attr.equals("extras-value")) {
            key = "EXTRA";
            extrasType = "extras-value";
        } else if (attr.equals("extras-key")) {
            key = "EXTRA";
            extrasType = "extras-key";
        } else if (attr.equals("bundleExtras-key")) {
            key = "EXTRA";
            extrasType = "extras-key";
        } else if (attr.equals("bundleExtras-value")) {
            key = "EXTRA";
            extrasType = "extras-value";
        } else if (attr.equals("category")) {
            // "kind": "CATEGORY",
            key = "CATEGORY";
        } else if (attr.equals("action")) {
            // "kind": "ACTION",
            key = "ACTION";
        }
        if (comp.keySet().contains(key)) {
            if (key.equals("URI")) {
                ic3Compare.put("uri", ic3Compare.get("uri") + 1);
                return;
            } else if (key.equals("ACTION")) {
                // if action is not in comp it action list will not be present
                ic3Compare.put("action", ic3Compare.get("action") + 1);
                return;
            } else if (key.equals("CATEGORY")) {
                JSONArray categories = (JSONArray) comp.get(key);
                if (arg == null) {
                    // getCategories()
                    if (categories.size() != 0){
                        ic3Compare.put("categories", ic3Compare.get("categories")+1);
                        return;
                    }
                }
                Iterator categoriesIter = categories.iterator();
                while (categoriesIter.hasNext()) {
                    String cItem = (String) categoriesIter.next();
                    if (arg != null) {
                        // hasCategory(x)
                        if (cItem.equals(arg)) {
                            // key found
                            ic3Compare.put("categories", ic3Compare.get("categories")+1);
                            return;
                        }
                    }
                }
            } else if (key.equals("EXTRA")) {
                JSONArray extras = (JSONArray) comp.get(key);
                Iterator extrasIter = extras.iterator();
                while (extrasIter.hasNext()) {
                    String eItem = (String) extrasIter.next();
                    if (arg != null) {
                        if (eItem.equals(arg)) {
                            // key found
                            ic3Compare.put(extrasType, ic3Compare.get(extrasType)+1);
                            return;
                        }
                    }
                }
            }
        }

       return;
    }

    public boolean ic3CanId(String attr, String arg, String methodSignature, String currClassName) {
        // TODO: need to pre-process ic3 output so components contain information in exit-points
        // action, URI, and categories IC3 identifies is at the component-level
        // only extras are at the method-level. methodSignature is relevant for extras
        // (with the exception if the extra is extracted from exit_points)
        // action, URI, and categories are identified based on manifest's intent filters
        JSONObject ic3obj = jsons.getValue0();
        if (ic3obj == null) {
            return false;
        }
        if (!ic3obj.keySet().contains("components")) {
            // ic3 did not identify any component
            return false;
        }
        JSONArray compsArray = (JSONArray) ic3obj.get("components");
        Iterator compsIter = compsArray.iterator();
        while (compsIter.hasNext()) {
            JSONObject comp = (JSONObject) compsIter.next();
            if (comp.get("name").toString().equals(currClassName)) {
                // found component corresponding to currClassName
                String key = null;
                String extrasType = null;
                if (attr.equals("uri-nullness")) {
                   // "kind": "TYPE",
                   key = "TYPE";
                } else if (attr.equals("extras-value")) {
                    key = "extras";
                    extrasType = "extras-value";
                } else if (attr.equals("extras-key")) {
                    key = "extras";
                    extrasType = "extras-key";
                } else if (attr.equals("bundleExtras-key")) {
                    key = "extras";
                    extrasType = "extras-key";
                } else if (attr.equals("bundleExtras-value")) {
                    key = "extras";
                    extrasType = "extras-value";
                } else if (attr.equals("category")) {
                    // "kind": "CATEGORY",
                    key = "CATEGORY";
                } else if (attr.equals("action")) {
                    // "kind": "ACTION",
                    key = "ACTION";
                }

                if (key.equals("TYPE") || key.equals("CATEGORY") || key.equals("ACTION")) {
                    // they are identified by analyzing manifest
                    if (!comp.keySet().contains("intent_filters")) {
                        // did not identify attributes in manifest
                        continue;
                    }
                    JSONArray filters = (JSONArray) comp.get("intent_filters");
                    Iterator filtersIter = filters.iterator();
                    while (filtersIter.hasNext()) {
                        JSONObject currFilter = (JSONObject) filtersIter.next();

                        // for action and URI, just check for existence
                        // TODO: update action to also check for value
                        if (key.equals("ACTION")) {
                            if (currFilter.get("kind").equals(key)) {
                                ic3Compare.put("action", ic3Compare.get("action") + 1);
                                return true;
                            }
                        } else if (key.equals("TYPE")) {
                            // TODO: are all those possible uri?
                            if (
                                    currFilter.get("kind").equals(key) ||
                                    currFilter.get("kind").equals("SCHEME") ||
                                    currFilter.get("kind").equals("HOST") ||
                                    currFilter.get("kind").equals("PATH")
                            ) {
                                ic3Compare.put("uri", ic3Compare.get("uri") + 1);
                                return true;
                            }
                        } else if (key.equals("CATEGORY")) {
                            // for category, check for existence of arg in the categories list
                            if (arg == null) {
                                // getCategories()
                                if (currFilter.get("kind").equals(key)) {
                                    ic3Compare.put("categories", ic3Compare.get("categories") + 1);
                                    return true;
                                }
                            } else {
                                // hasCategories(arg)
                                // iterate JSONObject currFilter to identify category string
                                // skip key-value pair where key is "kind"
                                Set<String> filterKeys = currFilter.keySet();
                                for (String k : filterKeys) {
                                    if (!k.equals("kind")) {
                                        if (currFilter.get(k).equals(arg)) {
                                            // category string found
                                            ic3Compare.put("categories", ic3Compare.get("categories") + 1);
                                            return true;
                                        }
                                    }
                                }
                            }
                       }
                    }
                } else if (key.equals("extras")) {
                    if (!comp.keySet().contains("extras")) {
                        // package+class name did not have extras
                        continue;
                    }
                    JSONArray extras = (JSONArray) comp.get("extras");
                    Iterator extrasIter = extras.iterator();
                    while (extrasIter.hasNext()) {
                        JSONObject currExtra = (JSONObject) extrasIter.next();
                        if (arg != null) {
                            if (currExtra.get("extra").toString().equals(arg)) {
                                // check if it is identified inside correct method
                                String instrKey = null;
                                if (!currExtra.keySet().contains("instruction")) {
                                    // no instruction field
                                    if (!currExtra.keySet().contains("registration_instruction")) {
                                        continue;
                                    }
                                    instrKey = "registration_instruction";
                                } else {
                                    instrKey = "instruction";
                                }
                                JSONObject instruction = (JSONObject) currExtra.get(instrKey);
                                if (!instruction.keySet().contains("method")) {
                                    // no method field
                                    continue;
                                }
                                if (instruction.get("method").toString().equals(methodSignature)) {
                                    ic3Compare.put(extrasType, ic3Compare.get(extrasType) + 1);
                                    return true;
                                }
                            }
                        }
                    }
                }

            }
       }
       return false;
    }

    public void iccBotCanId(String attr, String arg, String method, String currClassName) {
        // ICCBot differentiates Intents up to the package+class name, not method name like
        // phenomenon and IC3
        JSONObject iccbotobj = jsons.getValue1();
        if (iccbotobj == null) {
            return;
        }
        if (!iccbotobj.keySet().contains(currClassName)) {
            return;
        }
        JSONObject comp = (JSONObject) iccbotobj.get(currClassName);

        String key = null;
        String extrasType = null;
        if (attr.equals("uri-nullness")) {
           key = "uri";
        } else if (attr.equals("extras-value")) {
            key = "extras";
            extrasType = "extras-value";
        } else if (attr.equals("extras-key")) {
            key = "extras";
            extrasType = "extras-key";
        } else if (attr.equals("bundleExtras-key")) {
            key = "extras";
            extrasType = "extras-key";
        } else if (attr.equals("bundleExtras-value")) {
            key = "extras";
            extrasType = "extras-value";
        } else if (attr.equals("category")) {
            key = "categories";
        } else if (attr.equals("action")) {
            key = "actions";
        }

        if (comp.keySet().contains(key)) {
            if (key.equals("uri")) {
                iccbotCompare.put("uri", iccbotCompare.get("uri") + 1);
                return;
            } else if (key.equals("actions")) {
                // if action is not in comp it action list will not be present
                iccbotCompare.put("action", iccbotCompare.get("action") + 1);
                return;
            } else if (key.equals("categories")) {
                // categories is a list
                JSONArray categories = (JSONArray) comp.get(key);
                if (arg == null) {
                    // getCategories()
                    if (categories.size() != 0){
                        iccbotCompare.put("categories", iccbotCompare.get("categories")+1);
                        return;
                    }
                }
                Iterator categoriesIter = categories.iterator();
                while (categoriesIter.hasNext()) {
                    String cItem = (String) categoriesIter.next();
                    if (arg != null) {
                        // hasCategory(x)
                        if (cItem.equals(arg)) {
                            // key found
                            iccbotCompare.put("categories", iccbotCompare.get("categories")+1);
                            return;
                        }
                    }
                }
            } else if (key.equals("extras")) {
                // extras is a list
                JSONArray extras = (JSONArray) comp.get(key);
                Iterator extrasIter = extras.iterator();
                while (extrasIter.hasNext()) {
                    JSONObject eItem = (JSONObject) extrasIter.next();
                    if (arg != null) {
                        if (eItem.get("name").equals(arg)) {
                            // key found
                            iccbotCompare.put(extrasType, iccbotCompare.get(extrasType)+1);
                            return;
                        }
                    }
                }
            }
        }
        return;
    }

    public void fwCanId(String attr, String arg, String method, String currClassName) {
        JSONObject fwobj = jsons.getValue2();
        if (fwobj == null) {
            return;
        }
        if (!fwobj.keySet().contains(currClassName)) {
            return;
        }
        JSONObject comp = (JSONObject) fwobj.get(currClassName);

        if (!comp.keySet().contains(method)) {
            return;
        }
        JSONArray meth = (JSONArray) comp.get(method);

        String key = null;
        String extrasType = null;
        if (attr.equals("uri-nullness")) {
           key = "uri";
        } else if (attr.equals("extras-value")) {
            key = "extras";
            extrasType = "extras-value";
        } else if (attr.equals("extras-key")) {
            key = "extras";
            extrasType = "extras-key";
        } else if (attr.equals("bundleExtras-key")) {
            key = "extras";
            extrasType = "extras-key";
        } else if (attr.equals("bundleExtras-value")) {
            key = "extras";
            extrasType = "extras-value";
        } else if (attr.equals("category")) {
            key = "categories";
        } else if (attr.equals("action")) {
            key = "action";
        }
        Iterator methIter = meth.iterator();
        while (methIter.hasNext()) {
            JSONObject currIntent = (JSONObject) methIter.next();
            if (currIntent.keySet().contains(key)) {
                if (key.equals("uri")) {
                    fwCompare.put("uri", fwCompare.get("uri")+1);
                    return;
                } else if (key.equals("extras")) {
                    // extras is a list
                    JSONArray extras = (JSONArray) currIntent.get(key);
                    Iterator extrasIter = extras.iterator();
                    while (extrasIter.hasNext()) {
                        JSONObject eItem = (JSONObject) extrasIter.next();
                        if (arg != null) {
                            if (eItem.get("val1").equals(arg)) {
                                // key found
                                fwCompare.put(extrasType, fwCompare.get(extrasType)+1);
                                return;
                            }
                        }
                    }
                } else if (key.equals("categories")) {
                    // categories is a list
                    JSONArray categories = (JSONArray) currIntent.get(key);
                    if (arg == null) {
                        // getCategories()
                        if (categories.size() != 0){
                            fwCompare.put("categories", fwCompare.get("categories")+1);
                            return;
                        }
                    }
                    Iterator categoriesIter = categories.iterator();
                    while (categoriesIter.hasNext()) {
                        String cItem = (String) categoriesIter.next();
                        if (arg != null) {
                            // hasCategory(x)
                            if (cItem.equals(arg)) {
                                // key found
                                fwCompare.put("categories", fwCompare.get("categories")+1);
                                return;
                            }
                        }
                    }
                } else if (key.equals("action")) {
                    // contains action
                    fwCompare.put("action", fwCompare.get("action")+1);
                    return;
                }
            }
        }
        return;
    }

    public void updateTotalCompare(String attr) {
        if (attr.equals("uri-nullness")) {
            totalCompare.put("uri", totalCompare.get("uri")+1);
        } else if (attr.equals("extras-value")) {
            totalCompare.put("extras-value", totalCompare.get("extras-value")+1);
        } else if (attr.equals("extras-key")) {
            totalCompare.put("extras-key", totalCompare.get("extras-key")+1);
        } else if (attr.equals("bundleExtras-key")) {
            totalCompare.put("extras-key", totalCompare.get("extras-key")+1);
        } else if (attr.equals("bundleExtras-value")) {
            totalCompare.put("extras-value", totalCompare.get("extras-value")+1);
        } else if (attr.equals("category")) {
            totalCompare.put("categories", totalCompare.get("categories")+1);
        } else if (attr.equals("action")) {
            totalCompare.put("action", totalCompare.get("action")+1);
        }
    }

    public void compareTools(String attr, String arg, SootMethod method, String currClassName, Boolean needsValue, Triplet debugInfo, Pair noModel) {
        // arg : argument of Intent extraction method
        // needsValue : does Intent-controlled statement requires extra data value

        updateTotalCompare(attr);

        if (needsValue) {
            // track previous attr value
            int fwVal = 0;
            if (attr.equals("uri-nullness")) {
                fwVal = fwCompare.get("uri");
            } else if (attr.equals("extras-value") || attr.equals("bundleExtras-value")) {
                fwVal = fwCompare.get("extras-value");
            } else if (attr.equals("extras-key") || attr.equals("bundleExtras-key")) {
                fwVal = fwCompare.get("extras-key");
            } else if (attr.equals("category")) {
                fwVal = fwCompare.get("category");
            } else if (attr.equals("action")) {
                fwVal = fwCompare.get("action");
            } else {
                System.out.println("ERROR");
            }

            // only phenomenon can identify extra data value
            fwCanId(attr, arg, method.getName(), currClassName);

            int fwValAfter = 0;
            if (attr.equals("uri-nullness")) {
                fwValAfter = fwCompare.get("uri");
            } else if (attr.equals("extras-value") || attr.equals("bundleExtras-value")) {
                fwValAfter = fwCompare.get("extras-value");
            } else if (attr.equals("extras-key") || attr.equals("bundleExtras-key")) {
                fwValAfter = fwCompare.get("extras-key");
            } else if (attr.equals("category")) {
                fwValAfter = fwCompare.get("category");
            } else if (attr.equals("action")) {
                fwValAfter = fwCompare.get("action");
            } else {
                System.out.println("ERROR");
            }

            // identify attribute miss by each tool
            if (fwVal == fwValAfter) {
                if (noModel != null) {
                    logger.debug("MISS-FW: attr:" + attr + ", arg:" + arg + ", class:" + currClassName + ", method:" + method.getName() + ", intent-controlled statement:" + debugInfo.getValue1() + ", line number:" + debugInfo.getValue0() + ", defUnit: " + debugInfo.getValue2()+", no model class: " + noModel.getValue0()+", no model operation: "+noModel.getValue1());
                } else {
                    logger.debug("MISS-FW: attr:" + attr + ", arg:" + arg + ", class:" + currClassName + ", method:" + method.getName() + ", intent-controlled statement:" + debugInfo.getValue1() + ", line number:" + debugInfo.getValue0() + ", defUnit: " + debugInfo.getValue2());
                }
            }

        } else {
            // track previous attr value
            int fwVal = 0;
            int iccBotVal = 0;
            int ic3Val = 0;
            if (attr.equals("uri-nullness")) {
                fwVal = fwCompare.get("uri");
                iccBotVal = iccbotCompare.get("uri");
                ic3Val = ic3Compare.get("uri");
            } else if (attr.equals("extras-value") || attr.equals("bundleExtras-value")) {
                fwVal = fwCompare.get("extras-value");
                iccBotVal = iccbotCompare.get("extras-value");
                ic3Val = ic3Compare.get("extras-value");
            } else if (attr.equals("extras-key") || attr.equals("bundleExtras-key")) {
                fwVal = fwCompare.get("extras-key");
                iccBotVal = iccbotCompare.get("extras-key");
                ic3Val = ic3Compare.get("extras-key");
            } else if (attr.equals("category")) {
                fwVal = fwCompare.get("category");
                iccBotVal = iccbotCompare.get("category");
                ic3Val = ic3Compare.get("category");
            } else if (attr.equals("action")) {
                fwVal = fwCompare.get("action");
                iccBotVal = iccbotCompare.get("action");
                ic3Val = ic3Compare.get("action");
            } else {
                System.out.println("ERROR");
            }

            if (!ic3CanId(attr, arg, method.getSignature(), currClassName)) {
                // ic3 JSON uses method signature produced by Soot
                ic3CanIdExit(attr, arg, method.getSignature(), currClassName);
            }
            iccBotCanId(attr, arg, method.getName(), currClassName);
            fwCanId(attr, arg, method.getName(), currClassName);

            int fwValAfter = 0;
            int iccBotValAfter = 0;
            int ic3ValAfter = 0;
            if (attr.equals("uri-nullness")) {
                fwValAfter = fwCompare.get("uri");
                iccBotValAfter = iccbotCompare.get("uri");
                ic3ValAfter = ic3Compare.get("uri");
            } else if (attr.equals("extras-value") || attr.equals("bundleExtras-value")) {
                fwValAfter = fwCompare.get("extras-value");
                iccBotValAfter = iccbotCompare.get("extras-value");
                ic3ValAfter = ic3Compare.get("extras-value");
            } else if (attr.equals("extras-key") || attr.equals("bundleExtras-key")) {
                fwValAfter = fwCompare.get("extras-key");
                iccBotValAfter = iccbotCompare.get("extras-key");
                ic3ValAfter = ic3Compare.get("extras-key");
            } else if (attr.equals("category")) {
                fwValAfter = fwCompare.get("category");
                iccBotValAfter = iccbotCompare.get("category");
                ic3ValAfter = ic3Compare.get("category");
            } else if (attr.equals("action")) {
                fwValAfter = fwCompare.get("action");
                iccBotValAfter = iccbotCompare.get("action");
                ic3ValAfter = ic3Compare.get("action");
            } else {
                System.out.println("ERROR");
            }

            // identify attribute miss by each tool
            if (fwVal == fwValAfter) {
                if (noModel != null) {
                    logger.debug("MISS-FW: attr:" + attr + ", arg:" + arg + ", class:" + currClassName + ", method:" + method.getName() + ", intent-controlled statement:" + debugInfo.getValue1() + ", line number:" + debugInfo.getValue0() + ", defUnit: " + debugInfo.getValue2()+", no model class: " + noModel.getValue0()+", no model operation: "+noModel.getValue1());
                } else {
                    logger.debug("MISS-FW: attr=" + attr + ", arg=" + arg + ", class=" + currClassName + ", method=" + method.getName() + ", intent-controlled statement:" + debugInfo.getValue1() + ", line number:" + debugInfo.getValue0() + ", defUnit: " + debugInfo.getValue2());
                }
            }
            if (iccBotVal == iccBotValAfter) {
                logger.debug("MISS-ICCBOT: attr="+attr+", arg="+arg+", class="+currClassName+", method="+method.getName()+", unit:"+debugInfo.getValue1()+", line number:"+debugInfo.getValue1());
            }
            if (ic3Val == ic3ValAfter) {
                logger.debug("MISS-IC3: attr="+attr+", arg="+arg+", class="+currClassName+", method="+method.getName()+", unit:"+debugInfo.getValue1()+", line number:"+debugInfo.getValue0());
            }
        }
    }

    public Boolean isIntentPayloadExtractionMethod(SimpleLocalDefs localDefs,
                                                   Unit defUnit,
                                                   InvokeExpr invokeExpr,
                                                   StringBuilder messageType,
                                                   Boolean containsNullComp,
                                                   SootMethod method,
                                                   String currClassName,
                                                   Triplet debugInfo,
                                                   Pair noModel) {

        String invokedMethodName = invokeExpr.getMethod().getName();

        if (Pattern.matches("getData", invokedMethodName)) {
            // extracting URI. getData() returns URI
            // check: can the tool's corresponding intent have an URI field?
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                messageType.append(invokedMethodName+"().");
                if (containsNullComp) {
                    logger.debug("EVAL uri-nullness: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
                    intentCatCounts.put("uri-nullness", intentCatCounts.get("uri-nullness")+1);
                    compareTools("uri-nullness", null, method, currClassName, false, debugInfo, noModel);
                } else {
                    // TODO: we do not model uri in general
                    //intentCatCounts.put("uri", intentCatCounts.get("uri")+1);
                    //updateTotalCompare("uri");
                    intentCatCounts.put("uri", intentCatCounts.get("uri")+1);
                }
                return true;
            }
        }
        if (Pattern.matches("getDataString", invokedMethodName)) {
            // extracting URI as String. getDataString() returns URI
            // check: can the tool's corresponding intent have an URI field?
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                messageType.append(invokedMethodName+"().");
                if (containsNullComp) {
                    logger.debug("EVAL uri-nullness: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
                    intentCatCounts.put("uri-nullness", intentCatCounts.get("uri-nullness")+1);
                    compareTools("uri-nullness", null, method, currClassName, false, debugInfo, noModel);
                } else {
                    // TODO: we do not model uri in general
                    //intentCatCounts.put("uri", intentCatCounts.get("uri")+1);
                    //updateTotalCompare("uri");
                    intentCatCounts.put("uri", intentCatCounts.get("uri")+1);
                }
                return true;
            }
        }

       if (Pattern.matches("get.*Extra", invokedMethodName)) {
           // model array array variants now: nullness
           /*
          if (Pattern.matches("get.*ArrayExtra", invokeExpr.getMethod().getName()) ||
               Pattern.matches("get.*ArrayListExtra", invokeExpr.getMethod().getName())) {
               // we do not model these
               intentCatCounts.put("array-extras-value", intentCatCounts.get("array-extras-value")+1);
               intentControlDepPaths += 1;  // since it won't increment in unitNeedsAnalysis because we don't return true
               return null;
           }
            */
           // extracting extra data value
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                String arg = getIeArg(invokeExpr, localDefs, defUnit);
                if (arg == null) {
                    // extra data arg not sucessfully retrieved
                    return null;
                }
				messageType.append(invokedMethodName+"("+arg+").");
                logger.debug("EVAL extras-value: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
                intentCatCounts.put("extras-value", intentCatCounts.get("extras-value")+1);
                compareTools("extras-value", arg, method, currClassName, true, debugInfo, noModel);
                return true;
            }
        }
        if (Pattern.matches("hasExtra", invokedMethodName)) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                String arg = getIeArg(invokeExpr, localDefs, defUnit);
                if (arg == null) {
                    // extra data arg not sucessfully retrieved
                    return null;
                }
				messageType.append(invokedMethodName+"("+arg+").");
                logger.debug("EVAL extras-key: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
                intentCatCounts.put("extras-key", intentCatCounts.get("extras-key")+1);
                compareTools("extras-key", arg, method, currClassName, false, debugInfo, noModel);
                return true;
            }
        }
        if (Globals.bundleExtraDataMethodsSet.contains(invokedMethodName)) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.os.Bundle")) {
                Boolean isFromIntent = isBundleFromIntent(localDefs, defUnit, invokeExpr, messageType);
                if (isFromIntent) {
                    String arg = getIeArg(invokeExpr, localDefs, defUnit);
                    if (arg == null) {
                        // extra data arg not sucessfully retrieved
                        return null;
                    }
                    messageType.append(invokedMethodName+"("+arg+").");

                    if (invokedMethodName.equals("containsKey")) {
                        logger.debug("EVAL bundleExtras-key: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
                        intentCatCounts.put("bundleExtras-key", intentCatCounts.get("bundleExtras-key")+1);
                        compareTools("bundleExtras-key", arg, method, currClassName, false, debugInfo, noModel);
                    } else {
                        logger.debug("EVAL bundleExtras-value: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
                        intentCatCounts.put("bundleExtras-value", intentCatCounts.get("bundleExtras-value")+1);
                        compareTools("bundleExtras-value", arg, method, currClassName, true, debugInfo, noModel);
                    }
                }
                return isFromIntent;
            }
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.os.BaseBundle")) {
                Boolean isFromIntent = isBundleFromIntent(localDefs, defUnit, invokeExpr, messageType);
                if (isFromIntent) {
                    String arg = getIeArg(invokeExpr, localDefs, defUnit);
                    if (arg == null) {
                        // extra data arg not sucessfully retrieved
                        return null;
                    }
                    messageType.append(invokedMethodName+"("+arg+").");

                    if (invokedMethodName.equals("containsKey")) {
                        logger.debug("EVAL bundleExtras-key: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
                        intentCatCounts.put("bundleExtras-key", intentCatCounts.get("bundleExtras-key")+1);
                        compareTools("bundleExtras-key", arg, method, currClassName, false, debugInfo, noModel);
                    } else {
                        logger.debug("EVAL bundleExtras-value: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
                        intentCatCounts.put("bundleExtras-value", intentCatCounts.get("bundleExtras-value")+1);
                        compareTools("bundleExtras-value", arg, method, currClassName, true, debugInfo, noModel);
                    }
                }
                return isFromIntent;
            }
        }
        if (Globals.categoryMethodsSet.contains(invokedMethodName)) {
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                if (invokeExpr.getMethod().getName().equals("hasCategory")) {
                    logger.debug("EVAL category: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
                    // hasCategory takes an argument
                    intentCatCounts.put("category", intentCatCounts.get("category")+1);
                    String arg = getIeArg(invokeExpr, localDefs, defUnit);
                    if (arg == null) {
                        // extra data arg not sucessfully retrieved
                        return null;
                    }
                    messageType.append(invokedMethodName+"("+arg+").");
                    compareTools("category", arg, method, currClassName, false, debugInfo, noModel);
                } else {
                    logger.debug("EVAL category: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
                    intentCatCounts.put("category", intentCatCounts.get("category")+1);
                    messageType.append(invokedMethodName+"().");
                    compareTools("category", null, method, currClassName, false, debugInfo, noModel);
                }
                return true;
            }
        }
        if (Pattern.matches("getAction", invokedMethodName)) {
            // redundant. also in stringReturningIntentMethodsSet
            if (invokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                logger.debug("EVAL action: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
				messageType.append(invokedMethodName+"().");
                intentCatCounts.put("action", intentCatCounts.get("action")+1);
                compareTools("action", null, method, currClassName , false, debugInfo, noModel);
                return true;
            }
        }
        if (invokedMethodName.equals("equals") && invokeExpr.getMethod().getDeclaringClass().getName().equals("java.lang.String")) {
            if (invokeExpr instanceof VirtualInvokeExpr) {
                VirtualInvokeExpr vInvokeExpr = (VirtualInvokeExpr) invokeExpr;
                Value base = vInvokeExpr.getBase();
                if (base instanceof Local) {
                    List<Unit> baseDefs = localDefs.getDefsOfAt((Local) base, defUnit);
                    for (Unit baseDef : baseDefs) {
                        InvokeExpr baseInvokeExpr = Utils.getInvokeExprOfAssignStmt(baseDef);
                        if (baseInvokeExpr == null) {
                            continue;
                        }
                        if (Globals.stringReturningIntentMethodsSet.contains(baseInvokeExpr.getMethod().getName())) {
                            if (baseInvokeExpr.getMethod().getDeclaringClass().getName().equals("android.content.Intent")) {
                                // getStringExtra. Extracting extra data value
                                String arg = getIeArg(invokeExpr, localDefs, defUnit);
                                if (arg == null) {
                                    // extra data arg not sucessfully retrieved
                                    return null;
                                }
								messageType.append(invokedMethodName+"("+arg+").");
                                logger.debug("EVAL extras-value: class="+currClassName+", method="+method.getName()+", unit="+debugInfo.getValue1()+", line number="+debugInfo.getValue0());
                                intentCatCounts.put("extras-value", intentCatCounts.get("extras-value")+1);
                                compareTools("extras-value", arg, method, currClassName, true, debugInfo, noModel);
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    public boolean isNullComparison(IfStmt ifStmt) {
        List<ValueBox> values = ifStmt.getCondition().getUseBoxes();
        for (ValueBox v : values) {
            if (v.getValue() instanceof NullConstant) {
                return true;
            }
        }
        return false;
    }

    public boolean isStringComparison(IfStmt ifStmt) {
        List<ValueBox> values = ifStmt.getCondition().getUseBoxes();
        for (ValueBox v : values) {
            if (v.getValue() instanceof StringConstant) {
                return true;
            }
        }
        return false;
    }

    public String getStringInComparison(IfStmt ifStmt) {
        List<ValueBox> values = ifStmt.getCondition().getUseBoxes();
        for (ValueBox v : values) {
            if (v.getValue() instanceof StringConstant) {
                return v.getValue().toString();
            }
        }
        return null;
    }

	public boolean unitNeedsAnalysis(SootMethod method, String currClassName, Unit inUnit, StringBuilder messageType) {
        if (Utils.isAndroidMethod(method)) {
            return false;
        }
        if (method.getName().startsWith("access$")) {
            return false;
        }
        if (method.getName().startsWith("<init>")) {
            // constructor
            return false;
        }
        if (method.getName().startsWith("<clinit>")) {
            // static initializer
            return false;
        }

        BriefUnitGraph ug = new BriefUnitGraph(method.getActiveBody());
        SimpleLocalDefs localDefs = new SimpleLocalDefs(ug);
        for (Unit pred : ug.getPredsOf(inUnit)) {
            if (pred instanceof IfStmt) {
                //System.out.println("current unit: " + inUnit.toString()+", currClassName: "+currClassName+", method: "+method.toString());
                Boolean containsNullComp = isNullComparison((IfStmt) pred);
                controlDepPaths += 1;
                Boolean isIntentControlled = false;
                IfStmt predIfStmt = (IfStmt) pred;
                for (ValueBox useBox : predIfStmt.getUseBoxes()) {
                    if (useBox.getValue() instanceof Local) {
                        Local useLocal = (Local) useBox.getValue();
                        for (Unit defUnit : localDefs.getDefsOfAt(useLocal, predIfStmt)) {
                            // defUnit is the definition of useLocal at predIfStmt
                            Triplet debugInfo = new Triplet<Integer, String, String>(inUnit.getJavaSourceStartLineNumber(), inUnit.toString(), defUnit.toString());
                            Boolean defUnitUses = checkIfUnitUsesIntentPayload(defUnit, localDefs, messageType, containsNullComp, method, currClassName, debugInfo);
                            if (defUnitUses != null) {
                                if (defUnitUses.booleanValue()) {
                                    // pred of unit is an if-statement that contains usage of intent payload
                                    isIntentControlled = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (isIntentControlled) {
                    intentControlDepPaths += 1;
                    doesUnitNeedAnalysisSummary.put(inUnit, true);
                    logger.debug("UNIT: " + inUnit.toString() + " at line " + String.valueOf(inUnit.getJavaSourceStartLineNumber()) + " of method " + method.getName() + " and class " +method.getDeclaringClass().getName() );
                    return true;
                }
                doesUnitNeedAnalysisSummary.put(inUnit, false);
                return false;
            }
        }
        doesUnitNeedAnalysisSummary.put(inUnit,false);
        return false;
	}

//	@Override
	protected void internalTransform(String phaseName,
									 Map<String, String> options) {
		//logger.debug("Setting up dummy main method");
        //Utils.setupDummyMainMethod();
		logger.debug("Constructing CHA call graph");
		CHATransformer.v().transform();
		logger.debug("CHA call graph built");

		Hierarchy h = Scene.v().getActiveHierarchy();
		List<SootMethod> nonLifeCycleEntryPoints = new ArrayList<SootMethod>();
		// dynamic registration
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
							logger.debug("Marking " + m + " as a new entry point");
							nonLifeCycleEntryPoints.add(m);
						}
					}
				}
			}
		}
		List<SootMethod> newEntryPoints = new ArrayList<SootMethod>(Scene.v().getEntryPoints());
		newEntryPoints.addAll(nonLifeCycleEntryPoints);
		Scene.v().setEntryPoints(newEntryPoints);
		logger.debug("Entry points identified and added to Scene");

		logger.debug("Constructing CHA call graph");
		Options.v().set_time(false);
		CHATransformer.v().transform();
		logger.debug("CHA call graph built");

		List<SootMethod> rtoMethods = Utils.getMethodsInReverseTopologicalOrder();

		for (SootMethod m : rtoMethods) {
			if (m.getDeclaringClass().getName().contains("PackageIntentReceiver")) {
				logger.debug("Found method of PackageIntentReceiver: " + m);
			}
		}

		// dynamic registration
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
									logger.debug("Found android.content.Context.registerReceiver invocation at + " + u + " in " + m);
									String registeredType = ie.getArg(0).getType().toString();

									logger.debug("Type registered here: " + registeredType);
									SootClass receiverClass = Scene.v().getSootClass(registeredType);
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
			logger.debug("Constructing CHA call graph with entry points for dynamically registered receivers");
			Options.v().set_time(false);
			CHATransformer.v().transform();
			logger.debug("CHA call graph built");
			logger.debug("Recomputing RTO methods");
			rtoMethods = Utils.getMethodsInReverseTopologicalOrder();
		}

		String RECEIVER_FULL_PKG_NAME = "android.content.BroadcastReceiver";
		for (SootClass c : Scene.v().getApplicationClasses()) {
			if (c.isInterface()) {
				continue;
			}
			for (SootClass superClass : h.getSuperclassesOf(c)) {
				if (superClass.getName().equals(RECEIVER_FULL_PKG_NAME)) {
					logger.debug(c + " is a broadcast receiver");
				}
			}
		}

		rtoMethods = Utils.getMethodsInReverseTopologicalOrder();

		int currMethodCount=0;
		for (SootMethod method : rtoMethods) {
			logger.debug("Checking if I should analyze method: " + method);
			if (Utils.isApplicationMethod(method) && !method.getDeclaringClass().getName().startsWith("android.support")) {
				if (method.hasActiveBody()) {
					PatchingChain<Unit> units = method.getActiveBody().getUnits();
					logger.debug("Analyzing method: " + method);
					StringBuilder messageType = new StringBuilder("");
					for (Unit unit : units) {
						unitNeedsAnalysis(method, method.getDeclaringClass().getName(), unit, messageType);
					}

    			}
				else {
					logger.debug("method " + method + " has no active body, so it's won't be analyzed.");
				}
			}

			logger.debug("Finished path analysis on method: " + method);
			logger.debug("Number of methods analyzed: " + currMethodCount);
			currMethodCount++;
		}
	}

//	@Override
	public void run() {
        Utils.setupDummyMainMethod();
		// resolve the PrintStream and System soot-classes
		Scene.v().addBasicClass("java.io.PrintStream", SIGNATURES);
		Scene.v().addBasicClass("java.lang.System", SIGNATURES);
		Scene.v().addBasicClass("android.util.Log", SIGNATURES);
		Options.v().set_whole_program(true);
		Options.v().setPhaseOption("jb", "use-original-names:true");
        PackManager.v().getPack("wjtp").add(new Transform("wjtp.constant", new ConstantValueInitTransformer()));
		PackManager.v().getPack("wjtp").add(new Transform("wjtp.pathexec", this));
		PackManager.v().getPack("wjtp").apply();

		Options.v().set_output_format(Options.output_format_dex);
		Options.v().set_force_overwrite(true); // allows the PackManager to override the existing apk file BUT it's not working :(
		PackManager.v().writeOutput(); //write instrumented apk to sootOutputDir
	}
}