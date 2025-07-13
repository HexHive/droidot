package aaa.bbb.ccc.path.analyses;

//import edu.gmu.trimdroid.soot.utils.Util;
import aaa.bbb.ccc.Utils;
import org.javatuples.Pair;
import org.javatuples.Triplet;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.SimpleLiveLocals;
import soot.toolkits.scalar.SimpleLocalDefs;
import soot.util.Chain;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class DefaultPathAnalysis extends PathAnalysis{
	
	Map<Unit,Map<String,Stmt>> symStmtMaps;
	HashMap<Triplet<String, String, Unit>, Set<ConditionExpr>> pathConstraintMap;
	Map<Unit,Set< Set<Pair<Unit,Unit>>> > pathsMap; 
	
	
	DefaultPathAnalysis() {
		super();
		symStmtMaps = new HashMap<Unit,Map<String,Stmt>>();
		pathConstraintMap = new HashMap<Triplet<String,String,Unit>,Set<ConditionExpr>>();
		pathsMap = new HashMap<Unit,Set<Set<Pair<Unit,Unit>>>>();	
	}
	
	public void handleStmtType(SootMethod method, UnitGraph eug, String currClassName, Unit currUnit, Unit pred, int tabs) {
		//Stmt stmt = (Stmt) pred;
		Stmt stmt = (Stmt) currUnit;
		if (stmt instanceof JIfStmt) {
			handleIfStmt(method, currClassName, currUnit, stmt, eug);
		}
		else if (stmt instanceof InstanceInvokeExpr) {
			if (stmt.containsInvokeExpr())  {
				logger.debug("current stmt has InvokeExpr");
				InvokeExpr startingInvokeExpr = stmt.getInvokeExpr();
				if (startingInvokeExpr instanceof InstanceInvokeExpr) {
					InstanceInvokeExpr startInstanceInvokeExpr = (InstanceInvokeExpr)startingInvokeExpr;
					Type baseType = startInstanceInvokeExpr.getBase().getType();
					logger.debug("\tInvokeExpr base type of " + startInstanceInvokeExpr.getBase() + ": " + baseType);
				}
				
			}
		}
		else if (stmt instanceof JAssignStmt) {
			JAssignStmt assignStmt = (JAssignStmt)stmt;
			Value rightOp = assignStmt.getRightOp();
			if (rightOp instanceof AddExpr) {
				// TODO make handling arithmetic expressions meaningful
				handleAddExpr(method, currClassName, currUnit, stmt, eug);
			}
		}
	}
	
	public void handleIfStmt(SootMethod method, String currClassName,
			Unit startingUnit, Stmt stmt, UnitGraph eug) {
		JIfStmt ifStmt = (JIfStmt) stmt;
		ConditionExpr condition = (ConditionExpr)ifStmt.getCondition();
		Stmt target = ifStmt.getTarget();
		logger.debug("");
		logger.debug("Begin handling if stmt");
		logger.debug("Starting unit: " + startingUnit);
		logger.debug("In " + method.getSignature() );
		logger.debug("condition: " + condition);
		logger.debug("\ttarget stmt of condition: " + target);
		
		//Set<soot.toolkits.scalar.Pair<Value, Set<DefinitionStmt>>> reachingDefs = reachingDefsSolver.ifdsResultsAt(ifStmt);
		//printRelevantReachingDefsOfUnit(ifStmt, reachingDefs, 1);
		
		
		/*Map<String,Stmt> symStmtMap = null;
		if (symStmtMaps.containsKey(startingUnit)) {
			symStmtMap = symStmtMaps.get(startingUnit);
		}
		else {
			symStmtMap = new HashMap<String,Stmt>();
		}*/
		
		/*Map<String,String> concreteMap = null;
		if (concreteMaps.containsKey(startingUnit)) {
			concreteMap = concreteMaps.get(startingUnit);
		}
		else {
			concreteMap = new HashMap<String,String>();
		}*/
		
		Value op1 = condition.getOp1();
		Value op2 = condition.getOp2();
		
		try {
			handlePathConditionalBasedOnIntent(eug, ifStmt, op1, 1);
			handlePathConditionalBasedOnIntent(eug, ifStmt, op2, 1);
		}
		catch (RuntimeException e) {
			logger.error("caught RuntimeException",e);
		}
	}
	
	public void handlePathConditionalBasedOnIntent(UnitGraph unitGraph, Unit inUnit,
			Value condOpValue, int tabs) {
		String tabsStr = Utils.createTabsStr(tabs);
		if (condOpValue instanceof Local) {
			Local condOpLocal = (Local)condOpValue;
			SimpleLocalDefs simpleLocalDefs = new SimpleLocalDefs(unitGraph);
			List<Unit> defUnits = simpleLocalDefs.getDefsOfAt(condOpLocal, inUnit);
			logger.debug(tabsStr + "simple local definitions of " + condOpLocal + ": ");
			for (Unit defUnit : defUnits) {
				logger.debug(tabsStr + "\t" + defUnit);
				if (defUnit instanceof AssignStmt) {
					AssignStmt assignStmt = (AssignStmt) defUnit;
					if (assignStmt.containsInvokeExpr()) {
						if (assignStmt.getInvokeExpr() instanceof InstanceInvokeExpr) {
							InstanceInvokeExpr instanceInvokeExpr = (InstanceInvokeExpr)assignStmt.getInvokeExpr();
							if (instanceInvokeExpr.getMethod().getDeclaringClass().getName().contains("android.content.Intent") && 
								Pattern.matches("get.*Extra", instanceInvokeExpr.getMethod().getName()) ) {
								logger.debug(tabsStr + "\tDetected path conditional expression based off of extra data from Intent!");
								Value extraKeyValue = instanceInvokeExpr.getArg(0);
								if (extraKeyValue instanceof StringConstant) {
									StringConstant extraKeyStringConstant = (StringConstant)extraKeyValue;
									logger.debug(tabsStr + "\t\textra key:" + extraKeyStringConstant);
								}
								else {
									if (extraKeyValue instanceof Local) {
										Local extraKeyLocal = (Local)extraKeyValue;
										List<Unit> keyValDefUnits = simpleLocalDefs.getDefsOfAt(extraKeyLocal, assignStmt);
										logger.error("Definitions of " + extraKeyLocal);
										for (Unit keyValDefUnit : keyValDefUnits) {
											logger.error("\t" + keyValDefUnit);
										}
										throw new RuntimeException("This local argument should be a string constant: " + extraKeyValue);
									}
									else {
										throw new RuntimeException("This non-local argument should be a string constant: " + extraKeyValue);
									}
								}
								// identifyViewThatSendsIntent is for GUI test generation
								//identifyViewThatSendsIntent(tabs+2, extraKeyValue);
							}
							// 	if the variable in the conditional expression is obtained from a method of the Intent that started this Activity
							/*if (instanceInvokeExpr.getMethod().getDeclaringClass().getName().contains("android.app.Activity") && instanceInvokeExpr.getMethod().getName().contains("getIntent")) {
								logger.debug(tabsStr + "\tDetected path conditional expression based off of getIntent!");
								identifyViewThatSendsIntent(tabs, tabsStr);
							}*/
							// recursively check the base of the InstanceInvokeExpr
							handlePathConditionalBasedOnIntent(unitGraph,defUnit,instanceInvokeExpr.getBase(),tabs+1);
						}
					}
				}
			}
		}
	}


	public void obtainValuesForView(int tabs, SootMethod possibleIntentSendingMethod, SimpleLiveLocals liveLocals, Set<Integer> extractedInts, Set<Unit> doneUnits, Unit srcUnit) {
		if (!doneUnits.contains(srcUnit)) {
			//logger.debug(Utils.createTabsStr(tabs + 4) + " live locals at " + srcUnit + ":");
			Local paramLocal2 = possibleIntentSendingMethod.getActiveBody().getParameterLocal(2);
			List<Local> locals = liveLocals.getLiveLocalsBefore(srcUnit);
			for (Local local : locals) {
				if (local.equals(paramLocal2)) {
					logger.debug(Utils.createTabsStr(tabs + 5) + "Found live local matching 2nd parameter of this method: " + local);
					if (srcUnit instanceof IfStmt) {
						IfStmt srcIfStmt = (IfStmt) srcUnit;
						ConditionExpr cond = (ConditionExpr) srcIfStmt.getCondition();
						//Value op1 = cond.getOp1();
						Value op2 = cond.getOp2();
						if (op2 instanceof IntConstant) {
							IntConstant op2IntConst = (IntConstant) op2;
							logger.debug(Utils.createTabsStr(tabs + 5) + "int constant value: " + op2IntConst.value);
							extractedInts.add(op2IntConst.value);
						}
					}
				}

			}
			doneUnits.add(srcUnit);
		}
	}

	private String getActivityName(String activityWithPackage) {
		String[] tmp = activityWithPackage.split("\\.");
		return tmp[tmp.length-1];
	}
	
	private String getActivityPackage(String activityWithPackage) {
		String actvityName = getActivityName(activityWithPackage);
		return activityWithPackage.substring(0, activityWithPackage.length() - actvityName.length()-1);
	}
	
	private Value findWidgetId(Unit usedPoint, Chain<Unit> units) {
		// Check if the widget is looked up by Id
		for (ValueBox useBox : usedPoint.getUseBoxes()) {
			if (useBox.getValue() instanceof InvokeExpr) {
				InvokeExpr invokeExpr = (InvokeExpr) useBox.getValue();
				if (invokeExpr.getMethodRef().name().matches("^findViewById$")) {
					return invokeExpr.getArg(0);
				}
			}
		}
		// Otherwise do backward search for finding widget
		for (ValueBox useBox : usedPoint.getUseBoxes()) {
			Unit defPoint = null;
			Value usedVar = useBox.getValue();
// callee uses library functions in TrimDroid. This removes that dependencies
//			if (usedVar instanceof JInstanceFieldRef) {
//				JInstanceFieldRef ref = ((JInstanceFieldRef) usedVar);
//				defPoint = findClosestDefPointBackward(usedPoint, ref.getFieldRef(), units);
//			}
//			if (usedVar instanceof JimpleLocal) {
//				defPoint = findClosestDefPointBackward(usedPoint, usedVar, units);
//			}
//			if (defPoint != null) {
//				Value widgetId = findWidgetId(defPoint, units);
//				if (widgetId != null)
//					return widgetId;
//			}
		}
		
		Unit pred = null;
		Unit currUnit = usedPoint;
		while ((pred = units.getPredOf(currUnit)) != null) {
			if (pred instanceof InvokeStmt) {
				InvokeStmt invokeStmt = (InvokeStmt)pred;
				InvokeExpr invokeExpr = invokeStmt.getInvokeExpr();
				if (invokeExpr.getMethodRef().name().matches("^<init>$") && invokeExpr.getMethod().getDeclaringClass().getName().equals(("android.widget.ArrayAdapter"))) {
					return invokeExpr.getArg(1);
				}
			}
			currUnit = pred;
			
		}
		return null;
	}
	
//	protected Unit findClosestDefPointBackward(Unit usedPoint, SootFieldRef fieldRef, Chain<Unit> units) {
//		return Util.findClosestDefPointBackward(usedPoint, fieldRef, units);
//	}

//	protected Unit findClosestDefPointBackward(Unit usedPoint, Value var, Chain<Unit> units) {
//		return Util.findClosestDefPointBackward(usedPoint, var, units);
//	}
	
	
	protected void handleAddExpr(SootMethod method, String currClassName, Unit startingUnit, Stmt stmt, UnitGraph eug) {
		JAssignStmt assignStmt = (JAssignStmt)stmt;
		JAddExpr addExpr = (JAddExpr) assignStmt.getRightOp();;
		Value op1 = addExpr.getOp1();
		//Value op2 = addExpr.getOp2();
		
		logger.debug("Trying to handle AddExpr: " + stmt);
		
		Map<String,Stmt> symStmtMap = null;
		if (symStmtMaps.containsKey(startingUnit)) {
			symStmtMap = symStmtMaps.get(startingUnit);
		}
		else {
			symStmtMap = new HashMap<String,Stmt>();
		}
		
		if ( symStmtMap.containsKey(op1.toString()) ) {
			//Stmt symStmt = symStmtMap.get(op1.toString());
			symStmtMap.put(op1.toString(),stmt);
		}
		
		//storeAsSymIfLocal(symStmtMap,op1);
		//storeAsSymIfLocal(symStmtMap,op2);
		
		symStmtMaps.put(startingUnit,symStmtMap);
	}
}
