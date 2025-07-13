package aaa.bbb.ccc.path.analyses;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.SootMethod;
import soot.Unit;
import soot.jimple.IfStmt;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.tagkit.BytecodeOffsetTag;
import soot.tagkit.Tag;
import soot.toolkits.graph.UnitGraph;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Expr;

import aaa.bbb.ccc.Utils;

/**
 * 
 * the most common analyses for paths are housed here
 * 
 *
 */
public abstract class PathAnalysis {
	
	Logger logger = LoggerFactory.getLogger(PathAnalysis.class);
	/** key: the unit for which each path starts, value: a set of paths */
	Map<Unit,Set< List<Unit>> > pathsMap;
	Map<Unit, Set<Set<String>>> pathCondsMap;
	
	
	PathAnalysis() {
		pathsMap = new HashMap<Unit,Set<List<Unit>>>();
		pathCondsMap = new HashMap<Unit,Set< Set<String> >>();
	}
	
	public abstract void handleStmtType(SootMethod method, UnitGraph eug, String currClassName, Unit currUnit, Unit pred, int tabs);
	
	void updatePaths(JimpleBasedInterproceduralCFG icfg, Unit startingUnit, List<Unit> currPath, Set<String> currPathCond, SootMethod method, String currClassName, int tabs) {
		Set< List<Unit> > paths = null;
		if (pathsMap.containsKey(startingUnit)) {
			paths = pathsMap.get(startingUnit);
		}
		else {
			paths = new HashSet< List<Unit> >();
		}
		paths.add(currPath);
		pathsMap.put(startingUnit, paths);
		logger.debug(Utils.createTabsStr(tabs) + "a path for " + startingUnit + " in " + method + " of " + currClassName + ":");
		List<Unit> pathAsList = new ArrayList<Unit>(currPath);
		for (int i=0;i<pathAsList.size();i++) {
			Unit unit = pathAsList.get(i);
			Unit succUnit = null;
			if (i-1 < pathAsList.size() && i >= 1) {
				succUnit = pathAsList.get(i-1);
			}
			
			if (unit instanceof IfStmt) {
				if (succUnit != null) {
					logger.debug(Utils.createTabsStr(tabs) + unit + " : " + ( icfg.isFallThroughSuccessor(unit, succUnit) ? "false" : "true" ));
				}
				else {
					logger.debug(Utils.createTabsStr(tabs) + unit + " : unk" );
				}
			} else {
				BytecodeOffsetTag bcoTag = null;
				for (Tag tag : unit.getTags()) {
					if (tag instanceof BytecodeOffsetTag) {
						bcoTag = (BytecodeOffsetTag)tag;
					}
				}
				logger.debug(Utils.createTabsStr(tabs) + unit + " @ bytecode offset " + bcoTag + " and source line number " + unit.getJavaSourceStartLineNumber());
			}
		}
		
		logger.debug(Utils.createTabsStr(tabs) + "Final path condition: ");
		for (String expr : currPathCond) {
			if (expr.contains("\n")) {
				String subExprs[] = expr.split("\n");
				for (String subExpr : subExprs) {
					logger.debug(Utils.createTabsStr(tabs) + "\t" + subExpr);
				}
			} else {
				logger.debug(Utils.createTabsStr(tabs) + "\t" + expr);
			}
		}
		
		Set< Set<String> > pathConds = null;
		if (pathCondsMap.containsKey(startingUnit)) {
			pathConds = pathCondsMap.get(startingUnit);
		}
		else {
			pathConds = new HashSet<Set<String>>();
		}
		pathConds.add(currPathCond);
		pathCondsMap.put(startingUnit, pathConds);
	}
}
