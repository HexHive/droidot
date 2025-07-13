package aaa.bbb.ccc.path.analyses;

import soot.SootMethod;
import soot.Unit;
import soot.toolkits.graph.UnitGraph;

public class EmptyPathAnalysis extends PathAnalysis {
	@Override
	public void handleStmtType(SootMethod method, UnitGraph eug, String currClassName, Unit currUnit, Unit pred, int tabs) {
	
	}
}
