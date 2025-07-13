package aaa.bbb.ccc.path.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.microsoft.z3.ArithExpr;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Model;
import com.microsoft.z3.Solver;
import com.microsoft.z3.Status;
import com.microsoft.z3.Z3Exception;

import soot.ArrayType;
import soot.CharType;
import soot.Local;
import soot.RefType;
import soot.Unit;
import soot.Value;
import soot.jimple.ConditionExpr;
import soot.jimple.DoubleConstant;
import soot.jimple.FloatConstant;
import soot.jimple.IfStmt;
import soot.jimple.IntConstant;
import soot.jimple.LongConstant;
import soot.jimple.NullConstant;
import soot.jimple.Stmt;
import soot.jimple.internal.JIfStmt;
import soot.jimple.internal.JimpleLocal;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;

public class PathUtils {
	
	public static boolean isNullCheckPathCondition(int tabs, Unit currUnit) {
		if (currUnit instanceof IfStmt) {
			IfStmt ifStmt = (IfStmt)currUnit;
			ConditionExpr condition = (ConditionExpr)ifStmt.getCondition();
			Value opVal1 = condition.getOp1();
			Value opVal2 = condition.getOp2();
			
			if ( isNullCheckCondition(opVal1, opVal2) || isNullCheckCondition(opVal2,opVal1) ) {
				return true;
			}
		}
		return false;
		
	}
	
	public static boolean isArrayTypePathCondition(int tabs, Unit currUnit) {
		if (currUnit instanceof IfStmt) {
			IfStmt ifStmt = (IfStmt)currUnit;
			ConditionExpr condition = (ConditionExpr)ifStmt.getCondition();
			Value opVal1 = condition.getOp1();
			Value opVal2 = condition.getOp2();
			
			if ( isArrayTypeCondition(opVal1) || isArrayTypeCondition(opVal2) ) {
				return true;
			}
		}
		return false;
		
	}
	
	public static boolean isCharTypePathCondition(int tabs, Unit currUnit) {
		if (currUnit instanceof IfStmt) {
			IfStmt ifStmt = (IfStmt)currUnit;
			ConditionExpr condition = (ConditionExpr)ifStmt.getCondition();
			Value opVal1 = condition.getOp1();
			Value opVal2 = condition.getOp2();
			
			if ( isCharTypeCondition(opVal1) || isCharTypeCondition(opVal2) ) {
				return true;
			}
		}
		return false;
		
	}
	
	public static boolean isDoubleRefTypePathCondition(int tabs, Unit currUnit) {
		if (currUnit instanceof IfStmt) {
			IfStmt ifStmt = (IfStmt)currUnit;
			ConditionExpr condition = (ConditionExpr)ifStmt.getCondition();
			Value opVal1 = condition.getOp1();
			Value opVal2 = condition.getOp2();
			
			Local local1 = null;
			Local local2 = null;
			if (opVal1 instanceof Local) {
				local1 = (Local)opVal1;
			}
			if (opVal2 instanceof Local) {
				local2 = (Local)opVal2;
			}
			
			if (local1 == null || local2 == null) {
				return false;
			}
			
			if ( local1.getType() instanceof RefType && local2.getType() instanceof RefType ) {
				return true;
			}
		}
		return false;
		
	}

	public static boolean isNullCheckCondition(Value opVal1, Value opVal2) {
		if (opVal1 instanceof Local) {
			Local opLocal1 = (Local)opVal1;
			if (opLocal1.getType() instanceof RefType) {
				if (opVal2 instanceof NullConstant) {
					return true;
				}
			}
		}
		return false;
	}
	
	public static boolean isArrayTypeCondition(Value opVal1) {
		if (opVal1 instanceof Local) {
			Local opLocal1 = (Local)opVal1;
			if (opLocal1.getType() instanceof ArrayType) {
				return true;
			}
		}
		return false;
	}
	
	public static boolean isCharTypeCondition(Value opVal1) {
		if (opVal1 instanceof Local) {
			Local opLocal1 = (Local)opVal1;
			if (opLocal1.getType() instanceof CharType) {
				return true;
			}
		}
		return false;
	}
}
