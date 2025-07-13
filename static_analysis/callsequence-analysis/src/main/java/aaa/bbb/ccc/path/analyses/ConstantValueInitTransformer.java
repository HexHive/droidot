package aaa.bbb.ccc.path.analyses;

import soot.SceneTransformer;
import java.util.Map;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.*;
import soot.tagkit.StringConstantValueTag;

/**
 * Transformer that adds the StringConstantValueTag to each static and non-final string fields
 * initialized in the static initializer since Soot did not associate their initial string
 * value with the field when transformed to SootField
 *
 * For phenomenon, this is useful for identifying the string constant used by get*Extra([string])
 */
public class ConstantValueInitTransformer extends SceneTransformer {

    public static ConstantValueInitTransformer  v() {
        return new ConstantValueInitTransformer  ();
    }

    @Override
    protected void internalTransform(String phaseName, Map<String, String> options) {
        for (SootClass sc : Scene.v().getClasses()) {
            transformClass(sc);
        }
    }

    public void transformClass(SootClass sc) {
        for (SootMethod method : sc.getMethods()) {
            if (method.isStaticInitializer()) {
                if (method.hasActiveBody()) {
                    for (Unit u : method.retrieveActiveBody().getUnits()) {
                        Stmt s = (Stmt) u;
                        for (ValueBox vb : s.getDefBoxes()) {
                            Value value = vb.getValue();
                            if (value instanceof FieldRef) {
                                FieldRef fieldref = (FieldRef) value;
                                SootField field = (SootField) fieldref.getField();
                                if (field.isStatic() && !field.isFinal()) {
                                    // check if field is assigned a string constant
                                    if (s instanceof AssignStmt) {
                                        AssignStmt as = (AssignStmt) s;
                                        if (as.getRightOp() instanceof StringConstant) {
                                            StringConstant str = (StringConstant) as.getRightOp();
                                            field.addTag(new StringConstantValueTag(str.value));
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
}