package aaa.bbb.ccc.sexpr;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SExprRealParser {

    public static double convertSExprToReal(String expr) {
        Double retVal = null;

        Pattern negP = Pattern.compile("\\(\\s*-\\s+([^\\(\\)]+)\\)");
        Matcher negM = negP.matcher(expr);
        while (negM.find()) {
            String posVal = negM.group(1);
            retVal = Double.parseDouble(posVal)*-1;
        }

        Pattern posP = Pattern.compile("^(?!\\()(.+)");
        Matcher posM = posP.matcher(expr);
        while (posM.find()) {
            String posVal = posM.group(1);
            retVal = Double.parseDouble(posVal);
        }

        Pattern divP = Pattern.compile("\\(\\s*/\\s+(.+)\\s+(.+?)\\)");
        Matcher divM = divP.matcher(expr);
        while (divM.find()) {
            String leftVal = divM.group(1);
            String rightVal = divM.group(2);
            double divVal = Double.parseDouble(leftVal) / Double.parseDouble(rightVal);
            retVal = divVal;
        }

        Pattern negDivP = Pattern.compile("\\(\\s*-\\s*\\(\\s*/\\s+(.+)\\s+(.+)\\s*\\)\\s*\\)");
        Matcher negDivM = negDivP.matcher(expr);
        while (negDivM.find()) {
            String leftVal = negDivM.group(1);
            String rightVal = negDivM.group(2);
            double divVal = -1*Double.parseDouble(leftVal) / Double.parseDouble(rightVal);
            retVal = divVal;
        }
        return retVal;
    }

    public static void main(String[] args) {
        System.out.println(convertSExprToReal("(- 38)"));
        System.out.println(convertSExprToReal("5"));
        System.out.println(convertSExprToReal("(/ 77157.0 10.0)"));
        System.out.println(convertSExprToReal("(- (/ 77157.0 10.0))"));
        System.out.println(convertSExprToReal("2.0"));
        System.out.println(convertSExprToReal("(- 2.0)"));
    }
}
