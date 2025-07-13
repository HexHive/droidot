package aaa.bbb.ccc.path.analyses;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

public class Globals {
	
	public static int nullPointerCheckCount=0;
	public static String[] bundleExtraDataMethods = {"getString","getShort","getFloat","getBoolean","getDouble","getInt","getLong","hasExtra","containsKey"};
	public static String[] bundleExtraDataValues = {"getString","getShort","getFloat","getBoolean","getDouble","getInt","getLong"};
	public static String[] bundleExtraDataKeys = {"hasExtra","containsKey"};
	public static String[] getBundleMethods = {"getExtras","getBundleExtra"};
	public static String[] categoryMethods = {"hasCategory","getCategories"};
	//public static String[] stringReturningIntentMethods = {"getAction","getStringExtra"};

	public static String[] stringOps = {"equals","startsWith", "endsWith", "contains", "isEmpty"};
	public static Set<String> stringOpsSet = new LinkedHashSet<String>(Arrays.asList(stringOps));
	public static String[] numberExtras = {"getIntExtra","getDoubleExtra", "getFloatExtra", "getShortExtra", "getLongExtra"};
	public static Set<String> numberExtrasSet = new LinkedHashSet<String>(Arrays.asList(numberExtras));
	public static String[] numberBundle = {"getShort","getFloat", "getDouble", "getInt", "getLong"};
	public static Set<String> numberBundleSet = new LinkedHashSet<String>(Arrays.asList(numberBundle));
	public static String[] supportedExtras = {"getIntExtra","getDoubleExtra", "getFloatExtra", "getShortExtra", "getLongExtra", "getBooleanExtra", "getByteExtra", "getCharExtra", "getStringExtra"};
	public static Set<String> supportedExtrasSet = new LinkedHashSet<String>(Arrays.asList(supportedExtras));
	public static String[] stringReturningIntentMethods = {"getStringExtra", "getAction", "getString", "getDataString"};
	public static Set<String> bundleExtraDataMethodsSet = new LinkedHashSet<String>(Arrays.asList(bundleExtraDataMethods));
	public static Set<String> bundleExtraDataValuesSet = new LinkedHashSet<String>(Arrays.asList(bundleExtraDataValues));
	public static Set<String> bundleExtraDataKeysSet = new LinkedHashSet<String>(Arrays.asList(bundleExtraDataKeys));
	public static Set<String> categoryMethodsSet = new LinkedHashSet<String>(Arrays.asList(categoryMethods));
	public static Set<String> stringReturningIntentMethodsSet = new LinkedHashSet<String>(Arrays.asList(stringReturningIntentMethods));
	public static Set<String> getBundleMethodsSet = new LinkedHashSet<String>(Arrays.asList(getBundleMethods));
	
	public static String[] androidPkgPrefixes = {"android.","com.android.","dalvik.","java.","javax.","junit.","org.apache.","org.json.","org.w3c.dom.","org.xml.sax","org.xmlpull.", "kotlin."};
	public static Set<String> androidPkgPrefixesSet = new LinkedHashSet<String>(Arrays.asList(androidPkgPrefixes));

}
