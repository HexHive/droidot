package aaa.bbb.ccc.android;

import aaa.bbb.ccc.Config;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.model.*;
import aaa.bbb.ccc.path.util.DomUtil;
import aaa.bbb.ccc.sexpr.SExprRealParser;
import net.dongliu.apk.parser.ApkParser;
import org.javatuples.Triplet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.util.*;
import java.util.Map.Entry;

/**
 * 
 * Represents data extracted from an Android APK, and extracts data from the app's manifest
 *
 */
public class AndroidProcessor {
	Logger logger = LoggerFactory.getLogger(AndroidProcessor.class);
	
	/**
	 * the main package name of the app
	 */
	public String mainPackageName;
	/**
	 * the main component of the app
	 * 
	 */
	private String mainCompName;
	/**
	 * a key is the name of an app's Android component and the value is true if the component declares an intent filter in a manifest file
	 */
	public Map<String,Boolean> intentFiltersMap;
	/** 
	 * activities of the app 
	 */
	public Set<Component> activities = new LinkedHashSet<Component>();
	
	/**
	 * services of the app
	 */
	public Set<Component> services = new LinkedHashSet<Component>();

	/**
	 * broadcast receivers of the app
	 */
	public Set<Component> receivers = new LinkedHashSet<Component>();
	
	/**
	 * content providers of the app
	 */
	public Set<Component> providers = new LinkedHashSet<Component>();

	public Integer targetSdkVersion = null;
	public Integer minSdkVersion = null;

	/**
	 * 
	 * Constructs an instance of {@link aaa.bbb.ccc.android.model.Activity} from {@code activityNode}
	 * 
	 * @param activityNode with necessary information
	 * @return constructed Activity data structure
	 */
	private Activity constructAndroidActivityStructure(Node activityNode) {
		Element activityElem = DomUtil.getElement(activityNode);
		String activityName = activityElem.getAttribute("android:name");
		String exported=activityElem.getAttribute("android:exported");
		logger.debug("activity android:name - " + activityName);
		Activity activity = new Activity(activityName);
		if (exported.equals("true")) {
			activity.setExported(true);
		}
		
		NodeList intentFilters = activityElem.getElementsByTagName("intent-filter");
		for (int temp = 0; temp < intentFilters.getLength(); temp++) {
			Node intentFilterNode = intentFilters.item(temp);
			//logger.debug("Current Element :" + intentFilterNode.getNodeName());
			Element intentFilterElem = DomUtil.getElement(intentFilterNode);
			logger.debug("\tintent filter:");					
			extractIntentElementsFromManifest(intentFilterElem, activityElem, activity);
		}
		return activity;
	}
	
	/** Constructs an instance of {@link aaa.bbb.ccc.android.model.Service} from {@code serviceNode}
	 * @param serviceNode with necessary information
	 * @return constructed Service data structure
	 */
	private Service constructAndroidServiceStructure(Node serviceNode) {
		Element serviceElem = DomUtil.getElement(serviceNode);
		String serviceName = serviceElem.getAttribute("android:name");
		String exported=serviceElem.getAttribute("android:exported");
		logger.debug("service android:name - " + serviceName);
		Service service = new Service(serviceName);
		if (exported.equals("true")) {
			service.setExported(true);
		}
		
		NodeList intentFilters = serviceElem.getElementsByTagName("intent-filter");
		for (int temp = 0; temp < intentFilters.getLength(); temp++) {
			Node intentFilterNode = intentFilters.item(temp);
			//logger.debug("Current Element :" + intentFilterNode.getNodeName());
			Element intentFilterElem = DomUtil.getElement(intentFilterNode);
			logger.debug("\tintent filter:");					
			extractIntentElementsFromManifest(intentFilterElem, serviceElem, service);
		}
		return service;
	}
	
	private Component constructAndroidComponentStructure(Node compNode) {
		Element elem = DomUtil.getElement(compNode);
		String name = elem.getAttribute("android:name");
		String exported=elem.getAttribute("android:exported");
		logger.debug(elem.getLocalName() + " android:name - " + name);
		Component specificComp = null;
		if (elem.getNodeName().equals("activity")) {
			specificComp = new Activity(name);
		}
		else if (elem.getNodeName().equals("service")) {
			specificComp = new Service(name);
		}
		else if (elem.getNodeName().equals("receiver")) {
			specificComp = new Receiver(name);
		}
		else if (elem.getNodeName().equals("provider")) {
			specificComp = new Provider(name);
		}
		else {
			throw new RuntimeException("Unsupported component type: " + specificComp);
		}
		
		if (exported.equals("true")) {
			specificComp.setExported(true);
		}
		
		NodeList intentFilters = elem.getElementsByTagName("intent-filter");
		for (int temp = 0; temp < intentFilters.getLength(); temp++) {
			Node intentFilterNode = intentFilters.item(temp);
			//logger.debug("Current Element :" + intentFilterNode.getNodeName());
			Element intentFilterElem = DomUtil.getElement(intentFilterNode);
			logger.debug("\tintent filter:");					
			extractIntentElementsFromManifest(intentFilterElem, elem, specificComp);
		}
		return specificComp;
	}

	public int extractApkFilters(String apkFilePath, Set<Intent> totalIntents, JSONObject annotatedJson) {
		try {
			ApkParser apkParser = new ApkParser(new File(apkFilePath));
			apkParser.setPreferredLocale(Locale.ENGLISH);

			String xml = apkParser.getManifestXml();

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			InputSource is = new InputSource(new StringReader(xml));
			Document doc = dBuilder.parse(is);

			//mainPackageName = doc.getDocumentElement().getAttribute("package");

			NodeList usesSdks = doc.getElementsByTagName("uses-sdk");
			for (int i = 0; i < usesSdks.getLength(); i++) {
				Node usesSdkNode = usesSdks.item(i);
				Element usesSdkElem = DomUtil.getElement(usesSdkNode);

				NodeList activityNodes = doc.getElementsByTagName("activity");
				for (int activityIdx = 0; activityIdx < activityNodes.getLength(); activityIdx++) {
					Node activityNode = activityNodes.item(activityIdx);
					Activity activity = constructAndroidActivityStructure(activityNode);
					System.out.println("activity name: " + activity.getName());
					Set<IntentFilter> intentFilters = activity.getIntentFilters();
					JSONObject activityJson = new JSONObject();
					JSONObject intentFiltersJson = new JSONObject();
					JSONArray categoriesJson = new JSONArray();
					JSONArray actionsJson = new JSONArray();
					JSONArray dataJson = new JSONArray();
					for (IntentFilter filter : intentFilters) {
						categoriesJson.addAll(filter.categories);
						actionsJson.addAll(filter.actions);
						dataJson.addAll(filter.data.values());
					}
					if (actionsJson.size()!=0 || categoriesJson.size()!=0 || dataJson.size()!=0) {
						if (actionsJson.size()!=0) {
							intentFiltersJson.put("Action", actionsJson);
						}
						if (categoriesJson.size()!=0) {
							intentFiltersJson.put("Category", categoriesJson);
						}
						if (dataJson.size()!=0) {
							intentFiltersJson.put("Data", dataJson);
						}
						activityJson.put("IntentFilter", intentFiltersJson);
						annotatedJson.put(activity.getName(), activityJson);
					}
				}

				NodeList serviceNodes = doc.getElementsByTagName("service");
				for (int serviceIdx = 0; serviceIdx < serviceNodes.getLength(); serviceIdx++) {
					Node serviceNode = serviceNodes.item(serviceIdx);
					Service service = constructAndroidServiceStructure(serviceNode);
					System.out.println("service name: " + service.getName());
					Set<IntentFilter> intentFilters = service.getIntentFilters();
					JSONObject serviceJson = new JSONObject();
					JSONObject intentFiltersJson = new JSONObject();
					JSONArray categoriesJson = new JSONArray();
					JSONArray actionsJson = new JSONArray();
					JSONArray dataJson = new JSONArray();
					for (IntentFilter filter : intentFilters) {
						categoriesJson.addAll(filter.categories);
						actionsJson.addAll(filter.actions);
						dataJson.addAll(filter.data.values());
					}
					if (actionsJson.size()!=0 || categoriesJson.size()!=0 || dataJson.size()!=0) {
						if (actionsJson.size()!=0) {
							intentFiltersJson.put("Action", actionsJson);
						}
						if (categoriesJson.size()!=0) {
							intentFiltersJson.put("Category", categoriesJson);
						}
						if (dataJson.size()!=0) {
							intentFiltersJson.put("Data", dataJson);
						}
						serviceJson.put("IntentFilter", intentFiltersJson);
						annotatedJson.put(service.getName(), serviceJson);
					}
				}

				NodeList receiverNodes = doc.getElementsByTagName("receiver");
				for (int receiverIdx = 0; receiverIdx < receiverNodes.getLength(); receiverIdx++) {
					Node receiverNode = receiverNodes.item(receiverIdx);
					Component receiver = constructAndroidComponentStructure(receiverNode);
					System.out.println("receiver name: " + receiver.getName());
					Set<IntentFilter> intentFilters = receiver.getIntentFilters();
					JSONObject receiverJson = new JSONObject();
					JSONObject intentFiltersJson = new JSONObject();
					JSONArray categoriesJson = new JSONArray();
					JSONArray actionsJson = new JSONArray();
					JSONArray dataJson = new JSONArray();
					for (IntentFilter filter : intentFilters) {
						categoriesJson.addAll(filter.categories);
						actionsJson.addAll(filter.actions);
						dataJson.addAll(filter.data.values());
					}
					if (actionsJson.size()!=0 || categoriesJson.size()!=0 || dataJson.size()!=0) {
						if (actionsJson.size()!=0) {
							intentFiltersJson.put("Action", actionsJson);
						}
						if (categoriesJson.size()!=0) {
							intentFiltersJson.put("Category", categoriesJson);
						}
						if (dataJson.size()!=0) {
							intentFiltersJson.put("Data", dataJson);
						}
						receiverJson.put("IntentFilter", intentFiltersJson);
						annotatedJson.put(receiver.getName(), receiverJson);
					}
				}

				apkParser.close();
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (ParserConfigurationException e) {
			throw new RuntimeException(e);
		} catch (SAXException e) {
			throw new RuntimeException(e);
		}

		return 0;
	}

	public int extractApkCategories(String apkFilePath) {
		boolean printAllManifestEnabled = false;
		int totalCategories = 0;

		try {
			ApkParser apkParser = new ApkParser(new File(apkFilePath));
			apkParser.setPreferredLocale(Locale.ENGLISH);

			String xml = apkParser.getManifestXml();
			/*
			if (printAllManifestEnabled) {
				logger.debug(xml);
			}
			 */

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			InputSource is = new InputSource(new StringReader(xml));
			Document doc = dBuilder.parse(is);

			//mainPackageName = doc.getDocumentElement().getAttribute("package");

			NodeList usesSdks = doc.getElementsByTagName("uses-sdk");
			for (int i = 0; i < usesSdks.getLength(); i++) {
				Node usesSdkNode = usesSdks.item(i);
				Element usesSdkElem = DomUtil.getElement(usesSdkNode);

				NodeList activityNodes = doc.getElementsByTagName("activity");
				for (int activityIdx = 0; activityIdx < activityNodes.getLength(); activityIdx++) {
					Node activityNode = activityNodes.item(activityIdx);
					Activity activity = constructAndroidActivityStructure(activityNode);
					Set<IntentFilter> intentFilters = activity.getIntentFilters();
					for (IntentFilter filter : intentFilters) {
						totalCategories += filter.categories.size();
					}
				}

				NodeList serviceNodes = doc.getElementsByTagName("service");
				for (int serviceIdx = 0; serviceIdx < serviceNodes.getLength(); serviceIdx++) {
					Node serviceNode = serviceNodes.item(serviceIdx);
					Service service = constructAndroidServiceStructure(serviceNode);
					Set<IntentFilter> intentFilters = service.getIntentFilters();
					for (IntentFilter filter : intentFilters) {
						totalCategories += filter.categories.size();
					}
				}

				NodeList receiverNodes = doc.getElementsByTagName("receiver");
				for (int receiverIdx = 0; receiverIdx < receiverNodes.getLength(); receiverIdx++) {
					Node receiverNode = receiverNodes.item(receiverIdx);
					Component receiver = constructAndroidComponentStructure(receiverNode);
					Set<IntentFilter> intentFilters = receiver.getIntentFilters();
					for (IntentFilter filter : intentFilters) {
						totalCategories += filter.categories.size();
					}
				}

				apkParser.close();
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (ParserConfigurationException e) {
			throw new RuntimeException(e);
		} catch (SAXException e) {
			throw new RuntimeException(e);
		}

		return totalCategories;
	}

	public static String getSubstrByDotOccur(String str, int occurs) {
		int dotPos = 0;
		for (int i = 0; i < occurs; i++) {
			dotPos = str.indexOf(".", dotPos) +1;
		}
		if (dotPos == -1) {
			return str;
		} else {
			return str.substring(0, dotPos);
		}
	}

	public static Set<String> extractEntryPackages(int sensitivity) {
		Set<String> packs =  new LinkedHashSet<>();
		ApkParser apkParser = null;
		try {
			apkParser = new ApkParser(new File(Config.apkFilePath));
			apkParser.setPreferredLocale(Locale.ENGLISH);
			String xml = apkParser.getManifestXml();
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			InputSource is = new InputSource(new StringReader(xml));
			Document doc = dBuilder.parse(is);

			NodeList activityNodes = doc.getElementsByTagName("activity");
			for (int activityIdx = 0; activityIdx < activityNodes.getLength(); activityIdx++) {
				Node activityNode = activityNodes.item(activityIdx);
				Element activityElem = DomUtil.getElement(activityNode);
				String activityName = activityElem.getAttribute("android:name");
				//String activityPath = activityName.substring(0, activityName.lastIndexOf(".")+1); // with dot
				//System.out.println("> " + activityPath);
				if (sensitivity != 0) {
					String fuzzyActivityName = getSubstrByDotOccur(activityName, sensitivity);
					packs.add(fuzzyActivityName);
				} else {
					packs.add(activityName);
				}
			}

			NodeList serviceNodes = doc.getElementsByTagName("service");
			for (int serviceIdx = 0; serviceIdx < serviceNodes.getLength(); serviceIdx++) {
				Node serviceNode = serviceNodes.item(serviceIdx);
				Element serviceElem = DomUtil.getElement(serviceNode);
				String serviceName = serviceElem.getAttribute("android:name");
				//String servicePath = serviceName.substring(0, serviceName.lastIndexOf(".")+1);
				//System.out.println("> " + servicePath);
				if (sensitivity != 0) {
					String fuzzyServiceName = getSubstrByDotOccur(serviceName, sensitivity);
					packs.add(fuzzyServiceName);
				} else {
					packs.add(serviceName);
				}
			}

			NodeList receiverNodes = doc.getElementsByTagName("receiver");
			for (int receiverIdx = 0; receiverIdx < receiverNodes.getLength(); receiverIdx++) {
				Node receiverNode = receiverNodes.item(receiverIdx);
				Element elem = DomUtil.getElement(receiverNode);
				String name = elem.getAttribute("android:name");
				//String path = name.substring(0, name.lastIndexOf(".")+1);
				//System.out.println("> " + path);
				if (sensitivity != 0) {
					String fuzzyName = getSubstrByDotOccur(name, sensitivity);
					packs.add(fuzzyName);
				} else {
					packs.add(name);
				}
			}

			NodeList providerNodes = doc.getElementsByTagName("provider");
			for (int providerIdx = 0; providerIdx < providerNodes.getLength(); providerIdx++) {
				Node providerNode = providerNodes.item(providerIdx);
				Element elem = DomUtil.getElement(providerNode);
				String name = elem.getAttribute("android:name");
				//String path = name.substring(0, name.lastIndexOf(".")+1);
				//System.out.println("> " + path);
				if (sensitivity != 0) {
					String fuzzyName = getSubstrByDotOccur(name, sensitivity);
					packs.add(fuzzyName);
				} else {
					packs.add(name);
				}
			}

			apkParser.close();

		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (ParserConfigurationException e) {
			throw new RuntimeException(e);
		} catch (SAXException e) {
			throw new RuntimeException(e);
		}

		return packs;
	}

	/**
	 * extracts data from manifest and stores it to this class
	 */
	public void extractApkMetadata() {
		boolean printAllManifestEnabled = false;
		
		try {
			ApkParser apkParser = new ApkParser(new File(Config.apkFilePath));
			apkParser.setPreferredLocale(Locale.ENGLISH);

			String xml = apkParser.getManifestXml();
			if (printAllManifestEnabled) {
				logger.debug(xml);
			}

			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			InputSource is = new InputSource(new StringReader(xml));
			Document doc = dBuilder.parse(is);

			logger.debug("Root element :" + doc.getDocumentElement().getNodeName());
			mainPackageName = doc.getDocumentElement().getAttribute("package");
			logger.debug("package: " + mainPackageName);

			NodeList usesSdks = doc.getElementsByTagName("uses-sdk");
			for (int i=0;i<usesSdks.getLength();i++) {
				Node usesSdkNode = usesSdks.item(i);
				Element usesSdkElem = DomUtil.getElement(usesSdkNode);

				minSdkVersion = Integer.parseInt(usesSdkElem.getAttribute("android:minSdkVersion"));

				String targetSdkVersionStr = usesSdkElem.getAttribute("android:targetSdkVersion");
				if (targetSdkVersionStr.isEmpty()) {
					logger.debug("no target sdk version set, thus setting it equal to the min SDK version");
					targetSdkVersion = minSdkVersion;
					logger.debug("target sdk version: " + targetSdkVersion);
				} else {
					targetSdkVersion = Integer.parseInt(targetSdkVersionStr);
					logger.debug("target sdk version: " + targetSdkVersion);
				}
			}

			NodeList activityNodes = doc.getElementsByTagName("activity");
			for (int activityIdx = 0; activityIdx < activityNodes.getLength(); activityIdx++) {
				Node activityNode = activityNodes.item(activityIdx);
				Activity activity = constructAndroidActivityStructure(activityNode);
				this.activities.add(activity);
			}

			NodeList serviceNodes = doc.getElementsByTagName("service");
			for (int serviceIdx = 0; serviceIdx < serviceNodes.getLength(); serviceIdx++) {
				Node serviceNode = serviceNodes.item(serviceIdx);
				Service service = constructAndroidServiceStructure(serviceNode);
				this.services.add(service);
			}

			NodeList receiverNodes = doc.getElementsByTagName("receiver");
			for (int receiverIdx = 0; receiverIdx < receiverNodes.getLength(); receiverIdx++) {
				Node receiverNode = receiverNodes.item(receiverIdx);
				Component receiver = constructAndroidComponentStructure(receiverNode);
				this.receivers.add(receiver);
			}

			NodeList providerNodes = doc.getElementsByTagName("provider");
			for (int providerIdx = 0; providerIdx < providerNodes.getLength(); providerIdx++) {
				Node providerNode = providerNodes.item(providerIdx);
				Component provider = constructAndroidComponentStructure(providerNode);
				this.providers.add(provider);
			}

			apkParser.close();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * 
	 * Identifies and stores the name of the main component and intent filter information, and stores intent filter information to a {@code comp}	 
	 *  
	 * @param intentFilterElem intent filter data from manifest
	 * @param compElem corresponding component element of {@code comp}
	 * @param comp component data structure to store intent filters data to
	 */
	private void extractIntentElementsFromManifest(Element intentFilterElem, Element compElem, Component comp) {
		IntentFilter intentFilter = new IntentFilter();
		NodeList actionNodes = intentFilterElem.getElementsByTagName("action");
		for (int actionIndex = 0; actionIndex < actionNodes.getLength(); actionIndex++) {
			Element actionElem = DomUtil.getElement(actionNodes.item(actionIndex));
			String actionName = actionElem.getAttribute("android:name");
			logger.debug("\t\taction android:name - " + actionName);
			intentFilter.addAction(actionName);

			if (actionElem.getAttribute("android:name").equals(android.content.Intent.ACTION_MAIN)) {
				mainCompName = compElem.getAttribute("android:name");
			}
		}

		NodeList categoryNodes = intentFilterElem.getElementsByTagName("category");
		for (int categoryIndex = 0; categoryIndex < categoryNodes.getLength(); categoryIndex++) {
			Element categoryElem = DomUtil.getElement(categoryNodes.item(categoryIndex));
			String categoryName = categoryElem.getAttribute("android:name");
			logger.debug("\t\tcategory android:name - " + categoryName);
			intentFilter.addCategory(categoryName);
		}

		NodeList dataNodes = intentFilterElem.getElementsByTagName("data");
		for (int dataIndex = 0; dataIndex < dataNodes.getLength(); dataIndex++) {
			Element dataElem = DomUtil.getElement(dataNodes.item(dataIndex));
			NamedNodeMap attributes = dataElem.getAttributes();
			for (int attrIdx = 0; attrIdx < attributes.getLength(); attrIdx++) {
				Node attrNode = attributes.item(attrIdx);
				String attrName = attrNode.getNodeName();
				String attrValue = attrNode.getNodeValue();
				logger.debug("\t\tdata attrNode: " + attrNode);
				logger.debug("\t\tdata nodeName: " + attrName);
				logger.debug("\t\tdata nodeValue: " + attrValue);
				intentFilter.addDatum(attrName,attrValue);
			}
		}
		comp.addIntentFilter(intentFilter);
	}
	
	/**
	 * 
	 * writes Intent commands for Android components to be executed using adb
	 * 
	 * @param vulnerableCompName component to generate Intent command for
	 * @param comp contains manifest data for {@code vulnerableComp}
	 * @param genIntent intent to be generated
	 * @param writer used to write Intent commands to a file
	 * @throws IOException c
	 */
	public synchronized void writeIntentCmdsForADB(String vulnerableCompName, Component comp, Intent genIntent, BufferedWriter writer) throws IOException {
		writer.append("#!/bin/bash\n\n");
		String startCmd = null;
		if (comp instanceof Activity) {
			startCmd = "start";
		} else if (comp instanceof Service) {
			startCmd = "startservice";
		} else if (comp instanceof Receiver) {
			startCmd = "broadcast";
		}

		// Start the Activity/Service/Receiver
		String baseCmd = "adb shell su 0 am " + startCmd + " -n \"" + this.mainPackageName + "/" + vulnerableCompName + "\" ";
		
		for (Triplet<String,String,String> extraDatum : genIntent.extras) {
			String key = extraDatum.getValue1();
			
			String value = extraDatum.getValue2();
			String cmdValue = value;
			Double doubleVal = null;

			if (value != null) {
				if (value.contains("/")) {
					String[] tokens = value.split("/");
					Double num = Double.parseDouble(tokens[0]);
					Double denom = Double.parseDouble(tokens[1]);
					doubleVal = num / denom;
					cmdValue = doubleVal.toString();
				}
			}
			
			String type = extraDatum.getValue0();
			String typeConv = type.trim();
			boolean supportedType = false;
			if (typeConv.equals("int")) {
				baseCmd += "--ei ";
				supportedType = true;
			}
			else if (typeConv.equals("java.lang.String")) {
				baseCmd += "--es ";
				
				if (cmdValue.equals("")) {
					cmdValue = "AAA";
				}
				
				supportedType = true;
			}
			else if (typeConv.equals("String")) {
				baseCmd += "--es ";

				cmdValue = "AAA";
				supportedType = true;
			}
			else if (typeConv.equals("boolean")) {
				baseCmd += "--ez ";
				
				Integer cmdValueAsInt = Integer.parseInt(cmdValue);
				Boolean boolValue = (cmdValueAsInt != 0);
				cmdValue = boolValue.toString();
				
				supportedType = true;
			}
			else if (typeConv.equals("long")) {
				baseCmd += "--el ";
				supportedType = true;
			}
			else if (typeConv.equals("float")) {
				baseCmd += "--ef ";
				supportedType = true;
			}
			else if (typeConv.equals("java.lang.String[]")) {
				baseCmd += "--esa ";
				supportedType = true;
			}
			else if (typeConv.equals("java.util.ArrayList")) {
				baseCmd += "--esa ";
				supportedType = true;
			}
			if (supportedType) {
				baseCmd += key + " " + cmdValue + " ";
			}
		}
		
		writeIntentCommandsUsingBaseForADB(comp, genIntent.action, genIntent.uri, genIntent.categories, writer, baseCmd);
	}
	
	/**
	 * 
	 * writes Intent commands for Android components to be executed using drozer
	 * 
	 * @param vulnerableCompName component to generate Intent command for
	 * @param comp contains manifest data for {@code vulnerableComp}
	 * @param genIntent intent to generate
	 * @param writer used to write Intent commands to a file
	 * @throws IOException c
	 */
	public synchronized void writeIntentCmdsForDrozer(String vulnerableCompName, Component comp, Intent genIntent, BufferedWriter writer) throws IOException {
		String module = null;
		if (comp instanceof Activity) {
			module = "app.activity.start";
		} else if (comp instanceof Service) {
			module = "app.service.start";
		} else if (comp instanceof Receiver) {
			module = "app.broadcast.send";
		}
		
		String baseCmd = "run " + module + " --component " + this.mainPackageName + " " + vulnerableCompName + " ";
		for (Triplet<String,String,String> extraDatum : genIntent.extras) {
			String type = extraDatum.getValue0();
			String typeConv = type.trim();

			String key = extraDatum.getValue1();
			String value = extraDatum.getValue2();
			String cmdValue = value;
			if (typeConv.equals("int") || typeConv.equals("float") || typeConv.equals("double") || typeConv.equals("short") || typeConv.equals("long")) {
				cmdValue = Double.toString(SExprRealParser.convertSExprToReal(value));
				if (typeConv.equals("int")) {
					// otherwise will raise Exception because cmdValue is has a period (because it is a double)
					// cmdValue = Integer.toString(Integer.parseInt(cmdValue));
					cmdValue = Integer.toString(Integer.parseInt(value));
				}
			}

			if (typeConv.equals("int")) {
				typeConv = "integer";
			} else if (typeConv.equals("java.lang.String")) {
				typeConv = "string";
			} else if (typeConv.equals("boolean")) {
				Integer cmdValueAsInt = Integer.parseInt(cmdValue);
				Boolean boolValue = (cmdValueAsInt != 0);
				cmdValue = boolValue.toString();
			}
			
			baseCmd += "--extra " + typeConv + " " + key + " " + cmdValue + " ";
		}
		writeIntentCommandsUsingBaseForDrozer(writer, baseCmd, genIntent.action, genIntent.uri, genIntent.categories);
	}

	/**
	 * 
	 * Writes the ADB Intent commands to {@code writer} for component {@code comp} using the {@code baseCmd} and adds
	 * payload to the Intent based on analyses performed
	 * 
	 * @param comp component to generate Intent commands for
	 * @param action action of Intent
	 * @param writer used to write the Intent commands to some output stream
	 * @param baseCmd the base Intent command, which includes the adb command to write to component {@code Component}
	 * @throws IOException int sleepTime = 2;
		String sleepCmd = "sleep " + sleepTime;
	 */
	private synchronized void writeIntentCommandsUsingBaseForADB(Component comp,
																 String action,
																 Uri uri,
																 Set<String> categories,
																 BufferedWriter writer,
																 String baseCmd) throws IOException {
		float sleepAfterIntentTime = 3f;
		float sleepAfterStopTime = 2f;
		String sleepAfterIntentCmd = "sleep " + sleepAfterIntentTime;
		String sleepAfterStopCmd = "sleep " + sleepAfterStopTime;
		String stopCmd = "adb shell am force-stop " + this.mainPackageName;
		logger.debug("\t\t" + baseCmd);
		writer.append(baseCmd + "\n");
		writer.append("echo " + baseCmd + "\n");
		writer.append(sleepAfterIntentCmd + "\n");
		writer.append(stopCmd + "\n");
		writer.append(sleepAfterStopCmd + "\n");
		/*for (IntentFilter filter : comp.getIntentFilters()) {
			for (String action : filter.actions) {
				logger.debug("\t\t" + action);
				String baseActionCmd = baseCmd + " -a \"" + action + "\"";
				logger.debug("\t\t" + baseActionCmd);
				logger.debug("\n");
				writer.append(baseActionCmd + "\n");
				writer.append("echo " + baseActionCmd + "\n");
				writer.append(sleepCmd + "\n");
				writer.append(stopCmd + "\n");
				writer.append(sleepCmd + "\n");
				for (String category : filter.categories) {
					logger.debug("\t\t" + action);
					logger.debug("\t\t" + category);
					String baseActionCatCmd = baseActionCmd + " -c \"" + category + "\"";
					logger.debug("\t\t" + baseActionCatCmd);
					logger.debug("\n");
					writer.append(baseActionCatCmd + "\n");
					writer.append("echo " + baseActionCatCmd + "\n");
					writer.append(sleepCmd + "\n");
					writer.append(stopCmd + "\n");
					writer.append(sleepCmd + "\n");
					for (Entry<String, String> datum : filter.data.entrySet()) {
						logger.debug("\t\t" + action);
						logger.debug("\t\t" + category);
						logger.debug("\t\t" + datum);
					}
				}
			}
		}*/
		String baseActionCmd = baseCmd;
		if (action != null) {
			baseActionCmd += " -a \"" + action + "\"";
			logger.debug("\t\t" + baseActionCmd);
			logger.debug("\n");
			writer.append(baseActionCmd + "\n");
			writer.append(sleepAfterIntentCmd + "\n");
			writer.append(stopCmd + "\n");
			writer.append(sleepAfterStopCmd + "\n");
		}
		if (uri != null) {
			String baseUriCmd = baseActionCmd + " -d \"" + uri.whole + "\"";
			logger.debug("\t\t" + baseUriCmd);
			logger.debug("\n");
			writer.append(baseUriCmd + "\n");
			writer.append(sleepAfterIntentCmd + "\n");
			writer.append(stopCmd + "\n");
			writer.append(sleepAfterStopCmd + "\n");
		}
		for (String category : categories) {
			String baseCatCmd = baseCmd + " -c \"" + category + "\"";
			logger.debug("\t\t" + baseCatCmd);
			logger.debug("\n");
			writer.append(baseCatCmd + "\n");
			writer.append(sleepAfterIntentCmd + "\n");
			writer.append(stopCmd + "\n");
			writer.append(sleepAfterStopCmd + "\n");
		}
	}
	
	/**
	 * 
	 * Writes the drozer Intent commands to {@code writer} for component {@code comp} using the {@code baseCmd} and adds
	 * payload to the Intent based on analyses performed
	 * 
	 * @param writer used to write the Intent commands to some output stream
	 * @param baseCmd the base Intent command, which includes the adb command to write to component {@code Component}
	 * @param categories
	 * @throws IOException int sleepTime = 2;
		String sleepCmd = "sleep " + sleepTime;
	 */
	private synchronized void writeIntentCommandsUsingBaseForDrozer(BufferedWriter writer,
																	String baseCmd,
																	String action,
																	Uri uri,
																	Set<String> categories) throws IOException {
		float sleepAfterIntentTime = 3f;
		float sleepAfterStopTime = 2f;
		String sleepAfterIntentCmd = "sleep " + sleepAfterIntentTime;
		String sleepAfterStopCmd = "sleep " + sleepAfterStopTime;
		String forceStopCmd = "adb shell am force-stop " + this.mainPackageName;
		logger.debug("\t\t" + baseCmd);
		writer.append("#!/bin/bash\n");
		writer.append("drozer console connect -c \"" + baseCmd + "\"\n");
		writer.append(sleepAfterIntentCmd + "\n");
		writer.append(forceStopCmd + "\n");
		writer.append(sleepAfterStopCmd + "\n");
		/*
		if (action == null) {
			// for action, force stop after the adb command that sent action
			writer.append(forceStopCmd + "\n");
			writer.append(sleepAfterStopCmd + "\n");
		}
		 */

		//writerDrozerCmdForIntentFilters(comp, writer, baseCmd, action, sleepCmd);

		String baseActionCmd = baseCmd;
		if (action != null) {
			baseActionCmd += " --action \"" + action + "\"";
			logger.debug("\t\t" + baseActionCmd);
			logger.debug("\n");
			writer.append("drozer console connect -c \"" + baseActionCmd + "\"\n");
			writer.append(sleepAfterIntentCmd + "\n");
			// for certain actions they can only be sent by the Framework. However,
			// adb can bypass that
			/*
			writer.append("adb shell su 0 am broadcast -a " + action + " \n");
			// force stop after the restrictive action is sent
			writer.append(forceStopCmd + "\n");
			writer.append(sleepAfterStopCmd + "\n");
			 */
		}

		for (String category : categories) {
			logger.debug("\t\t" + action);
			logger.debug("\t\t" + category);
			String baseActionCatCmd = baseActionCmd + " --category \"" + category + "\"";
			logger.debug("\t\t" + baseActionCatCmd);
			logger.debug("\n");
			writer.append("drozer console connect -c \"" + baseActionCatCmd + "\"\n");
			writer.append(sleepAfterIntentCmd + "\n");
		}

		if (uri != null) {
			baseActionCmd += " --data-uri" + uri.whole;
			logger.debug("\t\t" + baseActionCmd);
			logger.debug("\n");
			writer.append("drozer console connect -c \"" + baseActionCmd + "\"\n");
			writer.append(sleepAfterIntentCmd + "\n");
		}
	}

	private void writerDrozerCmdForIntentFilters(Component comp, BufferedWriter writer, String baseCmd, String action, String sleepCmd) throws IOException {
		for (IntentFilter filter : comp.getIntentFilters()) {
			logger.debug("\t\t" + action);
			String baseActionCmd = baseCmd;
			if (action != null) {
				baseActionCmd += " --action \"" + action + "\"";
			}
			logger.debug("\t\t" + baseActionCmd);
			logger.debug("\n");
			writer.append(baseActionCmd + "\n");
			writer.append(sleepCmd + "\n");
			for (String category : filter.categories) {
				logger.debug("\t\t" + action);
				logger.debug("\t\t" + category);
				String baseActionCatCmd = baseActionCmd + " --category \"" + category + "\"";
				logger.debug("\t\t" + baseActionCatCmd);
				logger.debug("\n");
				writer.append(baseActionCatCmd + "\n");
				writer.append(sleepCmd + "\n");
				for (Entry<String, String> datum : filter.data.entrySet()) {
					logger.debug("\t\t" + action);
					logger.debug("\t\t" + category);
					logger.debug("\t\t" + datum);
				}
			}
		}
	}

	public Component findComponent(String vulnerableComp) {
		String fullCompName = null;
		for (Component activity : this.activities) {
			fullCompName = Utils.getFullCompName(this.mainPackageName, activity.getName());
			if (fullCompName.equals(vulnerableComp)) {
				return activity;
			}
		}
		
		for (Component service : this.services) {
			fullCompName = Utils.getFullCompName(this.mainPackageName, service.getName());
			if (fullCompName.equals(vulnerableComp)) {
				return service;
			}
		}
		
		for (Component receiver : this.receivers) {
			fullCompName = Utils.getFullCompName(this.mainPackageName, receiver.getName());
			if (fullCompName.equals(vulnerableComp)) {
				return receiver;
			}
		}
		
		for (Component provider : this.providers) {
			fullCompName = Utils.getFullCompName(this.mainPackageName, provider.getName());
			if (fullCompName.equals(vulnerableComp)) {
				return provider;
			}
		}
		
		return null;
		
	}
}
