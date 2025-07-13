package aaa.bbb.ccc.path.util;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class DomUtil {
	
	public static Element getElement(Node node) {
		if (node.getNodeType() == Node.ELEMENT_NODE) {
			 
			Element elem = (Element) node;
			return elem;
		}
		return null;
	}

}
