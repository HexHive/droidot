package aaa.bbb.ccc.android.model;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class IntentFilter {
	public Set<String> actions = new LinkedHashSet<String>();
	public Set<String> categories = new LinkedHashSet<String>();
	public Map<String,String> data = new LinkedHashMap<String,String>();
	
	public void addAction(String action) {
		actions.add(action);
	}
	
	public void addCategory(String category) {
		categories.add(category);
	}
	
	public void addDatum(String attrName, String value) {
		data.put(attrName,value);
	}
	
	@Override
	public boolean equals(Object object) {
		boolean result = false;
		if (object == null || object.getClass() != getClass()) {
			result = false;
		} else {
			IntentFilter filter = (IntentFilter) object;
			if (this.actions.equals(filter.actions) && this.categories.equals(filter.categories) && this.data.equals(filter.data)) {
				return true;
			}
		}
		return result;
	}
	
	@Override
	public int hashCode() {
		int hash = 3;
		hash = 7 * hash + this.actions.hashCode();
		hash = 7 * hash + this.categories.hashCode();
		hash = 7 * hash + this.data.hashCode();
		return hash;
	}
	
	@Override
	public String toString() {
		return actions.toString() + " : " + categories.toString() + " : " + data.toString();
	}
}
