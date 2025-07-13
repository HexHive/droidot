package aaa.bbb.ccc.android.model;

import java.util.LinkedHashSet;
import java.util.Set;

public abstract class Component {
	String name = "";
	Set<IntentFilter> intentFilters = new LinkedHashSet<IntentFilter>();
	private boolean isExported=false;
	
	public void addIntentFilter(IntentFilter intentFilter) {
		intentFilters.add(intentFilter);
	}
	
	public Set<IntentFilter> getIntentFilters() {
		return intentFilters;	
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	Component(String name) {
		this.name = name;
	}
	
	public String getName() {
		return this.name;
	}
	
	public String toString()  {
		return name;
	}

	public abstract String getManifestType();
	
	public boolean isExported() {
		return isExported;
	}

	public void setExported(boolean isExported) {
		this.isExported = isExported;
	}
}
