package aaa.bbb.ccc.android.model;

public class Activity extends Component {

	public Activity(String name) {
		super(name);
	}

	@Override
	public String getManifestType() {
		return "activity";
	}
}
