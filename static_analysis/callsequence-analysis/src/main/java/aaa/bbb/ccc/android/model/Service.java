package aaa.bbb.ccc.android.model;

public class Service extends Component {

	public Service(String name) {
		super(name);
	}

	@Override
	public String getManifestType() {
		return "service";
	}
	
}
