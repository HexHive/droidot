package aaa.bbb.ccc.android.model;

public class Uri {
    public String scheme = "";
    public String schemespecificpart = "";
    public String host = "";
    public String whole = "";

    public Uri(String uri) {
        if (uri.contains(":") && uri.contains("#")) {
            String [] uriParts = uri.split(":");
            this.scheme = uriParts[0];
            this.host = uriParts[1];
            String [] uriParts2 = this.host.split("#");
            this.schemespecificpart = uriParts2[0];
        } else if (uri.contains("://")) {
            String [] uriParts = uri.split("://");
            this.scheme = uriParts[0];
            this.host = uriParts[1];
        } else if (uri.contains(":")) {
            String [] uriParts = uri.split(":");
            this.scheme = uriParts[0];
            this.host = uriParts[1];
        }
        this.whole = uri;
    }

    public Uri(String scheme, String host) {
        this.scheme = scheme;
        this.host = host;
        if (!scheme.equals("") && !host.equals("")) {
            this.whole = scheme + ":" + host;
        } else if (scheme.equals("")) {
            this.whole = "file:" + host;
        } else {
            // host is ""
            this.whole = scheme + ":abc";
        }
    }

    public Uri(Uri uri) {
        this.scheme = uri.scheme;
        this.schemespecificpart = uri.schemespecificpart;
        this.host = uri.host;
        this.whole = uri.whole;
    }

    public String getWhole() {
        return this.whole;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Uri uri = (Uri) o;

        if (!whole.equals(uri.whole)) return false;
        if (!scheme.equals(uri.scheme)) return false;
        if (!schemespecificpart.equals(uri.schemespecificpart)) return false;
        return host.equals(uri.host);
    }

    @Override
    public int hashCode() {
        int result = whole.hashCode();
        result = 31 * result + scheme.hashCode();
        result = 31 * result + schemespecificpart.hashCode();
        result = 31 * result + host.hashCode();
        return result;
    }

}
