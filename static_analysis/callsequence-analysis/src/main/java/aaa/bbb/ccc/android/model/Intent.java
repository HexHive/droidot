package aaa.bbb.ccc.android.model;

import aaa.bbb.ccc.path.analyses.TargetedPathTransformerSp;
import org.javatuples.Triplet;

import java.util.LinkedHashSet;
import java.util.Set;

public class Intent {
    // type,key,value
    public Set<Triplet<String,String,String>> extras = new LinkedHashSet<Triplet<String,String,String>>();
    public Uri uri;
    public String action;
    public String targetComponent;
    public String targetMethod;
    public Set<String> categories = new LinkedHashSet<String>();

    public Intent(Intent intent) {
        if (intent.extras != null) {
            this.extras = new LinkedHashSet<>(intent.extras);
        } else {
            this.extras = null;
        }

        if (intent.uri != null) {
            this.uri = new Uri(intent.uri);
        } else {
            this.uri = null;
        }

        if (intent.action != null) {
            this.action = new String(intent.action);
        } else {
            this.action = null;
        }

        if (intent.targetComponent != null) {
            this.targetComponent = new String(intent.targetComponent);
        }
        else {
            this.targetComponent = null;
        }

        if (intent.targetMethod != null) {
            this.targetMethod = new String(intent.targetMethod);
        }
        else {
            this.targetMethod = null;
        }

        if (this.categories != null) {
            this.categories = new LinkedHashSet<>(intent.categories);
        }
        else {
            this.categories = null;
        }
    }

    public Intent() {
        super();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Intent intent = (Intent) o;

        if (extras != null ? !extras.equals(intent.extras) : intent.extras != null) return false;
        if (action != null ? !action.equals(intent.action) : intent.action != null) return false;
        if (uri != null ? !uri.equals(intent.uri) : intent.uri != null) return false;
        if (targetComponent != null ? !targetComponent.equals(intent.targetComponent) : intent.targetComponent != null)
            return false;
        if (targetMethod != null ? !targetMethod.equals(intent.targetMethod) : intent.targetMethod != null)
            return false;
        return categories != null ? categories.equals(intent.categories) : intent.categories == null;

    }

    @Override
    public int hashCode() {
        int result = extras != null ? extras.hashCode() : 0;
        result = 31 * result + (action != null ? action.hashCode() : 0);
        result = 31 * result + (uri != null ? uri.hashCode() : 0);
        result = 31 * result + (targetComponent != null ? targetComponent.hashCode() : 0);
        result = 31 * result + (targetMethod != null ? targetMethod.hashCode() : 0);
        result = 31 * result + (categories != null ? categories.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Intent{" +
                "extras=" + extras +
                ", action='" + action + '\'' +
                ", targetComponent='" + targetComponent + '\'' +
                ", uri='" + uri + '\'' +
                ", categories=" + categories +
                '}';
    }
}
