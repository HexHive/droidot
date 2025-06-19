
class Dependencies {

  static {
    System.loadLibrary("native");
  }

  public static void main(String args[]) {
    new Dependencies().foo();
    return;
  }

  private void foo() {
    int val = returnInt();
    takeInt(val);
  }

  private native int returnInt();
  private native void takeInt(int val);
}
