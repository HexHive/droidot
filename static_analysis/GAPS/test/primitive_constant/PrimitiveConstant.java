
class PrimitiveConstant {

  static {
    System.loadLibrary("native");
  }

  public static void main(String args[]) {
    new PrimitiveConstant().foo();
    return;
  }

  private void foo() {
    int a = 42;
    this.takeInt(a);
  }

  private native void takeInt(int v);
}
