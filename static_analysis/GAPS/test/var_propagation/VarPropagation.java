class VarPropagation {
    int a = 42;
  static {
    System.loadLibrary("native");
  }

  public static void main(String args[]) {
    Wrapper wrap = new Wrapper();
    wrap.a = 32;
    new VarPropagation().foo();
    return;
  }

  private void foo() {
    Wrapper wrap = new Wrapper();
    wrap.a = a;
    this.takeInt(wrap.a);
  }

  private native void takeInt(int v);
}
