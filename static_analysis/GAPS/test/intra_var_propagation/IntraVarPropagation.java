class IntraVarPropagation {
  static {
    System.loadLibrary("native");
  }

  public static void main(String args[]) {
    Wrapper wrap = new Wrapper();
    wrap.a = 77;
    new IntraVarPropagation().foo();
    return;
  }

  private void foo() {
    Wrapper wrap = new Wrapper();
    wrap.a = 42;
    this.takeInt(wrap.a);
  }

  private native void takeInt(int v);
}
