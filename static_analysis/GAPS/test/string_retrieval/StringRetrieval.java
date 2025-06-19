class StringRetrieval {
  static {
    System.loadLibrary("native");
  }

  public static void main(String args[]) {
    new StringRetrieval().foo();
    return;
  }

  private void foo() {
    String info = "{\"hey there\": 42}";
    this.takeString(info);
  }

  private native void takeString(String info);
}
