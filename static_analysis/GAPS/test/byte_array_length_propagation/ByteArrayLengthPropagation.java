class ByteArrayLengthPropagation {
    public int sz = 42;
  static {
    System.loadLibrary("native");
  }

  public static void main(String args[]) {
    new ByteArrayLengthPropagation().foo();
    return;
  }

  private void foo() {
    byte[] arr = new byte[sz];
    this.takeBytes(arr);
  }

  private native void takeBytes(byte[] arr);
}
