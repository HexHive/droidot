class ByteArrayExample {
  static {
    System.loadLibrary("native");
  }

  public static void main(String args[]) {
    new ByteArrayExample().foo();
    return;
  }

  private void foo() {
    byte[] arr = new byte[42];
    this.takeBytes(arr, arr.length);
  }

  private native void takeBytes(byte[] arr, int length);
}
