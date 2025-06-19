
class Overloading {

  static {
    System.loadLibrary("native");
  }

  public static void main(String args[]) {
    new Overloading().foo();
    return;
  }

  private void foo() {
    byte[] arr = new byte[23];
    takeByte(arr);
    int len = arr.length;
    takeByte(arr, len);
  }

  private native void takeByte(byte[] arr);
  private native void takeByte(byte[] arr, int len);
}
