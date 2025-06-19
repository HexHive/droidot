import java.io.File;

class FilePath {

  static {
    System.loadLibrary("native");
  }

  public static void main(String args[]) {
    new FilePath().foo();
    return;
  }

  private void foo() {
    File f = new File("/tmp");
    String path = f.getAbsolutePath();
    this.takeString(path);
  }

  private native void takeString(String path);
}
