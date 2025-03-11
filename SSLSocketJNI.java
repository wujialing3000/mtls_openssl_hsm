public class SSLSocketJNI {

    // 加载 OpenSSL 动态库
    static {
        System.loadLibrary("ssl_socket"); // 假设库名为 ssl_socket.so
    }

    // 定义原生方法
    public native long createSSLContext();
    public native long createSSL(long ctx, int fd);
    public native int SSLConnect(long ssl);
    public native int SSLRead(long ssl, byte[] buffer, int size);
    public native int SSLWrite(long ssl, byte[] data, int size);
    public native int SSLShutdown(long ssl);
    public native void freeSSL(long ssl);
    public native void freeSSLContext(long ctx);

}
