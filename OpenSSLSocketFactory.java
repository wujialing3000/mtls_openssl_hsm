import javax.net.ssl.*;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.conscrypt.Conscrypt;
import java.security.Security;

/**
 * 自定义的 OpenSSL SSLSocketFactory
 */
public class OpenSSLSocketFactory extends SSLSocketFactory {
    private SSLSocketFactory internalSSLSocketFactory;

    static {
        // 加载 OpenSSL 库
        System.loadLibrary("crypto");
        System.loadLibrary("ssl");

        // 使用 Conscrypt 作为 Provider，Conscrypt 基于 OpenSSL
        Security.insertProviderAt(Conscrypt.newProvider(), 1);
    }
	
	

    public OpenSSLSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance("TLS", "Conscrypt");
        sslContext.init(null, null, new SecureRandom());
        internalSSLSocketFactory = sslContext.getSocketFactory();
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return internalSSLSocketFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return internalSSLSocketFactory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return internalSSLSocketFactory.createSocket(s, host, port, autoClose);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return internalSSLSocketFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort) throws IOException {
        return internalSSLSocketFactory.createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(java.net.InetAddress host, int port) throws IOException {
        return internalSSLSocketFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(java.net.InetAddress address, int port, java.net.InetAddress localAddress, int localPort) throws IOException {
        return internalSSLSocketFactory.createSocket(address, port, localAddress, localPort);
    }
}
