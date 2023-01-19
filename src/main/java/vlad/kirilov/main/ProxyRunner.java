package vlad.kirilov.main;

import java.net.UnknownHostException;

public class ProxyRunner {
    public static void main(String[] args) throws UnknownHostException {
        Socks5Proxy server = new Socks5Proxy( "127.0.0.1",1080);
        server.start();
        //System.out.println(InetAddress.getByName("localhost"));
    }
}
