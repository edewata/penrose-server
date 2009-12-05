package org.safehaus.penrose.ldap.connection;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.File;
import java.net.Socket;
import java.util.Collection;
import java.util.ArrayList;

import org.newsclub.net.unix.AFUNIXSocket;
import org.newsclub.net.unix.AFUNIXSocketAddress;
import org.ietf.ldap.LDAPUrl;
import org.safehaus.penrose.jldap.LDAPIUrl;

/**
 * @author Endi Sukma Dewata
 */
public class LDAPSocketFactory implements org.ietf.ldap.LDAPSocketFactory, com.novell.ldap.LDAPSocketFactory {

    protected Collection<LDAPUrl> urls;
    protected Integer timeout;

    protected SocketFactory sslSocketFactory;

    public LDAPSocketFactory() throws Exception {
        this(new ArrayList<LDAPUrl>());
    }

    public LDAPSocketFactory(String url) throws Exception {
        this(new LDAPUrl(url));
    }

    public LDAPSocketFactory(LDAPUrl url) throws Exception {
        urls = new ArrayList<LDAPUrl>();
        urls.add(url);

        sslSocketFactory = SSLSocketFactory.getDefault();
    }

    public LDAPSocketFactory(Collection<LDAPUrl> urls) throws Exception {
        this.urls = urls;
        sslSocketFactory = SSLSocketFactory.getDefault();
    }

    public Socket createSocket(String host, int port) throws IOException {

        Socket socket = null;

        for (LDAPUrl url : urls) {

            if (url instanceof LDAPIUrl) {
                LDAPIUrl ldapiUrl = (LDAPIUrl)url;
                socket = createUnixDomainSocket(ldapiUrl.getPath());

            } else {
                String urlHost = url.getHost();
                int urlPort = url.getPort();

                if (host.equals(urlHost) && port == urlPort) {
                    if (url.toString().startsWith("ldap://")) {
                        socket = createSecureSocket(host, port);
                    } else {
                        socket = createRegularSocket(host, port);
                    }
                }
            }
        }

        if (socket == null) {
            socket = createRegularSocket(host, port);
        }

        if (timeout != null) socket.setSoTimeout(timeout);

        return socket;
    }

    public Socket createRegularSocket(String host, int port) throws IOException {
        return new Socket(host, port);
    }

    public Socket createUnixDomainSocket(String path) throws IOException {
        AFUNIXSocket socket = AFUNIXSocket.newInstance();
        socket.connect(new AFUNIXSocketAddress(new File(path)));
        return socket;
    }

    public Socket createSecureSocket(String host, int port) throws IOException {
        return sslSocketFactory.createSocket(host, port);
    }

    public Integer getTimeout() {
        return timeout;
    }

    public void setTimeout(Integer timeout) {
        this.timeout = timeout;
    }
}
