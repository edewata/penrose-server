package org.safehaus.penrose.jldap;

import com.novell.ldap.client.Debug;

import java.net.MalformedURLException;
import java.util.Enumeration;

/**
 * @author Endi S. Dewata
 */
public class LDAPIUrl extends org.ietf.ldap.LDAPUrl implements Cloneable {

    private String path;

    public LDAPIUrl(String url) throws MalformedURLException {
        super("ldap://localhost");
        parseURL(url);
    }

    private void parseURL(String url) throws MalformedURLException {

        int scanStart = 0;
        int scanEnd = url.length();

        if( Debug.LDAP_DEBUG)
            Debug.trace(  Debug.urlParse, "parseURL(" + url + ")");
        if( url == null)
            throw new MalformedURLException("LDAPUrl: URL cannot be null");

        // Check if URL is enclosed by < & >
        if( url.charAt(scanStart) == '<') {
            if( url.charAt(scanEnd - 1) != '>')
                throw new MalformedURLException("LDAPUrl: URL bad enclosure");
            scanStart += 1;
            scanEnd -= 1;
            if( Debug.LDAP_DEBUG)
                Debug.trace(  Debug.urlParse, "LDAPUrl: parseURL: Url is enclosed");
        }

        // Determine the URL scheme and set appropriate default port
        if( url.substring(scanStart, scanStart + 4).equalsIgnoreCase( "URL:")) {
            scanStart += 4;
        }
        if( url.substring(scanStart, scanStart + 8).equalsIgnoreCase( "ldapi://")) {
            scanStart += 8;
        } else {
            throw new MalformedURLException("LDAPIUrl: URL scheme is not ldapi");
        }

        path = decode(url.substring(scanStart, scanEnd));
        if( Debug.LDAP_DEBUG)
            Debug.trace(  Debug.urlParse, "parseURL: path " + path);
    }

    public String[] getAttributeArray() {
		return null;
    }

    public Enumeration getAttributes() {
		return null;
    }

    public String getDN() {
		return null;
    }

    public String[] getExtensions() {
		return null;
    }

    public String getFilter() {
		return null;
    }

    public String getPath() {
        return path;
    }

    public String getHost() {
		return "localhost";
    }

    public int getPort() {
		return 0;
    }

    public int getScope() {
		return 0;
    }

    public String toString() {
        StringBuffer url = new StringBuffer();
        url.append("ldapi://");
        url.append(encode(path));
        return url.toString();
    }
}