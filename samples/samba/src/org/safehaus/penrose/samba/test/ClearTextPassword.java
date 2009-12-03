package org.safehaus.penrose.samba.test;

import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ad.SupplementalCredentialsUtil;
import org.safehaus.penrose.ad.SupplementalCredentials;
import org.safehaus.penrose.ad.SupplementalCredentialsPackage;

import javax.naming.Context;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Endi S. Dewata
 */
public class ClearTextPassword {

    public static void main(String args[]) throws Exception {

        if (args.length != 4) {
            System.out.println("Usage:");
            System.out.println("    org.safehaus.penrose.samba.test.ClearTextPassword <URL> <Bind DN> <Password> <Target DN>");
            System.exit(0);
        }

        String url          = args[0];
        String bindDn       = args[1];
        String bindPassword = args[2];
        String targetDn     = args[3];

        System.out.println("URL           : "+url);
        System.out.println("Bind DN       : "+bindDn);
        System.out.println("Bind Password : "+bindPassword);
        System.out.println("Target DN     : "+targetDn);

        Map<String,String> parameters = new HashMap<String,String>();
        parameters.put(Context.PROVIDER_URL, url);
        parameters.put(Context.SECURITY_PRINCIPAL, bindDn);
        parameters.put(Context.SECURITY_CREDENTIALS, bindPassword);
        parameters.put("java.naming.ldap.attributes.binary", "supplementalCredentials");

        LDAPConnectionFactory connectionFactory = new LDAPConnectionFactory(parameters);
        LDAPClient client = new LDAPClient(connectionFactory);

        System.out.println("Connecting to "+parameters.get(Context.PROVIDER_URL)+"...");
        client.connect();

        SearchRequest request = new SearchRequest();
        request.setDn(targetDn);
        request.setScope(SearchRequest.SCOPE_BASE);
        request.setAttributes(new String[] { "supplementalCredentials" });

        SearchResponse response = new SearchResponse();

        System.out.println("Searching for "+request.getDn()+"...");
        client.search(request, response);

        SearchResult result = response.next();

        System.out.println("dn: "+result.getDn());
        for (Attribute attribute : result.getAttributes().getAll()) {
            for (Object value : attribute.getValues()) {
                if (value instanceof byte[]) {
                    //System.out.println(attribute.getName()+": "+BinaryUtil.encode(BinaryUtil.BIG_INTEGER, (byte[])value));
                } else {
                    //System.out.println(attribute.getName()+": "+value+" ("+value.getClass().getSimpleName()+")");
                }
            }
        }

        Attribute attribute = result.getAttribute("supplementalCredentials");
        byte[] buffer = (byte[])attribute.getValue();

        System.out.println("Supplemental Credentials:");
        System.out.printf("Length: %04X\n", buffer.length);

        SupplementalCredentialsUtil scUtil = new SupplementalCredentialsUtil();
        SupplementalCredentials sc = new SupplementalCredentials();
        scUtil.decode(sc, buffer);

        SupplementalCredentialsPackage scPackage = sc.getPackage("Primary:CLEARTEXT");
        if (scPackage != null) {
            String clearText = new String(scPackage.data, "UTF-16LE");
            System.out.printf("Password: [%s]\n", clearText);
        }
    }
}
