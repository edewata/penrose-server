package org.safehaus.penrose.changelog;

import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.util.BinaryUtil;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.io.BufferedReader;
import java.io.StringReader;
import java.util.Collection;
import java.util.ArrayList;

/**
 * @author Endi S. Dewata
 */
public class ChangeLog extends SearchResult {

    public static Logger log = LoggerFactory.getLogger(ChangeLog.class);

    public final static int ADD    = 1;
    public final static int MODIFY = 2;
    public final static int MODRDN = 3;
    public final static int DELETE = 4;

    protected Number changeNumber;
    protected Object changeTime;
    protected int changeAction;
    protected String changeUser;

    protected Request request;

    public Number getChangeNumber() {
        return changeNumber;
    }

    public void setChangeNumber(Number changeNumber) {
        this.changeNumber = changeNumber;
    }

    public Object getChangeTime() {
        return changeTime;
    }

    public void setChangeTime(Object changeTime) {
        this.changeTime = changeTime;
    }

    public int getChangeAction() {
        return changeAction;
    }

    public void setChangeAction(int changeAction) {
        this.changeAction = changeAction;
    }

    public String getChangeUser() {
        return changeUser;
    }

    public void setChangeUser(String changeUser) {
        this.changeUser = changeUser;
    }

    public Request getRequest() {
        return request;
    }

    public void setRequest(Request request) {
        this.request = request;
    }

    public static Attributes parseAttributes(String changes) throws Exception {

        //boolean debug = log.isDebugEnabled();

        Attributes attributes = new Attributes();
        if (changes == null) return attributes;

        BufferedReader in = new BufferedReader(new StringReader(changes));

        String attributeName = null;
        boolean binary = false;

        StringBuilder sb = new StringBuilder();

        String line;
        while ((line = in.readLine()) != null) {

            //if (debug) log.debug("Parsing ["+line+"]");

            if (line.length() == 0) continue;

            if (line.startsWith(" ")) {
                sb.append(line.substring(1));
                continue;
            }

            if (attributeName != null) { // store previous value
                String s = sb.toString().trim();
                Object value = binary ? BinaryUtil.decode(BinaryUtil.BASE64, s) : s;
                attributes.addValue(attributeName, value);

                attributeName = null;
                sb = new StringBuilder();
            }

            int i = line.indexOf(":");
            if (i < 0) continue;
            
            attributeName = line.substring(0, i);

            i++;
            if (line.charAt(i) == ':') {
                binary = true;
                i++;

            } else {
                binary = false;
            }

            sb.append(line.substring(i));
        }

        if (attributeName != null) { // store remaining value
            String s = sb.toString().trim();
            Object value = binary ? BinaryUtil.decode(BinaryUtil.BASE64, s) : s;
            attributes.addValue(attributeName, value);
        }

        return attributes;
    }

    public static Collection<Modification> parseModifications(String changes) throws Exception {

        //boolean debug = log.isDebugEnabled();

        Collection<Modification> modifications = new ArrayList<Modification>();
        if (changes == null) return modifications;
        
        BufferedReader in = new BufferedReader(new StringReader(changes));

        Integer operation = null;
        String attributeName = null;
        boolean binary = false;

        StringBuilder sb = new StringBuilder();
        Attribute attribute = null;

        String line;
        while ((line = in.readLine()) != null) {

            //if (debug) log.debug("Parsing ["+line+"]");

            if (line.length() == 0) continue;

            if (line.startsWith(" ")) {
                sb.append(line.substring(1));
                continue;
            }

            if (line.equals("-")) { // store previous value, store attribute
                String s = sb.toString().trim();
                Object value = binary ? BinaryUtil.decode(BinaryUtil.BASE64, s) : s;

                attribute.addValue(value);

                Modification modification = new Modification(operation, attribute);
                modifications.add(modification);

                attributeName = null;
                sb = new StringBuilder();
                continue;
            }

            int i = line.indexOf(":");
            if (i < 0) continue;

            if (attributeName == null) { // get operation & attribute name
                operation = LDAP.getModificationOperation(line.substring(0, i));
                attributeName = line.substring(i+1).trim();

                attribute = new Attribute(attributeName);
                continue;

            }

            if (sb.length() > 0) { // store previous value
                String s = sb.toString().trim();
                Object value = binary ? BinaryUtil.decode(BinaryUtil.BASE64, s) : s;
                attribute.addValue(value);
                sb = new StringBuilder();
            }

            i++;
            if (line.charAt(i) == ':') {
                binary = true;
                i++;

            } else {
                binary = false;
            }

            sb.append(line.substring(i));
        }

        if (attributeName != null) { // store remaining value
            String s = sb.toString().trim();
            Object value = binary ? BinaryUtil.decode(BinaryUtil.BASE64, s) : s;

            attribute.addValue(value);

            Modification modification = new Modification(operation, attribute);
            modifications.add(modification);
        }

        return modifications;
    }
}
