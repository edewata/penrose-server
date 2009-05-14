package org.safehaus.penrose.control;

import com.novell.ldap.asn1.*;
import org.safehaus.penrose.ldap.DN;

/**
 * @author Endi Sukma Dewata
 */
public class EntryChangeNotificationControl extends Control {

    public final static String OID = "2.16.840.1.113730.3.4.7";

    public final static int CHANGE_TYPE_ADD    = 1;
    public final static int CHANGE_TYPE_DELETE = 2;
    public final static int CHANGE_TYPE_MODIFY = 4;
    public final static int CHANGE_TYPE_MODDN  = 8;

    private int changeType;
    private DN  previousDn;
    private int changeNumber;

    public EntryChangeNotificationControl(String oid, byte[] value, boolean critical) throws Exception {
        super(oid, value, critical);

        decodeValue();
    }

    public void decodeValue() throws Exception {

        LBERDecoder decoder = new LBERDecoder();

        ASN1Sequence sequence = (ASN1Sequence)decoder.decode(value);
        int size = sequence.size();

        ASN1Enumerated changeType = (ASN1Enumerated)sequence.get(0);
        this.changeType = changeType.intValue();

        if (size > 1) {
            ASN1Object previousDn = sequence.get(1);
            this.previousDn = null;
        }

        if (size > 2) {
            ASN1Integer changeNumber = (ASN1Integer)sequence.get(2);
            this.changeNumber = changeNumber.intValue();
        }
    }

    public int getChangeType() {
        return changeType;
    }

    public void setChangeType(int changeType) {
        this.changeType = changeType;
    }

    public DN getPreviousDn() {
        return previousDn;
    }

    public void setPreviousDn(DN previousDn) {
        this.previousDn = previousDn;
    }

    public int getChangeNumber() {
        return changeNumber;
    }

    public void setChangeNumber(int changeNumber) {
        this.changeNumber = changeNumber;
    }
}
