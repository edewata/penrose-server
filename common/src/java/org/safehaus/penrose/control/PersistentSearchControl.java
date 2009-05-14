package org.safehaus.penrose.control;

import com.novell.ldap.asn1.*;

/**
 * @author Endi Sukma Dewata
 */
public class PersistentSearchControl extends Control {

    public final static String OID = "2.16.840.1.113730.3.4.3";

    public final static int CHANGE_TYPE_ADD    = 1;
    public final static int CHANGE_TYPE_DELETE = 2;
    public final static int CHANGE_TYPE_MODIFY = 4;
    public final static int CHANGE_TYPE_MODDN  = 8;

    public int     changeTypes;
    public boolean changesOnly;
    public boolean returnECs;

    public PersistentSearchControl(
            int changeTypes,
            boolean changesOnly,
            boolean returnECs
    ) throws Exception {

        super(OID, null, true);

        this.changeTypes = changeTypes;
        this.changesOnly = changesOnly;
        this.returnECs   = returnECs;

        encodeValue();
    }

    public void encodeValue() throws Exception {

        ASN1Sequence sequence = new ASN1Sequence();

        sequence.add(new ASN1Integer(changeTypes));
        sequence.add(new ASN1Boolean(changesOnly));
        sequence.add(new ASN1Boolean(returnECs));

        LBEREncoder encoder = new LBEREncoder();
        value = sequence.getEncoding(encoder);
    }
}
