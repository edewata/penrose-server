package org.safehaus.penrose.samba;

import org.safehaus.penrose.ad.*;

import java.io.StringWriter;
import java.io.PrintWriter;

/**
 * @author Endi S. Dewata
 */
public class Samba {

    public static byte[] toBinaryGUID(String nsUniqueId) {

        if (nsUniqueId == null) return null;

        // %08x-%04x%04x-%02x%02x%02x%02x-%02x%02x%02x%02x
        //System.out.println("nsUniqueId: "+nsUniqueId);

        GUID guid = new GUID();

        String timeLow = nsUniqueId.substring(0, 8);
        guid.setTimeLow(Long.parseLong(timeLow, 16));
        //System.out.printf("timeLow: %08x\n", guid.getTimeLow());

        String timeMid = nsUniqueId.substring(9, 13);
        guid.setTimeMid(Integer.parseInt(timeMid, 16));
        //System.out.printf("timeMid: %04x\n", guid.getTimeMid());

        String timeHiAndVersion = nsUniqueId.substring(13, 17);
        guid.setTimeHiAndVersion(Integer.parseInt(timeHiAndVersion, 16));
        //System.out.printf("timeHiAndVersion: %04x\n", guid.getTimeHiAndVersion());

        byte[] clockSeq = guid.getClockSeq();
        String clockSeq0 = nsUniqueId.substring(18, 20);
        clockSeq[0] = (byte)(Integer.parseInt(clockSeq0, 16) & 0xff);

        String clockSeq1 = nsUniqueId.substring(20, 22);
        clockSeq[1] = (byte)(Integer.parseInt(clockSeq1, 16) & 0xff);

        //System.out.printf("node: ");
        //for (int i=0; i<clockSeq.length; i++) {
        //    System.out.printf("%02x", clockSeq[i]);
        //}
        //System.out.printf("\n");

        byte[] node = guid.getNode();
        String node0 = nsUniqueId.substring(22, 24);
        node[0] = (byte)(Integer.parseInt(node0, 16) & 0xff);

        String node1 = nsUniqueId.substring(24, 26);
        node[1] = (byte)(Integer.parseInt(node1, 16) & 0xff);

        String node2 = nsUniqueId.substring(27, 29);
        node[2] = (byte)(Integer.parseInt(node2, 16) & 0xff);

        String node3 = nsUniqueId.substring(29, 31);
        node[3] = (byte)(Integer.parseInt(node3, 16) & 0xff);

        String node4 = nsUniqueId.substring(31, 33);
        node[4] = (byte)(Integer.parseInt(node4, 16) & 0xff);

        String node5 = nsUniqueId.substring(33, 35);
        node[5] = (byte)(Integer.parseInt(node5, 16) & 0xff);

        //System.out.printf("node: ");
        //for (int i=0; i<node.length; i++) {
        //    System.out.printf("%02x", node[i]);
        //}
        //System.out.printf("\n");

        return guid.getBytes();
    }

    public static String toStringGUID(byte[] bytes) throws Exception {

        if (bytes == null) return null;
        
        StringWriter sw = new StringWriter();
        PrintWriter out = new PrintWriter(sw);

        out.printf(
                "%02x%02x%02x%02x-%02x%02x%02x%02x-%02x%02x%02x%02x-%02x%02x%02x%02x",
                bytes[3], bytes[2], bytes[1], bytes[0],
                bytes[5], bytes[4], bytes[7], bytes[6],
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15]
        );

        return sw.toString();
    }

    public static String getClearTextPassword(byte[] bytes) throws Exception {

        if (bytes == null) return null;

        SupplementalCredentialsUtil scUtil = new SupplementalCredentialsUtil();
        SupplementalCredentials sc = new SupplementalCredentials();
        scUtil.decode(sc, bytes);

        SupplementalCredentialsPackage scPackage = sc.getPackage("Primary:CLEARTEXT");
        if (scPackage == null) return null;

        return new String(scPackage.data, "UTF-16LE");
    }
}
