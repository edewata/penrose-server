package org.safehaus.penrose.ipa;

import org.safehaus.penrose.ad.ActiveDirectory;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.security.MessageDigest;

/**
 * @author Endi Sukma Dewata
 */
public class IPA {

    public static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");

    public static Date toDate(String date) throws Exception {
        if (date == null) return null;

        if (date.endsWith("Z") || date.endsWith("z")) date = date.substring(0, date.length()-1);
        return dateFormat.parse(date);
    }

    public static String toTimestamp(Date date) {
        return dateFormat.format(date)+'Z';
    }

    public static String generateIPAUniqueId(byte[] guid) throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(guid);
        byte[] digest = md.digest();

        return ActiveDirectory.toStringGUID(digest);
    }
}
