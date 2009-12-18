/**
 * Copyright 2009 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package org.safehaus.penrose.ad;

import org.apache.log4j.Level;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.xml.DOMConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import gnu.getopt.LongOpt;
import gnu.getopt.Getopt;

import java.util.*;
import java.io.File;
import java.io.FileInputStream;

/**
 * @author Endi S. Dewata
 */
public class ActiveDirectory {

    public static Logger log = LoggerFactory.getLogger(ActiveDirectory.class);

    public static final long MIN_TIMESTAMP; // 1601-01-01T00:00:00Z
    public static final long MAX_TIMESTAMP = 9223372036854775807l;

    static {
        Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal.clear();
        cal.set(1601, 0, 1, 0, 0);
        MIN_TIMESTAMP = cal.getTime().getTime();
    }

    public static Date toDate(String timestamp) {
        return toDate(Long.parseLong(timestamp));
    }
    
    public static Date toDate(long timestamp) {
        return new Date(MIN_TIMESTAMP + (timestamp/10000));
    }

    public static long toTimestamp(Date date) {
        if (date == null) return MIN_TIMESTAMP * 10000;
        return (date.getTime() - MIN_TIMESTAMP) * 10000;
    }

    public static byte[] toUnicodePassword(Object password) throws Exception {
        String newPassword;
        if (password instanceof byte[]) {
            newPassword = "\""+new String((byte[])password)+ "\"";
        } else {
            newPassword = "\""+password+ "\"";
        }

        return newPassword.getBytes("UTF-16LE");
/*
        byte unicodeBytes[] = newPassword.getBytes("Unicode");
        byte bytes[]  = new byte[unicodeBytes.length-2];

        System.arraycopy(unicodeBytes, 2, bytes, 0, unicodeBytes.length-2);

        return bytes;
*/
    }

    public static String toStringGUID(byte[] guid) {
        StringBuilder sb = new StringBuilder();

        sb.append(byte2hex(guid[3]));
        sb.append(byte2hex(guid[2]));
        sb.append(byte2hex(guid[1]));
        sb.append(byte2hex(guid[0]));
        sb.append("-");
        sb.append(byte2hex(guid[5]));
        sb.append(byte2hex(guid[4]));
        sb.append("-");
        sb.append(byte2hex(guid[7]));
        sb.append(byte2hex(guid[6]));
        sb.append("-");
        sb.append(byte2hex(guid[8]));
        sb.append(byte2hex(guid[9]));
        sb.append("-");
        sb.append(byte2hex(guid[10]));
        sb.append(byte2hex(guid[11]));
        sb.append(byte2hex(guid[12]));
        sb.append(byte2hex(guid[13]));
        sb.append(byte2hex(guid[14]));
        sb.append(byte2hex(guid[15]));

        return sb.toString();
    }

    /**
     * http://msdn.microsoft.com/en-us/library/cc230371(PROT.10).aspx
     * 
     * @param sid byte array of SID
     * @return string representation of SID
     */
    public static String toStringSID(byte[] sid) {

        boolean debug = log.isDebugEnabled();

        StringBuilder sb = new StringBuilder();
        sb.append("S-");

         // revision
        int revision = sid[0];
        if (debug) log.debug("SID[0] revision: "+ revision);

        sb.append(revision);
        sb.append("-");

        // sub-authority subAuthorityCount
        int subAuthorityCount = sid[1]&0xFF;
        if (debug) log.debug("SID[1] sub-authority count: "+ subAuthorityCount);

        // get authority
        StringBuilder sb2 = new StringBuilder();
        for (int i=2; i<=7; i++) {
            sb2.append(byte2hex(sid[i]));
        }
        String identifierAuthority = sb2.toString();
        if (debug) log.debug("SID[2-7] identifier authority: "+identifierAuthority);

        sb.append(Long.parseLong(identifierAuthority, 16));

        //iterate all the sub-auths
        for (int i=0; i<subAuthorityCount; i++) {

            int start = i*4 + 8;
            int end = i*4 + 11;
            if (debug) log.debug("SID["+start+"-"+end+"] sub-authority #"+i+":");

            StringBuilder tmp2 = new StringBuilder();
            for (int j=end; j>=start; j--) {
                tmp2.append(byte2hex(sid[j]));
            }

            String subauthority = tmp2.toString();
            if (debug) log.debug("SID["+start+"-"+end+"] sub-authority #"+i+": "+subauthority);

            sb.append("-");
            sb.append(Long.parseLong(subauthority, 16));
        }

        return sb.toString();
    }

    public static String byte2hex(byte b) {
        int i = (int)b & 0xFF;
        return (i <= 0x0F) ? "0" + Integer.toHexString(i) : Integer.toHexString(i);
    }

    public static void executeShowGUIDCommand(String fileName) throws Exception {
        File file = new File(fileName);
        FileInputStream in = new FileInputStream(fileName);

        byte[] buffer = new byte[(int)file.length()];

        if (in.read(buffer) == -1) {
            throw new Exception("Error reading "+fileName+".");
        }

        in.close();

        String guid = toStringGUID(buffer);
        System.out.println(guid);
    }

    public static void executeShowSidCommand(String fileName) throws Exception {
        File file = new File(fileName);
        FileInputStream in = new FileInputStream(fileName);

        byte[] buffer = new byte[(int)file.length()];

        if (in.read(buffer) == -1) {
            throw new Exception("Error reading "+fileName+".");
        }

        in.close();

        String sid = toStringSID(buffer);
        System.out.println(sid);
    }

    public static void executeShowCommand(Iterator<String> iterator) throws Exception {
        String target = iterator.next();
        if ("guid".equals(target)) {
            String fileName = iterator.next();
            executeShowGUIDCommand(fileName);

        } else if ("sid".equals(target)) {
            String fileName = iterator.next();
            executeShowSidCommand(fileName);

        } else {
            System.out.println("Invalid type: "+target);
        }
    }

    public static void executeCommand(Collection<String> parameters) throws Exception {

        Iterator<String> iterator = parameters.iterator();
        String command = iterator.next();
        //System.out.println("Executing "+command);

        if ("show".equals(command)) {
            executeShowCommand(iterator);

        } else {
            System.out.println("Invalid command: "+command);
        }
    }

    public static void showUsage() {
        System.out.println("Usage: org.safehaus.penrose.ad.ActiveDirectory [OPTION]... <COMMAND>");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -?, --help         display this help and exit");
        System.out.println("  -d                 run in debug mode");
        System.out.println("  -v                 run in verbose mode");
        System.out.println();
        System.out.println("Commands:");
        System.out.println();
        System.out.println("  show sid <file name>");
    }

    public static void main(String args[]) {

        Level level          = Level.WARN;

        LongOpt[] longopts = new LongOpt[1];
        longopts[0] = new LongOpt("help", LongOpt.NO_ARGUMENT, null, '?');

        Getopt getopt = new Getopt("ActiveDirectory", args, "-:?dvt:h:p:r:P:D:w:", longopts);

        Collection<String> parameters = new ArrayList<String>();
        int c;
        while ((c = getopt.getopt()) != -1) {
            switch (c) {
                case ':':
                case '?':
                    showUsage();
                    System.exit(0);
                    break;
                case 1:
                    parameters.add(getopt.getOptarg());
                    break;
                case 'd':
                    level = Level.DEBUG;
                    break;
                case 'v':
                    level = Level.INFO;
                    break;
            }
        }

        if (parameters.size() == 0) {
            showUsage();
            System.exit(0);
        }

        org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger("org.safehaus.penrose");

        File log4jXml = new File("conf"+File.separator+"log4j.xml");

        if (level.equals(Level.DEBUG)) {
            logger.setLevel(level);
            ConsoleAppender appender = new ConsoleAppender(new PatternLayout("%-20C{1} [%4L] %m%n"));
            BasicConfigurator.configure(appender);

        } else if (level.equals(Level.INFO)) {
            logger.setLevel(level);
            ConsoleAppender appender = new ConsoleAppender(new PatternLayout("[%d{MM/dd/yyyy HH:mm:ss}] %m%n"));
            BasicConfigurator.configure(appender);

        } else if (log4jXml.exists()) {
            DOMConfigurator.configure(log4jXml.getAbsolutePath());

        } else {
            logger.setLevel(level);
            ConsoleAppender appender = new ConsoleAppender(new PatternLayout("[%d{MM/dd/yyyy HH:mm:ss}] %m%n"));
            BasicConfigurator.configure(appender);
        }

        try {
            executeCommand(parameters);

        } catch (SecurityException e) {
            log.error(e.getMessage());

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }
}
