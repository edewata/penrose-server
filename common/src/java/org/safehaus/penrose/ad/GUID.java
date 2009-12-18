package org.safehaus.penrose.ad;

/**
 * @author Endi S. Dewata
 */
public class GUID {

    long timeLow;
    int timeMid;
    int timeHiAndVersion;
    byte[] clockSeq = new byte[2];
    byte[] node = new byte[6];

    public GUID() {
    }

    public long getTimeLow() {
        return timeLow;
    }

    public void setTimeLow(long timeLow) {
        this.timeLow = timeLow;
    }

    public int getTimeMid() {
        return timeMid;
    }

    public void setTimeMid(int timeMid) {
        this.timeMid = timeMid;
    }

    public int getTimeHiAndVersion() {
        return timeHiAndVersion;
    }

    public void setTimeHiAndVersion(int timeHiAndVersion) {
        this.timeHiAndVersion = timeHiAndVersion;
    }

    public byte[] getClockSeq() {
        return clockSeq;
    }

    public byte[] getNode() {
        return node;
    }

    public byte[] getBytes() {
        byte[] b = new byte[16];

        b[0] = (byte)(timeLow & 0xff);
        b[1] = (byte)((timeLow & 0xff00) >> 8);
        b[2] = (byte)((timeLow & 0xff0000) >> 16);
        b[3] = (byte)((timeLow & 0xff000000) >> 24);

        b[4] = (byte)(timeMid & 0xff);
        b[5] = (byte)((timeMid & 0xff00) >> 8);

        b[6] = (byte)(timeHiAndVersion & 0xff);
        b[7] = (byte)((timeHiAndVersion & 0xff00) >> 8);

        System.arraycopy(clockSeq, 0, b, 8, clockSeq.length);
        System.arraycopy(node, 0, b, 10, node.length);

        //for (int i=0; i<b.length; i++) {
        //    System.out.printf("bytes[%d]: %02x\n", i, b[i]);
        //}

        return b;
    }
}
