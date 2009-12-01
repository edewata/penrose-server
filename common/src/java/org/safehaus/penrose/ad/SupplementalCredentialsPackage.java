package org.safehaus.penrose.ad;

/**
 * @author Endi S. Dewata
 */
public class SupplementalCredentialsPackage {

    public String name;
    public byte[] data;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }
}
