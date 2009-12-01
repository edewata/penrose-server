package org.safehaus.penrose.ad;

import java.util.Collection;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * @author Endi S. Dewata
 */
public class SupplementalCredentials {
    
    public int size;
    public String charset;
    public int signature;
    public Collection<SupplementalCredentialsPackage> packages = new ArrayList<SupplementalCredentialsPackage>();

    public int getSize() {
        return size;
    }

    public void setSize(int size) {
        this.size = size;
    }

    public String getCharset() {
        return charset;
    }

    public void setCharset(String charset) {
        this.charset = charset;
    }

    public int getSignature() {
        return signature;
    }

    public void setSignature(int signature) {
        this.signature = signature;
    }

    public SupplementalCredentialsPackage[] getPackages() {
        return packages.toArray(new SupplementalCredentialsPackage[packages.size()]);
    }

    public void addPackage(SupplementalCredentialsPackage scPackage) {
        this.packages.add(scPackage);
    }

    public SupplementalCredentialsPackage getPackage(String name) {
        for (SupplementalCredentialsPackage scPackage : packages) {
            if (scPackage.getName().equals(name)) return scPackage;
        }
        return null;
    }

    public void setPackages(SupplementalCredentialsPackage[] packages) {
        this.packages.clear();
        this.packages.addAll(Arrays.asList(packages));
    }
}
