package org.safehaus.penrose.ad;

import jcifs.util.Encdec;
import org.safehaus.penrose.util.BinaryUtil;

/**
 * @author Endi S. Dewata
 */
public class SupplementalCredentialsUtil {

    public int align(int offset, int size) {
        if (size == 5) {
            size = 4;
        } else if (size == 3) {
            size = 2;
        }

        return (offset + (size-1)) & ~(size-1);
    }

    public int decode(SupplementalCredentials sc, byte buffer[]) throws Exception {
        return decode(sc, buffer, 0);
    }

    public int decode(SupplementalCredentials sc, byte buffer[], int offset) throws Exception {

        offset = align(offset, 4);

        int unknown1 = Encdec.dec_uint32le(buffer, offset);
        System.out.printf("[%04X] Unknown1: %d\n", offset, unknown1);
        offset +=4;

        sc.size = Encdec.dec_uint32le(buffer, offset);
        System.out.printf("[%04X] Size: %04X\n", offset, sc.size);
        offset +=4;

        System.out.printf("[%04X] Unknown2: ", offset);
        int unknown2 = Encdec.dec_uint32le(buffer, offset);
        System.out.printf("%d\n", unknown2);
        offset +=4;

        offset = align(offset, 3);

        sc.charset = new String(buffer, offset, 0x60, "UTF-16LE");
        System.out.printf("[%04X] Charset: [%s]\n", offset, sc.charset);
        offset += 0x60;

        sc.signature = Encdec.dec_uint16le(buffer, offset);
        System.out.printf("[%04X] Signature: %d\n", offset, sc.signature);
        offset +=2;

        int packages = Encdec.dec_uint16le(buffer, offset);
        System.out.printf("[%04X] Packages: %d\n", offset, packages);
        offset +=2;

        for (int i=0; i<packages; i++) {
            SupplementalCredentialsPackage scp = new SupplementalCredentialsPackage();
            offset = decode(scp, buffer, offset);
            sc.addPackage(scp);
        }

        offset = align(offset, 3);

        int unknown3 = buffer[offset];
        System.out.printf("[%04X] Unknown3: %d\n", offset, unknown3);
        offset +=1;

        offset = align(offset, 4);

        return offset;
    }

    public int decode(SupplementalCredentialsPackage scp, byte buffer[], int offset) throws Exception {

        offset = align(offset, 2);

        System.out.printf("[%04X] Name length: ", offset);
        int nameLength = Encdec.dec_uint16le(buffer, offset);
        System.out.printf("%04X\n", nameLength);
        offset +=2;

        System.out.printf("[%04X] Data length: ", offset);
        int dataLength = Encdec.dec_uint16le(buffer, offset);
        System.out.printf("%04X\n", dataLength);
        offset +=2;

        System.out.printf("[%04X] Reserved: ", offset);
        int reserved = Encdec.dec_uint16le(buffer, offset);
        System.out.printf("%d\n", reserved);
        offset +=2;

        scp.name = new String(buffer, offset, nameLength, "UTF-16LE");
        System.out.printf("[%04X] Name: %s\n", offset, scp.name);
        offset += nameLength;

        String data = new String(buffer, offset, dataLength);
        scp.data = BinaryUtil.decode(BinaryUtil.BIG_INTEGER, data);
        System.out.printf("[%04X] Data: %s\n", offset, data);
        offset += dataLength;

        offset = align(offset, 2);

        return offset;
    }
}
