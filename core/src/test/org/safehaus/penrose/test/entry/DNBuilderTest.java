package org.safehaus.penrose.test.entry;

import junit.framework.TestCase;
import org.safehaus.penrose.ldap.DN;
import org.safehaus.penrose.ldap.RDN;
import org.safehaus.penrose.ldap.DNBuilder;
import org.apache.log4j.Logger;

import java.util.Collection;
import java.util.Iterator;

/**
 * @author Endi S. Dewata
 */
public class DNBuilderTest extends TestCase {

    Logger log = Logger.getLogger(getClass());

    public void testParse() throws Exception {

        Collection rdns = DNBuilder.parse("cn=John Smith,ou=Users,dc=Example,dc=com");
        assertEquals(4, rdns.size());

        Iterator i = rdns.iterator();

        RDN rdn = (RDN)i.next();
        assertEquals("cn=John Smith", rdn.toString());

        rdn = (RDN)i.next();
        assertEquals("ou=Users", rdn.toString());

        rdn = (RDN)i.next();
        assertEquals("dc=Example", rdn.toString());

        rdn = (RDN)i.next();
        assertEquals("dc=com", rdn.toString());
    }

    public void testParseSpecial() throws Exception {

        Collection rdns = DNBuilder.parse("cn=Smith\\, John,ou=Users,dc=Example,dc=com");
        assertEquals(4, rdns.size());

        Iterator i = rdns.iterator();

        RDN rdn = (RDN)i.next();
        assertEquals("cn=Smith\\, John", rdn.toString());

        rdn = (RDN)i.next();
        assertEquals("ou=Users", rdn.toString());

        rdn = (RDN)i.next();
        assertEquals("dc=Example", rdn.toString());

        rdn = (RDN)i.next();
        assertEquals("dc=com", rdn.toString());
    }

    public void testSet() throws Exception {

        DN dn = new DN("cn=John Smith,ou=Users,dc=Example,dc=com");

        DNBuilder db = new DNBuilder();
        db.set("cn=John Smith,ou=Users,dc=Example,dc=com");

        DN dn2 = db.toDn();

        assertEquals(dn, dn2);
    }

    public void testSize() throws Exception {

        DNBuilder db = new DNBuilder();
        db.set("cn=John Smith,ou=Users,dc=Example,dc=com");

        assertEquals(4, db.getSize());
    }

    public void testEmpty() {

        DNBuilder db = new DNBuilder();

        assertTrue(db.isEmpty());
    }

    public void testAppend() throws Exception {

        DN dn = new DN("cn=John Smith,ou=Users,dc=Example,dc=com");

        DNBuilder db = new DNBuilder();
        db.append("cn=John Smith");
        db.append("ou=Users");
        db.append("dc=Example");
        db.append("dc=com");

        assertEquals(dn, db.toDn());
    }

    public void testPrepend() throws Exception {

        DN dn = new DN("cn=John Smith,ou=Users,dc=Example,dc=com");

        DNBuilder db = new DNBuilder();
        db.prepend("dc=com");
        db.prepend("dc=Example");
        db.prepend("ou=Users");
        db.prepend("cn=John Smith");

        assertEquals(dn, db.toDn());
    }
}
