package org.safehaus.penrose.test.mapping.basic;

import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.ldap.SearchResponse;
import org.safehaus.penrose.ldap.SearchResult;
import org.safehaus.penrose.ldap.Attributes;
import org.safehaus.penrose.ldap.LDAP;
import org.safehaus.penrose.Penrose;
import org.ietf.ldap.LDAPException;

import java.util.Collection;
import java.util.ArrayList;

/**
 * @author Endi S. Dewata
 */
public class SearchSubtreeTest extends BasicTestCase {

    public SearchSubtreeTest() throws Exception {
    }

    public void testSearchingBase() throws Exception {

        String groupnames[] = new String[] { "abc", "def", "ghi" };
        String descriptions[] = new String[] { "ABC", "DEF", "GHI" };
        for (int i=0; i<groupnames.length; i++) {
            Collection params = new ArrayList();
            params.add(groupnames[i]);
            params.add(descriptions[i]);
            executeUpdate("insert into groups values (?, ?)", params);
        }

        Session session = penrose.createSession();
        session.bind(penroseConfig.getRootDn(), penroseConfig.getRootPassword());

        SearchResponse response = session.search("cn=def,"+baseDn, "(objectClass=*)");

        boolean hasNext = response.hasNext();
        log.debug("hasNext: "+hasNext);
        assertTrue(hasNext);

        SearchResult searchResult = (SearchResult) response.next();
        String dn = searchResult.getDn().toString();
        log.debug("dn: "+dn);
        assertEquals("cn=def,"+baseDn, dn);

        Attributes attributes = searchResult.getAttributes();

        Object value = attributes.getValue("cn");
        log.debug("cn: "+value);
        assertEquals("def", value);

        value = attributes.getValue("description");
        log.debug("description: "+value);
        assertEquals("DEF", value);

        hasNext = response.hasNext();
        log.debug("hasNext: "+hasNext);
        assertFalse(hasNext);

        session.close();
    }

    public void testSearchingNonExistentBase() throws Exception {

        String groupnames[] = new String[] { "abc", "def", "ghi" };
        String descriptions[] = new String[] { "ABC", "DEF", "GHI" };
        for (int i=0; i<groupnames.length; i++) {
            Collection params = new ArrayList();
            params.add(groupnames[i]);
            params.add(descriptions[i]);
            executeUpdate("insert into groups values (?, ?)", params);
        }

        Session session = penrose.createSession();
        session.bind(penroseConfig.getRootDn(), penroseConfig.getRootPassword());

        SearchResponse response = session.search("cn=jkl,"+baseDn, "(objectClass=*)");

        try {
            boolean hasNext = response.hasNext();
            log.debug("hasNext: "+hasNext);
            fail();
        } catch (LDAPException e) {
            Penrose.errorLog.error(e.getMessage(), e);
            assertEquals(LDAP.NO_SUCH_OBJECT, e.getResultCode());
        }

        session.close();
    }
}
