package org.safehaus.penrose.test.mapping.nested2;

import org.apache.log4j.Logger;
import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.ldap.SearchRequest;
import org.safehaus.penrose.ldap.SearchResponse;
import org.safehaus.penrose.ldap.SearchResult;
import org.safehaus.penrose.ldap.Attributes;

/**
 * @author Endi S. Dewata
 */
public class SearchOneLevelTest extends NestedTestCase {

    Logger log = Logger.getLogger(getClass());

    public SearchOneLevelTest() throws Exception {
    }

    public void testSearchingOneLevelOnParent() throws Exception {

        executeUpdate("insert into parents values ('parent1', 'description1')");
        executeUpdate("insert into parents values ('parent2', 'description2')");
        executeUpdate("insert into parents values ('parent3', 'description3')");

        executeUpdate("insert into children values ('parent1', 'child1')");
        executeUpdate("insert into children values ('parent2', 'child2')");

        Session session = penrose.createSession();
        session.bind(penroseConfig.getRootDn(), penroseConfig.getRootPassword());

        SearchResponse response = session.search(
                "cn=parent1,"+baseDn,
                "(objectClass=*)",
                SearchRequest.SCOPE_ONE
        );

        boolean hasNext = response.hasNext();
        log.debug("hasNext: "+hasNext);
        assertTrue(hasNext);

        SearchResult searchResult = (SearchResult) response.next();
        String dn = searchResult.getDn().toString();
        log.debug("DN: "+dn);
        assertEquals("uid=child,cn=parent1,"+baseDn, dn);

        Attributes attributes = searchResult.getAttributes();

        Object value = (String)attributes.getValue("uid");
        log.debug("uid: "+ value);
        assertEquals("child", value);

        value = attributes.getValue("description");
        log.debug("description: "+value);
        assertEquals("child1", value);

        hasNext = response.hasNext();
        log.debug("hasNext: "+hasNext);
        assertFalse(hasNext);

        long totalCount = response.getTotalCount();
        log.debug("totalCount: "+totalCount);
        assertEquals(1, totalCount);

        session.close();
    }

    public void testSearchingOneLevelOnParentWithNoChild() throws Exception {

        executeUpdate("insert into parents values ('parent1', 'description1')");
        executeUpdate("insert into parents values ('parent2', 'description2')");
        executeUpdate("insert into parents values ('parent3', 'description3')");

        executeUpdate("insert into children values ('parent1', 'child1')");
        executeUpdate("insert into children values ('parent2', 'child2')");

        Session session = penrose.createSession();
        session.bind(penroseConfig.getRootDn(), penroseConfig.getRootPassword());

        SearchResponse response = session.search(
                "cn=parent3,"+baseDn,
                "(objectClass=*)",
                SearchRequest.SCOPE_ONE
        );

        boolean hasNext = response.hasNext();
        log.debug("hasNext: "+hasNext);
        assertFalse(hasNext);

        long totalCount = response.getTotalCount();
        log.debug("totalCount: "+totalCount);
        assertEquals(0, totalCount);

        session.close();
    }
}
