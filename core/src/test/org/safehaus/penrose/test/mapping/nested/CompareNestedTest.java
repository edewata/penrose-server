package org.safehaus.penrose.test.mapping.nested;

import org.safehaus.penrose.session.Session;

/**
 * @author Endi S. Dewata
 */
public class CompareNestedTest extends NestedTestCase {

    public CompareNestedTest() throws Exception {
    }

    public void testComparingEntry() throws Exception {

        executeUpdate("insert into groups values ('group', 'description')");
        executeUpdate("insert into members values ('member', 'group', 'Member')");

        Session session = penrose.createSession();
        session.bind(penroseConfig.getRootDn(), penroseConfig.getRootPassword());

        boolean result = session.compare("cn=group,"+baseDn, "description", "description");
        assertTrue(result);

        result = session.compare("uid=member,cn=group,"+baseDn, "memberOf", "group");
        assertTrue(result);

        result = session.compare("uid=member,cn=group,"+baseDn, "cn", "Member");
        assertTrue(result);

        session.close();
    }
}
