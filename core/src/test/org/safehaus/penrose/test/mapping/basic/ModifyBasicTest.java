package org.safehaus.penrose.test.mapping.basic;

import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.ldap.Modification;
import org.safehaus.penrose.ldap.Attribute;

import java.util.Collection;
import java.util.ArrayList;
import java.util.Map;

/**
 * @author Endi S. Dewata
 */
public class ModifyBasicTest extends BasicTestCase {

    public ModifyBasicTest() throws Exception {
    }

    public void testModifyingEntry() throws Exception {

        executeUpdate("insert into groups values ('group', 'olddesc')");

        Session session = penrose.createSession();
        session.bind(penroseConfig.getRootDn(), penroseConfig.getRootPassword());

        Attribute attribute = new Attribute("description");
        attribute.addValue("newdesc");

        Modification mi = new Modification(Modification.REPLACE, attribute);
        Collection<Modification> modifications = new ArrayList<Modification>();
        modifications.add(mi);

        session.modify("cn=group,"+baseDn, modifications);

        session.close();

        Collection results = executeQuery("select * from groups");
        assertEquals(results.size(), 1);

        Map row = (Map)results.iterator().next();
        assertEquals("group", row.get("GROUPNAME"));
        assertEquals("newdesc", row.get("DESCRIPTION"));
    }
}
