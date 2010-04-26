package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.ldap.DN;
import org.safehaus.penrose.ldap.Modification;
import org.safehaus.penrose.ldap.Attribute;

import java.util.Collection;

/**
 * @author Endi S. Dewata
 */
public class IPASambaUserSyncModule extends UserSyncModule {

    public void modifyEntry(Session session, DN sourceDn, Collection<Modification> modifications) throws Exception {

        DN modifiersName = null;

        for (Modification modification : modifications) {
            Attribute attribute = modification.getAttribute();
            String attributeName = attribute.getName();

            if ("modifiersName".equalsIgnoreCase(attributeName)) {
                modifiersName = new DN(attribute.getValue().toString());
            }
        }

        log.debug("Modifiers name: "+modifiersName);

        if (modifiersName != null && modifiersName.matches("cn=ipa-memberof,cn=plugins,cn=config")) {
            log.debug("Skipping changes by ipa-memberof plugin.");
            return;
        }

        super.modifyEntry(session, sourceDn, modifications);
    }
}
