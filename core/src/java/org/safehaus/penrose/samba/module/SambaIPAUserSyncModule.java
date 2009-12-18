package org.safehaus.penrose.samba.module;

import org.safehaus.penrose.ipa.module.UserSyncModule;
import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.session.Session;
import org.ietf.ldap.LDAPException;

/**
 * @author Endi S. Dewata
 */
public class SambaIPAUserSyncModule extends UserSyncModule {

    public SearchResult addUser(Session session, DN sourceDn, Attributes sourceAttributes) throws Exception {

        SearchResult sourceEntry = super.addUser(session, sourceDn, sourceAttributes);

        ModifyRequest request = new ModifyRequest();
        request.setDn(new DN("cn=ipausers,cn=groups,cn=accounts").append(targetFE.getBaseDn()));

        request.addModification(new Modification(
                Modification.ADD,
                new Attribute("member", sourceEntry.getDn().toString())
        ));

        ModifyResponse response = new ModifyResponse();

        try {
            targetFE.modify(session, request, response);
        } catch (LDAPException e) {
            if (e.getResultCode() == LDAPException.ATTRIBUTE_OR_VALUE_EXISTS) {
                log.debug(e.getMessage());
            } else {
                throw e;
            }
        }

        return sourceEntry;
    }

    public void deleteUser(Session session, SearchResult sourceEntry) throws Exception {

        ModifyRequest request = new ModifyRequest();
        request.setDn(new DN("cn=ipausers,cn=groups,cn=accounts").append(targetFE.getBaseDn()));

        request.addModification(new Modification(
                Modification.DELETE,
                new Attribute("member", sourceEntry.getDn().toString())
        ));

        ModifyResponse response = new ModifyResponse();

        try {
            targetFE.modify(session, request, response);
        } catch (LDAPException e) {
            if (e.getResultCode() == LDAPException.NO_SUCH_ATTRIBUTE) {
                log.debug(e.getMessage());
            } else {
                throw e;
            }
        }

        super.deleteUser(session, sourceEntry);
    }
}
