/**
 * Copyright (c) 2000-2005, Identyx Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package org.safehaus.penrose.ldap;

import org.apache.directory.server.core.authn.AbstractAuthenticator;
import org.apache.directory.server.core.authn.LdapPrincipal;
import org.apache.directory.server.core.jndi.ServerContext;
import org.apache.directory.shared.ldap.exception.LdapAuthenticationException;
import org.apache.directory.shared.ldap.aci.AuthenticationLevel;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.ietf.ldap.LDAPException;
import org.safehaus.penrose.Penrose;
import org.safehaus.penrose.session.PenroseSession;
import org.safehaus.penrose.config.PenroseConfig;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;

/**
 * @author Endi S. Dewata
 */
public class PenroseAuthenticator extends AbstractAuthenticator {

    Logger log = LoggerFactory.getLogger(getClass());

    Penrose penrose;

    public PenroseAuthenticator()
    {
        super("simple");
    }

    public void init() throws NamingException {
    }

    public void setPenrose(Penrose penrose) throws Exception {
        this.penrose = penrose;
    }

    public LdapPrincipal authenticate(LdapDN dn, ServerContext ctx) throws NamingException {

        Object credentials = ctx.getEnvironment().get(Context.SECURITY_CREDENTIALS);
        String password = new String((byte[])credentials);

        PenroseConfig penroseConfig = penrose.getPenroseConfig();
        String rootDn = penroseConfig.getRootUserConfig().getDn();
        String rootPassword = penroseConfig.getRootUserConfig().getPassword();

        //log.info("Login "+dn);

        if (rootDn != null &&
                rootPassword != null &&
                rootDn.equals(dn)) {

            throw new LdapAuthenticationException();
        }

        try {
            PenroseSession session = penrose.getSession(dn.getUpName());

            if (session == null) {
                session = penrose.createSession(dn.getUpName());
                if (session == null) throw new ServiceUnavailableException();
            }

            int rc = session.bind(dn.getUpName(), password);

            if (rc != LDAPException.SUCCESS) {
                throw ExceptionTool.createNamingException(rc);
            }

            log.warn("Bind operation succeeded.");

            return createLdapPrincipal(dn.getUpName(), AuthenticationLevel.SIMPLE);

        } catch (NamingException e) {
            log.warn("Bind operation failed.");
            throw e;

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new NamingException(e.getMessage());
        }
    }
}
