/**
 * Copyright 2009 Red Hat, Inc.
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
package org.safehaus.penrose.apacheds;

import org.safehaus.penrose.schema.SchemaConfig;
import org.safehaus.penrose.PenroseConfig;
import org.safehaus.penrose.Penrose;
import org.safehaus.penrose.backend.PenroseBackend;
import org.safehaus.penrose.server.PenroseServer;
import org.safehaus.penrose.ldap.LDAPService;
import org.apache.directory.server.core.configuration.*;
import org.apache.directory.server.jndi.ServerContextFactory;
import org.apache.directory.server.core.jndi.CoreContextFactory;
import org.apache.directory.server.configuration.MutableServerStartupConfiguration;
import org.apache.directory.server.ldap.support.extended.GracefulShutdownHandler;
import org.apache.directory.server.ldap.support.extended.LaunchDiagnosticUiHandler;

import javax.naming.Context;
import javax.naming.directory.InitialDirContext;
import java.io.File;
import java.util.*;

import org.safehaus.penrose.ldapbackend.Backend;
import org.safehaus.penrose.ldapbackend.apacheds.LDAPBackendAuthenticator;
import org.safehaus.penrose.ldapbackend.apacheds.LDAPBackendInterceptor;

/**
 * @author Endi S. Dewata
 */
public class ApacheDSService extends LDAPService {

    public void init() throws Exception {
        super.init();
    
        //log.warn("Starting LDAP Service.");

        if (ldapPort < 0) return;

        PenroseServer penroseServer = serviceContext.getPenroseServer();
        Penrose penrose = penroseServer.getPenrose();
        PenroseConfig penroseConfig = penrose.getPenroseConfig();
        File path = serviceContext.getPath();

        Backend backend = new PenroseBackend(penroseServer);

        MutableServerStartupConfiguration configuration = new MutableServerStartupConfiguration();

        // Configure LDAP ports
        configuration.setLdapPort(ldapPort);

        configuration.setEnableLdaps(enableLdaps);
        configuration.setLdapsPort(ldapsPort);

        if (ldapsCertificateFile != null) configuration.setLdapsCertificateFile(new File(ldapsCertificateFile));
        if (ldapsCertificatePassword != null) configuration.setLdapsCertificatePassword(ldapsCertificatePassword);

        //log.debug("Allow anonymous access: "+allowAnonymousAccess);
        configuration.setAllowAnonymousAccess(allowAnonymousAccess);

        configuration.setMaxThreads(maxThreads);

        // Configure working directory
        File workingDirectory = new File(path, "var"+File.separator+"data");
        configuration.setWorkingDirectory(workingDirectory);

        // Configure bootstrap schemas
        ClassLoader classLoader = serviceContext.getClassLoader();
        Set<Object> bootstrapSchemas = new HashSet<Object>();
        for (SchemaConfig schemaConfig : penroseConfig.getSchemaConfigs()) {

            String name = schemaConfig.getName();
            String className = "org.apache.directory.server.core.schema.bootstrap." +
                    name.substring(0, 1).toUpperCase() + name.substring(1) +
                    "Schema";

            log.debug("Loading " + className);
            Class clazz = classLoader.loadClass(className);
            Object object = clazz.newInstance();
            bootstrapSchemas.add(object);
        }

        configuration.setBootstrapSchemas(bootstrapSchemas);

        // Configure extended operation handlers
        Set<Object> extendedOperationHandlers = new HashSet<Object>();
        extendedOperationHandlers.add(new GracefulShutdownHandler());
        extendedOperationHandlers.add(new LaunchDiagnosticUiHandler());
        configuration.setExtendedOperationHandlers(extendedOperationHandlers);

        // Register Penrose authenticator

        LDAPBackendAuthenticator authenticator = new LDAPBackendAuthenticator();
        authenticator.setBackend(backend);

        MutableAuthenticatorConfiguration authenticatorConfig = new MutableAuthenticatorConfiguration();
        authenticatorConfig.setName("Penrose");
        authenticatorConfig.setAuthenticator(authenticator);

        Set<AuthenticatorConfiguration> authenticators = new LinkedHashSet<AuthenticatorConfiguration>();
        authenticators.add(authenticatorConfig);
        authenticators.addAll(configuration.getAuthenticatorConfigurations());
        //Set authenticators = configuration.getAuthenticatorConfigurations();
        //authenticators.add(authenticatorConfig);
        configuration.setAuthenticatorConfigurations(authenticators);

        log.debug("Authenticators:");
        for (AuthenticatorConfiguration ac : authenticators) {
            log.debug(" - " + ac.getName());
        }

        // Register Penrose interceptor
        LDAPBackendInterceptor interceptor = new LDAPBackendInterceptor();
        interceptor.setBackend(backend);

        MutableInterceptorConfiguration interceptorConfig = new MutableInterceptorConfiguration();
        interceptorConfig.setName("penroseService");
        interceptorConfig.setInterceptor(interceptor);

        List<InterceptorConfiguration> interceptors = new ArrayList<InterceptorConfiguration>();
        interceptors.add(interceptorConfig);
        interceptors.addAll(configuration.getInterceptorConfigurations());
        configuration.setInterceptorConfigurations(interceptors);

        log.debug("Interceptors:");
        for (InterceptorConfiguration ic : interceptors) {
            log.debug(" - " + ic.getName());
        }

        // Initialize ApacheDS
        final Hashtable<String,Object> env = new Hashtable<String,Object>();
        env.put(Context.PROVIDER_URL, "ou=system");
        env.put(Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName() );
        env.put(Context.SECURITY_PRINCIPAL, penroseConfig.getRootDn().toString());
        env.put(Context.SECURITY_CREDENTIALS, penroseConfig.getRootPassword());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.REFERRAL, "throw");
/*
        env.setProperty("asn.1.berlib.provider", "org.apache.ldap.common.berlib.asn1.SnickersProvider");
        //env.setProperty("asn.1.berlib.provider", "org.apache.asn1new.ldap.TwixProvider");

        env.setProperty("java.naming.ldap.attributes.binary",
                "photo personalSignature audio jpegPhoto javaSerializedData "+
                "userPassword userCertificate cACertificate "+
                "authorityRevocationList certificateRevocationList crossCertificatePair "+
                "x500UniqueIdentifier krb5Key");
*/
        String binaryAttributes = getParameter("java.naming.ldap.attributes.binary");
        if (binaryAttributes != null) {
            //log.debug("Setting java.naming.ldap.attributes.binary: "+binaryAttributes);
            env.put("java.naming.ldap.attributes.binary", binaryAttributes);
        }

        env.putAll(configuration.toJndiEnvironment());

        ClassLoader currentClassLoader = Thread.currentThread().getContextClassLoader();

        try {
            Thread.currentThread().setContextClassLoader(classLoader);

            new InitialDirContext(env);

        } finally {
            Thread.currentThread().setContextClassLoader(currentClassLoader);
        }

        log.warn("Listening to port "+ldapPort+" (LDAP).");

        if (enableLdaps) {
            log.warn("Listening to port "+ldapsPort+" (LDAPS).");
        }

        // Start ApacheDS synchronization thread
/*
        Thread thread = new Thread() {
            public void run() {
                try {
                    env.putAll(new SyncConfiguration().toJndiEnvironment());
                    while (true) {
                        try {
                            Thread.sleep(20000);
                        } catch ( InterruptedException e ) {
                            // ignore
                        }

                        new InitialDirContext(env);
                    }
                } catch (Exception e) {
                    log.error(e.getMessage());
                }
            }
        };

        thread.start();
*/
    }

    public void destroy() throws Exception {

        if (ldapPort < 0) return;

        Penrose penrose = serviceContext.getPenroseServer().getPenrose();
        PenroseConfig penroseConfig = penrose.getPenroseConfig();

        Hashtable<String,Object> env = new ShutdownConfiguration().toJndiEnvironment();
        env.put(Context.INITIAL_CONTEXT_FACTORY, CoreContextFactory.class.getName());
        env.put(Context.PROVIDER_URL, "ou=system");
        env.put(Context.SECURITY_PRINCIPAL, penroseConfig.getRootDn().toString());
        env.put(Context.SECURITY_CREDENTIALS, penroseConfig.getRootPassword());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");

        new InitialDirContext(env);

        log.warn("LDAP Service has been shutdown.");
    }

}
