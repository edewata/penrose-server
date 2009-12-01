package org.safehaus.penrose.mina;

import org.safehaus.penrose.Penrose;
import org.safehaus.penrose.backend.PenroseBackend;
import org.safehaus.penrose.server.PenroseServer;
import org.safehaus.penrose.naming.PenroseContext;
import org.safehaus.penrose.schema.SchemaManager;
import org.safehaus.penrose.schema.AttributeType;
import org.safehaus.penrose.schema.attributeSyntax.AttributeSyntax;
import org.safehaus.penrose.schema.attributeSyntax.AttributeSyntaxUtil;
import org.safehaus.penrose.ldap.LDAPService;
import org.safehaus.penrose.ldapbackend.mina.MinaHandler;
import org.apache.mina.transport.socket.nio.SocketAcceptor;
import org.apache.mina.transport.socket.nio.SocketAcceptorConfig;
import org.apache.mina.transport.socket.nio.SocketSessionConfig;
import org.apache.mina.common.ExecutorThreadModel;

import java.net.InetSocketAddress;
import java.util.*;

import edu.emory.mathcs.backport.java.util.concurrent.TimeUnit;
import edu.emory.mathcs.backport.java.util.concurrent.LinkedBlockingQueue;
import edu.emory.mathcs.backport.java.util.concurrent.ThreadPoolExecutor;
import org.safehaus.penrose.ldapbackend.Backend;

/**
 * @author Endi S. Dewata
 */
public class MinaService extends LDAPService {

    SocketAcceptorConfig acceptorConfig;
    SocketAcceptor acceptor;

    MinaProtocolCodecFactory codecFactory;
    MinaHandler handler;

    ExecutorThreadModel threadModel;
    ThreadPoolExecutor threadPoolExecutor;

    public void init() throws Exception {
        super.init();

        PenroseServer penroseServer = serviceContext.getPenroseServer();
        Penrose penrose = penroseServer.getPenrose();
        PenroseContext penroseContext = penrose.getPenroseContext();

        Backend backend = new PenroseBackend(penroseServer);

        SchemaManager schemaManager = penroseContext.getSchemaManager();
        Collection<AttributeType> attributeTypes = schemaManager.getAttributeTypes();
        Set<String> binaryAttributes = new HashSet<String>();

        //log.debug("Binary attributes:");
        for (AttributeType attributeType : attributeTypes) {

            //String name = attributeType.getName();
            //log.debug("Attribute type "+name);

            String syntax = attributeType.getSyntax();
            //log.debug("Attribute syntax: "+syntax);
            if (syntax == null) {
                //log.debug("Attribute syntax for "+name+" not defined.");
                continue;
            }

            String oid = syntax;

            int p = oid.indexOf('{');
            if (p >= 0) {
                oid = oid.substring(0, p);
            }
            //log.debug("OID: "+oid);

            AttributeSyntax as = schemaManager.getAttributeSyntax(oid);
            if (as == null) {
                //log.debug("Attribute syntax "+oid+" not found.");
                continue;
            }

            if (as.isHumanReadable()) {
                //log.debug("Attribute is not binary.");
                continue;
            }

            //log.debug(" - " + name);
            for (String cn : attributeType.getNames()) {
                binaryAttributes.add(cn.toLowerCase());
            }
        }

        Hashtable<Object,Object> env = new Hashtable<Object,Object>();
        env.put("java.naming.ldap.attributes.binary", binaryAttributes);

        codecFactory = new MinaProtocolCodecFactory(env);
        handler = new MinaHandler(backend, codecFactory);

        threadPoolExecutor = new ThreadPoolExecutor(
                maxThreads,
                maxThreads,
                60,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue()
        );

        threadModel = ExecutorThreadModel.getInstance("Mina");
        threadModel.setExecutor(threadPoolExecutor);

        acceptorConfig = new SocketAcceptorConfig();
        acceptorConfig.setDisconnectOnUnbind(false);
        acceptorConfig.setReuseAddress(true);
        acceptorConfig.setThreadModel(threadModel);

        ((SocketSessionConfig)(acceptorConfig.getSessionConfig())).setTcpNoDelay(true);

        acceptor = new SocketAcceptor();

        //acceptor.setLocalAddress();
        //acceptor.setHandler(handler);
        acceptor.bind(new InetSocketAddress(ldapPort), handler, acceptorConfig);

        log.warn("Listening to port "+ldapPort+" (LDAP).");
    }

    public void destroy() throws Exception {
        acceptor.unbind(new InetSocketAddress(ldapPort));
    }
}
