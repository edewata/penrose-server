package org.safehaus.penrose.samba;

import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;
import org.apache.log4j.*;
import org.apache.log4j.xml.DOMConfigurator;
import org.safehaus.penrose.client.PenroseClient;
import org.safehaus.penrose.module.ModuleClient;
import org.safehaus.penrose.module.ModuleManagerClient;
import org.safehaus.penrose.partition.PartitionClient;
import org.safehaus.penrose.partition.PartitionManagerClient;
import org.safehaus.penrose.ldap.SearchResult;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

/**
 * @author Endi Sukma Dewata
 */
public class SambaSyncClient {

    PenroseClient client;

    public SambaSyncClient(
            String serverType,
            String protocol,
            String hostname,
            int port,
            String bindDn,
            String bindPassword
    ) throws Exception {

        client = new PenroseClient(
                serverType,
                protocol,
                hostname,
                port,
                bindDn,
                bindPassword
        );
    }

    public void setRmiTransportPort(int rmiTransportPort) {
        client.setRmiTransportPort(rmiTransportPort);
    }

    public void connect() throws Exception {
        client.connect();
    }

    public void close() throws Exception {
        client.close();
    }


    public void execute(String partition, Collection<String> parameters) throws Exception {

        Iterator<String> iterator = parameters.iterator();

        String command = iterator.next();
        if ("start".equals(command)) {
            start(partition);

        } else if ("stop".equals(command)) {
            stop(partition);

        } else if ("reset".equals(command)) {
            reset(partition);

        } else if ("show-users".equals(command)) {
            showUsers(partition);

        } else if ("show-user".equals(command)) {
            String key = iterator.next();
            showUser(partition, key);

        } else if ("show-groups".equals(command)) {
            showGroups(partition);

        } else if ("show-group".equals(command)) {
            String key = iterator.next();
            showGroup(partition, key);

        } else if ("sync".equals(command)) {
            sync(partition);

        } else if ("sync-all".equals(command)) {
            syncAll(partition);

        } else if ("sync-users".equals(command)) {
            syncUsers(partition);

        } else if ("sync-user".equals(command)) {
            String key = iterator.next();
            syncUser(partition, key);

        } else if ("link-user".equals(command)) {
            String key = iterator.next();
            linkUser(partition, key);

        } else if ("unlink-user".equals(command)) {
            String key = iterator.next();
            unlinkUser(partition, key);

        } else if ("delete-user".equals(command)) {
            String key = iterator.next();
            deleteUser(partition, key);

        } else if ("sync-groups".equals(command)) {
            syncGroups(partition);

        } else if ("sync-group".equals(command)) {
            String key = iterator.next();
            syncGroup(partition, key);

        } else if ("unlink-group".equals(command)) {
            String key = iterator.next();
            unlinkGroup(partition, key);

        } else if ("delete-group".equals(command)) {
            String key = iterator.next();
            deleteGroup(partition, key);

        } else {
            throw new Exception("Unknown command: "+command);
        }
    }

    public void start(String partition) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("ChangeLogMonitorModule");

        moduleClient.invoke("start");
    }

    public void stop(String partition) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaChangeLogMonitorModule");

        moduleClient.invoke("stop");
    }

    public void reset(String partition) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaChangeLogMonitorModule");

        moduleClient.invoke("reset");
    }

    public void showUsers(String partition) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAUserModule");

        Collection<SearchResult> results = (Collection<SearchResult>)moduleClient.invoke("getUsers");

        System.out.println("Users:");
        for (SearchResult result : results) {
            System.out.println(" - "+result.getDn());
        }
    }

    public void showUser(String partition, String key) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAUserModule");

        SearchResult result = (SearchResult)moduleClient.invoke(
                "getUser",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
        
        System.out.println(result);
    }

    public void showGroups(String partition) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAGroupModule");

        Collection<SearchResult> results = (Collection<SearchResult>)moduleClient.invoke("getGroups");

        System.out.println("Groups:");
        for (SearchResult result : results) {
            System.out.println(" - "+result.getDn());
        }
    }

    public void showGroup(String partition, String key) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAGroupModule");

        SearchResult result = (SearchResult)moduleClient.invoke(
                "getGroup",
                new Object[] { key },
                new String[] { String.class.getName() }
        );

        System.out.println(result);
    }

    public void sync(String partition) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaChangeLogMonitorModule");

        moduleClient.invoke("sync");
    }

    public void syncAll(String partition) throws Exception {
        syncUsers(partition);
        syncGroups(partition);
    }

    public void syncUsers(String partition) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAUserModule");

        moduleClient.invoke("syncUsers");
    }

    public void syncUser(String partition, String key) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAUserModule");

        moduleClient.invoke(
                "syncUser",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }

    public void linkUser(String partition, String key) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAUserModule");

        moduleClient.invoke(
                "linkUser",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }

    public void unlinkUser(String partition, String key) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAUserModule");

        moduleClient.invoke(
                "unlinkUser",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }

    public void deleteUser(String partition, String key) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAUserModule");

        moduleClient.invoke(
                "deleteUser",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }

    public void syncGroups(String partition) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAGroupModule");

        moduleClient.invoke("syncGroups");
    }

    public void syncGroup(String partition, String key) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAGroupModule");

        moduleClient.invoke(
                "syncGroup",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }

    public void unlinkGroup(String partition, String key) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAGroupModule");

        moduleClient.invoke(
                "unlinkGroup",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }

    public void deleteGroup(String partition, String key) throws Exception {
        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        PartitionClient partitionClient = partitionManagerClient.getPartitionClient(partition);
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("SambaIPAGroupModule");

        moduleClient.invoke(
                "deleteGroup",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }

    public static void showUsage() {
        System.out.println("Usage: org.safehaus.penrose.samba.SambaSyncClient [OPTION]... <command> [arguments]...");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -?, --help         display this help and exit");
        System.out.println("  -P protocol        Penrose JMX protocol");
        System.out.println("  -h host            Penrose server");
        System.out.println("  -p port            Penrose JMX port");
        System.out.println("  -D username        username");
        System.out.println("  -w password        password");
        System.out.println("  -d                 run in debug mode");
        System.out.println("  -v                 run in verbose mode");
        System.out.println();
        System.out.println("Commands:");
        System.out.println("  list-users          List users.");
        System.out.println("  sync                Sync all.");
        System.out.println("  sync-users          Sync users.");
        System.out.println("  sync-user <key>     Sync user.");
        System.out.println("  unlink-user <key>   Unlink user.");
        System.out.println("  delete-user <key>   Delete user.");
        System.out.println("  sync-groups         Sync groups.");
        System.out.println("  sync-group <key>    Sync group.");
        System.out.println("  unlink-group <key>  Unlink group.");
        System.out.println("  delete-group <key>  Delete group.");
        System.out.println("  sync-hosts          Sync hosts.");
        System.out.println("  sync-host <key>     Sync host.");
    }

    public static void main(String args[]) throws Exception {

        Level level          = Level.WARN;
        String serverType    = PenroseClient.PENROSE;
        String protocol      = PenroseClient.DEFAULT_PROTOCOL;
        String hostname      = "localhost";
        int portNumber       = PenroseClient.DEFAULT_RMI_PORT;
        int rmiTransportPort = PenroseClient.DEFAULT_RMI_TRANSPORT_PORT;

        String bindDn = null;
        String bindPassword = null;

        LongOpt[] longopts = new LongOpt[1];
        longopts[0] = new LongOpt("help", LongOpt.NO_ARGUMENT, null, '?');

        Getopt getopt = new Getopt("SambaSyncClient", args, "-:?dvt:h:p:r:P:D:w:", longopts);

        Collection<String> parameters = new ArrayList<String>();
        int c;
        while ((c = getopt.getopt()) != -1) {
            switch (c) {
                case ':':
                case '?':
                    showUsage();
                    System.exit(0);
                    break;
                case 1:
                    parameters.add(getopt.getOptarg());
                    break;
                case 'd':
                    level = Level.DEBUG;
                    break;
                case 'v':
                    level = Level.INFO;
                    break;
                case 'P':
                    protocol = getopt.getOptarg();
                    break;
                case 't':
                    serverType = getopt.getOptarg();
                    break;
                case 'h':
                    hostname = getopt.getOptarg();
                    break;
                case 'p':
                    portNumber = Integer.parseInt(getopt.getOptarg());
                    break;
                case 'r':
                    rmiTransportPort = Integer.parseInt(getopt.getOptarg());
                    break;
                case 'D':
                    bindDn = getopt.getOptarg();
                    break;
                case 'w':
                    bindPassword = getopt.getOptarg();
            }
        }

        if (parameters.size() == 0) {
            showUsage();
            System.exit(0);
        }

        File penroseHome = new File(System.getProperty("penrose.home"));

        //Logger rootLogger = Logger.getRootLogger();
        //rootLogger.setLevel(Level.OFF);

        Logger logger = Logger.getLogger("org.safehaus.penrose");

        File log4jXml = new File(penroseHome, "conf"+File.separator+"log4j.xml");

        if (level.equals(Level.DEBUG)) {
            logger.setLevel(level);
            ConsoleAppender appender = new ConsoleAppender(new PatternLayout("%-20C{1} [%4L] %m%n"));
            BasicConfigurator.configure(appender);

        } else if (level.equals(Level.INFO)) {
            logger.setLevel(level);
            ConsoleAppender appender = new ConsoleAppender(new PatternLayout("[%d{MM/dd/yyyy HH:mm:ss}] %m%n"));
            BasicConfigurator.configure(appender);

        } else if (log4jXml.exists()) {
            DOMConfigurator.configure(log4jXml.getAbsolutePath());

        } else {
            logger.setLevel(level);
            ConsoleAppender appender = new ConsoleAppender(new PatternLayout("[%d{MM/dd/yyyy HH:mm:ss}] %m%n"));
            BasicConfigurator.configure(appender);
        }

        try {
            SambaSyncClient client = new SambaSyncClient(
                    serverType,
                    protocol,
                    hostname,
                    portNumber,
                    bindDn,
                    bindPassword
            );

            client.setRmiTransportPort(rmiTransportPort);
            client.connect();

            String partition = System.getProperty("partition.name");
            client.execute(partition, parameters);

            client.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}