package org.safehaus.penrose.ipa;

import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;
import org.apache.log4j.*;
import org.apache.log4j.xml.DOMConfigurator;
import org.safehaus.penrose.client.PenroseClient;
import org.safehaus.penrose.ldap.Attributes;
import org.safehaus.penrose.ldap.DN;
import org.safehaus.penrose.module.ModuleClient;
import org.safehaus.penrose.module.ModuleManagerClient;
import org.safehaus.penrose.partition.PartitionClient;
import org.safehaus.penrose.partition.PartitionManagerClient;
import org.safehaus.penrose.ldap.SearchResult;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

/**
 * @author Endi Sukma Dewata
 */
public class SyncClient {

    PenroseClient client;

    String partitionName;
    PartitionClient partitionClient;

    ChangeLogMonitorClient changeLogMonitorClient;
    SyncModuleClient userSyncModuleClient;
    SyncModuleClient groupSyncModuleClient;
    SyncModuleClient hostSyncModuleClient;

    public SyncClient(
            String serverType,
            String protocol,
            String hostname,
            int port,
            String bindDn,
            String bindPassword,
            int rmiTransportPort,
            String partitionName
    ) throws Exception {

        client = new PenroseClient(
                serverType,
                protocol,
                hostname,
                port,
                bindDn,
                bindPassword
        );

        client.setRmiTransportPort(rmiTransportPort);
        this.partitionName = partitionName;
    }

    public void connect() throws Exception {
        client.connect();

        PartitionManagerClient partitionManagerClient = client.getPartitionManagerClient();
        partitionClient = partitionManagerClient.getPartitionClient(partitionName);

        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();

        ModuleClient changeLogMonitorModuleClient = moduleManagerClient.getModuleClient("ChangeLogMonitorModule");
        changeLogMonitorClient = new ChangeLogMonitorClient(changeLogMonitorModuleClient);

        ModuleClient userSyncModuleClient = moduleManagerClient.getModuleClient("UserModule");
        this.userSyncModuleClient = new SyncModuleClient(userSyncModuleClient);

        ModuleClient groupSyncModuleClient = moduleManagerClient.getModuleClient("GroupModule");
        this.groupSyncModuleClient = new SyncModuleClient(groupSyncModuleClient);

        ModuleClient hostSyncModuleClient = moduleManagerClient.getModuleClient("HostModule");
        this.hostSyncModuleClient = new SyncModuleClient(hostSyncModuleClient);
    }

    public void close() throws Exception {
        client.close();
    }


    public void execute(Collection<String> parameters) throws Exception {

        Iterator<String> iterator = parameters.iterator();

        String command = iterator.next();
        if ("start".equals(command)) {
            start();

        } else if ("stop".equals(command)) {
            stop();

        } else if ("reset".equals(command)) {
            reset();

        } else if ("add-tracker".equals(command)) {
            String key = iterator.next();
            addTracker(new Long(key));

        } else if ("delete-trackers".equals(command)) {
            deleteTrackers();

        } else if ("show-logs".equals(command)) {
            showLogs();

        } else if ("show-log".equals(command)) {
            String key = iterator.next();
            showLog(new Long(key));

        } else if ("show-users".equals(command)) {
            showUsers();

        } else if ("show-user".equals(command)) {
            String key = iterator.next();
            showUser(key);

        } else if ("show-groups".equals(command)) {
            showGroups();

        } else if ("show-group".equals(command)) {
            String key = iterator.next();
            showGroup(key);

        } else if ("sync".equals(command)) {
            sync();

        } else if ("sync-all".equals(command)) {
            syncAll();

        } else if ("sync-users".equals(command)) {
            syncUsers();

        } else if ("sync-user".equals(command)) {
            String key = iterator.next();
            syncUser(key);

        } else if ("link-user".equals(command)) {
            String key = iterator.next();
            linkUser(key);

        } else if ("unlink-user".equals(command)) {
            String key = iterator.next();
            unlinkUser(key);

        } else if ("delete-user".equals(command)) {
            String key = iterator.next();
            deleteUser(key);

        } else if ("sync-groups".equals(command)) {
            syncGroups();

        } else if ("sync-group".equals(command)) {
            String key = iterator.next();
            syncGroup(key);

        } else if ("link-group".equals(command)) {
            String key = iterator.next();
            linkGroup(key);

        } else if ("unlink-group".equals(command)) {
            String key = iterator.next();
            unlinkGroup(key);

        } else if ("delete-group".equals(command)) {
            String key = iterator.next();
            deleteGroup(key);

        } else if ("sync-hosts".equals(command)) {
            syncHosts();

        } else {
            throw new Exception("Unknown command: "+command);
        }
    }

    public void start() throws Exception {
        changeLogMonitorClient.start();
    }

    public void stop() throws Exception {
        changeLogMonitorClient.stop();
    }

    public void reset() throws Exception {
        changeLogMonitorClient.reset();
    }

    public void addTracker(Long changeNumber) throws Exception {
        changeLogMonitorClient.addTracker(changeNumber);
    }

    public void deleteTrackers() throws Exception {
        changeLogMonitorClient.deleteTrackers();
    }

    public void showLogs() throws Exception {
        Collection<SearchResult> list = changeLogMonitorClient.getLogs();

        System.out.println("Logs:");
        for (SearchResult result : list) {
            Attributes attributes = result.getAttributes();
            Object changeNumber = attributes.getValue("changeNumber");
            Object changeType = attributes.getValue("changeType");
            Object targetDn = attributes.getValue("targetDn");

            System.out.println(" - "+changeNumber+": "+changeType+" "+targetDn);
        }
    }

    public void showLog(Long changeNumber) throws Exception {
        SearchResult result = changeLogMonitorClient.getLog(changeNumber);

        System.out.println(result);
    }

    public void showUsers() throws Exception {
        Map<String, DN> map = userSyncModuleClient.getDns();

        System.out.println("Users:");
        for (String key : map.keySet()) {
            DN dn = map.get(key);
            System.out.println(" - "+key+": "+dn);
        }
    }

    public void showUser(String key) throws Exception {
        SearchResult result = userSyncModuleClient.getEntry(key);

        System.out.println(result);
    }

    public void showGroups() throws Exception {
        Map<String,DN> map = groupSyncModuleClient.getDns();

        System.out.println("Groups:");
        for (String key : map.keySet()) {
            DN dn = map.get(key);
            System.out.println(" - "+key+": "+dn);
        }
    }

    public void showGroup(String key) throws Exception {
        SearchResult result = groupSyncModuleClient.getEntry(key);
        System.out.println(result);
    }

    public void sync() throws Exception {
        changeLogMonitorClient.sync();
    }

    public void syncAll() throws Exception {
        syncUsers();
        syncGroups();
        syncHosts();
    }

    public void syncUsers() throws Exception {
        userSyncModuleClient.syncEntries();
    }

    public void syncUser(String key) throws Exception {
        userSyncModuleClient.syncEntry(key);
    }

    public void linkUser(String key) throws Exception {
        userSyncModuleClient.linkEntry(key);
    }

    public void unlinkUser(String key) throws Exception {
        userSyncModuleClient.unlinkEntry(key);
    }

    public void deleteUser(String key) throws Exception {
        userSyncModuleClient.deleteEntry(key);
    }

    public void syncGroups() throws Exception {
        groupSyncModuleClient.syncEntries();
    }

    public void syncGroup(String key) throws Exception {
        groupSyncModuleClient.syncEntry(key);
    }

    public void linkGroup(String key) throws Exception {
        groupSyncModuleClient.linkEntry(key);
    }

    public void unlinkGroup(String key) throws Exception {
        groupSyncModuleClient.unlinkEntry(key);
    }

    public void deleteGroup(String key) throws Exception {
        groupSyncModuleClient.deleteEntry(key);
    }

    public void syncHosts() throws Exception {
        ModuleManagerClient moduleManagerClient = partitionClient.getModuleManagerClient();
        ModuleClient moduleClient = moduleManagerClient.getModuleClient("HostModule");

        moduleClient.invoke("syncHosts");
    }

    public static void showUsage() {
        System.out.println("Usage: "+ SyncClient.class.getName()+" [OPTION]... <command> [arguments]...");
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
        System.out.println("  sync                Sync all.");
        System.out.println("  sync-users          Sync all users.");
        System.out.println("  sync-user <key>     Sync user.");
        System.out.println("  show-users          Show users.");
        System.out.println("  show-user <key>     Show user.");
        System.out.println("  link-user <key>     Link user.");
        System.out.println("  unlink-user <key>   Unlink user.");
        System.out.println("  delete-user <key>   Delete user.");
        System.out.println("  sync-groups         Sync all groups.");
        System.out.println("  sync-group <key>    Sync group.");
        System.out.println("  show-groups         Show groups.");
        System.out.println("  show-group <key>    Show group.");
        System.out.println("  link-group <key>    Link group.");
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

        Getopt getopt = new Getopt(SyncClient.class.getName(), args, "-:?dvt:h:p:r:P:D:w:", longopts);

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

        String partitionName = System.getProperty("partition.name");
        File partitionHome = new File(System.getProperty("partition.home"));
        File log4jXml = new File(partitionHome, "conf"+File.separator+"log4j.xml");

        Logger logger = Logger.getLogger("org.safehaus.penrose");

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
            SyncClient client = new SyncClient(
                    serverType,
                    protocol,
                    hostname,
                    portNumber,
                    bindDn,
                    bindPassword,
                    rmiTransportPort,
                    partitionName
            );

            client.connect();

            client.execute(parameters);

            client.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}