package org.safehaus.penrose.connection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.safehaus.penrose.client.BaseClient;
import org.safehaus.penrose.client.PenroseClient;

/**
 * @author Endi Sukma Dewata
 */
public class ConnectionClient extends BaseClient implements ConnectionServiceMBean {

    public static Logger log = LoggerFactory.getLogger(ConnectionClient.class);

    protected String partitionName;

    public ConnectionClient(PenroseClient client, String partitionName, String connectionName) throws Exception {
        super(client, connectionName, getStringObjectName(partitionName, connectionName));

        this.partitionName = partitionName;
    }

    public ConnectionConfig getConnectionConfig() throws Exception {
        return (ConnectionConfig)getAttribute("ConnectionConfig");
    }
    
    public void setConnectionConfig(ConnectionConfig connectionConfig) throws Exception {
        setAttribute("ConnectionConfig", connectionConfig);
    }

    public static String getStringObjectName(String partitionName, String connectionName) {
        return "Penrose:type=Connection,partition="+partitionName+",name="+connectionName;
    }

    public String getPartitionName() {
        return partitionName;
    }

    public void setPartitionName(String partitionName) {
        this.partitionName = partitionName;
    }

    public String getStatus() throws Exception {
        return (String)getAttribute("Status");
    }

    public void start() throws Exception {
        invoke("start", new Object[] {}, new String[] {});
    }

    public void stop() throws Exception {
        invoke("stop", new Object[] {}, new String[] {});
    }

    public void restart() throws Exception {
        invoke("restart", new Object[] {}, new String[] {});
    }

    public String getAdapterName() throws Exception {
        return (String)getAttribute("AdapterName");
    }
}
