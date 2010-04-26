package org.safehaus.penrose.ipa;

import org.safehaus.penrose.ldap.SearchResult;
import org.safehaus.penrose.module.ModuleClient;

import java.util.Collection;

/**
 * @author Endi Sukma Dewata
 */
public class ChangeLogMonitorClient implements ChangeLogMonitor {

    ModuleClient moduleClient;

    public ChangeLogMonitorClient(ModuleClient moduleClient) throws Exception {
        this.moduleClient = moduleClient;
    }

    public void start() throws Exception {
        moduleClient.invoke("start");
    }

    public void stop() throws Exception {
        moduleClient.invoke("stop");
    }

    public Collection<SearchResult> getLogs() throws Exception {
        return (Collection<SearchResult>)moduleClient.invoke("getLogs");
    }

    public SearchResult getLog(Long changeNumber) throws Exception {
        return (SearchResult)moduleClient.invoke(
                "getLog",
                new Object[] { changeNumber },
                new String[] { Long.class.getName() }
        );
    }

    public void sync() throws Exception {
        moduleClient.invoke("sync");
    }

    public void reset() throws Exception {
        moduleClient.invoke("reset");
    }

    public void addTracker(Long changeNumber) throws Exception {
        moduleClient.invoke("addTracker",
                new Object[] { changeNumber },
                new String[] { Long.class.getName() }
        );
    }

    public void deleteTrackers() throws Exception {
        moduleClient.invoke("deleteTrackers");
    }
}
