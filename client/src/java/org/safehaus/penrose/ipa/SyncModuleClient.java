package org.safehaus.penrose.ipa;

import org.safehaus.penrose.ldap.DN;
import org.safehaus.penrose.ldap.SearchResult;
import org.safehaus.penrose.module.ModuleClient;

import java.util.Map;

/**
 * @author Endi Sukma Dewata
 */
public class SyncModuleClient implements Sync {

    ModuleClient moduleClient;

    public SyncModuleClient(ModuleClient moduleClient) throws Exception {
        this.moduleClient = moduleClient;
    }

    public Map<String,DN> getDns() throws Exception {
        return (Map<String,DN>)moduleClient.invoke("getDns");
    }

    public SearchResult getEntry(String key) throws Exception {
        return (SearchResult)moduleClient.invoke(
                "getEntry",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }

    public void syncEntries() throws Exception {
        moduleClient.invoke("syncEntries");
    }

    public void syncEntry(String key) throws Exception {
        moduleClient.invoke(
                "syncEntry",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }

    public void linkEntry(String key) throws Exception {
        moduleClient.invoke(
                "linkEntry",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }

    public void unlinkEntry(String key) throws Exception {
        moduleClient.invoke(
                "unlinkEntry",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }

    public void deleteEntry(String key) throws Exception {
        moduleClient.invoke(
                "deleteEntry",
                new Object[] { key },
                new String[] { String.class.getName() }
        );
    }
}
