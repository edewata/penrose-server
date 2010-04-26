package org.safehaus.penrose.ipa;

import org.safehaus.penrose.ldap.DN;
import org.safehaus.penrose.ldap.SearchResult;

import java.util.Map;

/**
 * @author Endi Sukma Dewata
 */
public interface Sync {
    
    public Map<String,DN> getDns() throws Exception;
    public SearchResult getEntry(String key) throws Exception;

    public void syncEntries() throws Exception;
    public void syncEntry(String key) throws Exception;
    public void linkEntry(String key) throws Exception;
    public void unlinkEntry(String key) throws Exception;
    public void deleteEntry(String key) throws Exception;
}
