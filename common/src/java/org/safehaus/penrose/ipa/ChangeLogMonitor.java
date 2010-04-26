package org.safehaus.penrose.ipa;

import org.safehaus.penrose.ldap.SearchResult;

import java.util.Collection;

/**
 * @author Endi Sukma Dewata
 */
public interface ChangeLogMonitor {

    public void start() throws Exception;
    public void stop() throws Exception;

    public Collection<SearchResult> getLogs() throws Exception;
    public SearchResult getLog(Long changeNumber) throws Exception;

    public void sync() throws Exception;
    public void reset() throws Exception;

    public void addTracker(Long changeNumber) throws Exception;
    public void deleteTrackers() throws Exception;
}
