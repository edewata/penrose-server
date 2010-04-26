package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.control.PersistentSearchControl;
import org.safehaus.penrose.filter.Filter;
import org.safehaus.penrose.filter.FilterEvaluator;
import org.safehaus.penrose.filter.FilterTool;
import org.safehaus.penrose.ipa.ChangeLogMonitor;
import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ldap.connection.LDAPConnection;
import org.safehaus.penrose.ldap.source.LDAPSource;
import org.safehaus.penrose.util.TextUtil;
import org.safehaus.penrose.source.SourceManager;
import org.safehaus.penrose.module.Module;
import org.safehaus.penrose.module.ModuleManager;
import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.jdbc.source.JDBCSource;
import org.safehaus.penrose.jdbc.QueryResponse;

import java.util.*;
import java.sql.ResultSet;
import java.sql.Timestamp;

/**
 * @author Endi Sukma Dewata
 */
public class ChangeLogMonitorModule extends Module implements ChangeLogMonitor, Runnable {

    LDAPSource changelog;
    JDBCSource tracker;

    Session session;

    LDAPConnection connection;
    LDAPClient client;

    Map<Filter,SyncModule> modules = new LinkedHashMap<Filter,SyncModule>();

    FilterEvaluator filterEvaluator = new FilterEvaluator();

    public ChangeLogMonitorModule() throws Exception {
    }

    public void init() throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing Change Log Monitor Module", 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();
        ModuleManager moduleManager = partition.getModuleManager();

        String changelogName = getParameter("changelog");
        changelog = (LDAPSource)sourceManager.getSource(changelogName);

        connection = (LDAPConnection)changelog.getConnection();

        String trackerName = getParameter("tracker");
        tracker = (JDBCSource)sourceManager.getSource(trackerName);

        String s = getParameter("modules.count");
        int modulesCount = Integer.parseInt(s);

        for (int i=1; i<=modulesCount; i++) {
            s = getParameter("modules."+i);
            int p = s.indexOf(":");
            String f = s.substring(0, p);
            String moduleName = s.substring(p+1);

            Filter filter = FilterTool.parseFilter(f);
            SyncModule module = (SyncModule)moduleManager.getModule(moduleName);

            modules.put(filter, module);
        }
    }

    public void destroy() throws Exception {
    }

    public void run() {
        try {
            Long lastTrackedChangeNumber = getLastTrackedChangeNumber(session);
            log.debug("Last tracked change number: "+lastTrackedChangeNumber);

            PersistentSearchControl psc = new PersistentSearchControl(
                    PersistentSearchControl.CHANGE_TYPE_ADD
                            | PersistentSearchControl.CHANGE_TYPE_DELETE
                            | PersistentSearchControl.CHANGE_TYPE_MODIFY
                            | PersistentSearchControl.CHANGE_TYPE_MODDN,
                    false,
                    false
            );

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.setDn(changelog.getBaseDn());

            if (lastTrackedChangeNumber != null) {
                searchRequest.setFilter(
                        "(&(changeNumber>="+lastTrackedChangeNumber+")"+
                        "(!(changeNumber="+lastTrackedChangeNumber+")))"
                );
            }

            searchRequest.addControl(psc);

            SearchResponse searchResponse = new SearchResponse() {
                public void add(SearchResult searchResult) throws Exception {
                    try {
                        sync(session, searchResult);

                    } catch (Exception e) {
                        log.error(e.getMessage(), e);
                    }
                }
            };

            client.search(searchRequest, searchResponse);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public void start() throws Exception {

        session = createAdminSession();
        client = connection.getClient(session);

        Thread thread = new Thread(this);
        thread.start();
    }

    public void stop() throws Exception {
        client.close();
        session.close();
    }

    public Collection<SearchResult> getLogs() throws Exception {
        Session session = null;

        try {
            session = createAdminSession();
            Collection<SearchResult> results = new ArrayList<SearchResult>();

            Long lastTrackedChangeNumber = getLastTrackedChangeNumber(session);
            log.debug("Last tracked change number: "+lastTrackedChangeNumber);

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.setDn(changelog.getBaseDn());

            if (lastTrackedChangeNumber != null) {
                searchRequest.setFilter(
                        "(&(changeNumber>="+lastTrackedChangeNumber+")"+
                        "(!(changeNumber="+lastTrackedChangeNumber+")))"
                );
            }

            SearchResponse searchResponse = new SearchResponse();

            changelog.search(session, searchRequest, searchResponse);

            while (searchResponse.hasNext()) {
                SearchResult result = searchResponse.next();
                results.add(result);
            }

            return results;

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public SearchResult getLog(Long changeNumber) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.setDn(changelog.getBaseDn());
            searchRequest.setFilter("(changeNumber="+changeNumber+")");

            SearchResponse searchResponse = new SearchResponse();

            changelog.search(session, searchRequest, searchResponse);

            if (!searchResponse.hasNext()) return null;
            return searchResponse.next();

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void sync() throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            Long lastTrackedChangeNumber = getLastTrackedChangeNumber(session);
            log.debug("Last tracked change number: "+lastTrackedChangeNumber);

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.setDn(changelog.getBaseDn());

            if (lastTrackedChangeNumber != null) {
                searchRequest.setFilter(
                        "(&(changeNumber>="+lastTrackedChangeNumber+")"+
                        "(!(changeNumber="+lastTrackedChangeNumber+")))"
                );
            }

            SearchResponse searchResponse = new SearchResponse();
            searchResponse.setSizeLimit(1);

            try {
                changelog.search(session, searchRequest, searchResponse);
            } catch (Exception e) {
                // ignore
            }

            if (!searchResponse.hasNext()) return;

            SearchResult searchResult = searchResponse.next();
            sync(session, searchResult);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void reset() throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            Long lastTrackedChangeNumber = getLastTrackedChangeNumber(session);
            log.debug("Last tracked change number: "+lastTrackedChangeNumber);

            SearchResult rootDse = this.changelog.find(session, "");
            Attribute attribute = rootDse.getAttribute("lastChangeNumber");
            if (attribute == null) return;

            Long lastChangeNumber = Long.parseLong(attribute.getValue().toString());
            log.debug("Last change number: "+lastChangeNumber);
            
            if (lastChangeNumber.equals(lastTrackedChangeNumber)) return;
            
            addTracker(session, lastChangeNumber);
            
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void addTracker(Long changeNumber) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            addTracker(session, changeNumber);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void deleteTrackers() throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            deleteTrackers(session);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public Long getLastTrackedChangeNumber(Session session) throws Exception {

        QueryResponse response = new QueryResponse() {
            public void add(Object object) throws Exception {
                ResultSet rs = (ResultSet)object;
                super.add(rs.getLong(1));
            }
        };

        String tableName = tracker.getTableName();
        tracker.executeQuery(session, "select max(changeNumber) from "+tableName, response);

        if (!response.hasNext()) return null;

        return (Long)response.next();
    }

    public void addTracker(Session session, Number changeNumber) throws Exception {

        Attributes attributes = new Attributes();
        attributes.setValue("changeNumber", changeNumber);
        attributes.setValue("changeTimestamp", new Timestamp(System.currentTimeMillis()));

        tracker.add(session, new DN(), attributes);
    }

    public void deleteTrackers(Session session) throws Exception {
        tracker.clear(session);
    }

    public void sync(Session session, SearchResult searchResult) throws Exception {

        Attributes attributes = searchResult.getAttributes();

        Long changeNumber = Long.parseLong(attributes.getValue("changeNumber").toString());
        if (log.isInfoEnabled()) log.info("Processing change number "+changeNumber);

        for (Filter filter : modules.keySet()) {
            if (filterEvaluator.eval(attributes, filter)) {
                SyncModule module = modules.get(filter);
                module.sync(session, searchResult);
            }
        }

        addTracker(session, changeNumber);
    }
}