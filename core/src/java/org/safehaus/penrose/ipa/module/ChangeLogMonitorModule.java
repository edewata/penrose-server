package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.control.PersistentSearchControl;
import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ldap.connection.LDAPConnection;
import org.safehaus.penrose.ldap.source.LDAPSource;
import org.safehaus.penrose.util.TextUtil;
import org.safehaus.penrose.changelog.ChangeLog;
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
public class ChangeLogMonitorModule extends Module implements Runnable {

    LDAPSource source;
    LDAPSource target;

    LDAPConnection sourceConnection;

    LDAPSource sourceUsers;
    LDAPSource sourceGroups;
    LDAPSource sourceHosts;

    LDAPSource targetUsers;

    LDAPSource changelog;

    JDBCSource tracker;

    Session session;
    LDAPClient client;

    UserSyncModule userSyncModule;
    GroupSyncModule groupSyncModule;

    public ChangeLogMonitorModule() {
    }

    public void init() throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing Change Log Monitor Module", 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();
        ModuleManager moduleManager = partition.getModuleManager();

        String changelogName = getParameter("changelog");
        changelog = (LDAPSource)sourceManager.getSource(changelogName);

        String sourceName = getParameter("source");
        source = (LDAPSource)sourceManager.getSource(sourceName);
        sourceConnection = (LDAPConnection)source.getConnection();

        String sourceUsersName = getParameter("sourceUsers");
        sourceUsers = (LDAPSource)sourceManager.getSource(sourceUsersName);

        String sourceGroupsName = getParameter("sourceGroups");
        sourceGroups = (LDAPSource)sourceManager.getSource(sourceGroupsName);

        String targetName = getParameter("target");
        target = (LDAPSource)sourceManager.getSource(targetName);

        String trackerName = getParameter("tracker");
        tracker = (JDBCSource)sourceManager.getSource(trackerName);

        String userSyncModuleName = getParameter("userSyncModule");
        userSyncModule = (UserSyncModule)moduleManager.getModule(userSyncModuleName);

        String groupSyncModuleName = getParameter("groupSyncModule");
        groupSyncModule = (GroupSyncModule)moduleManager.getModule(groupSyncModuleName);
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
        client = sourceConnection.getClient(session);

        Thread thread = new Thread(this);
        thread.start();
    }

    public void stop() throws Exception {
        client.close();
        session.close();
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

            SearchResult rootDse = source.find(session, "");
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

    public void sync(Session session, SearchResult searchResult) throws Exception {

        Attributes attributes = searchResult.getAttributes();

        DN targetDn = new DN((String)attributes.getValue("targetDn"));
        String changeType = (String)attributes.getValue("changeType");
        String changes = (String)attributes.getValue("changes");
        String changeTime = (String)attributes.getValue("changeTime");
        Long changeNumber = Long.parseLong(attributes.getValue("changeNumber").toString());

        if (log.isInfoEnabled()) log.info("Processing change number "+changeNumber);

        if (targetDn.endsWith(sourceUsers.getBaseDn())) {
            if (changeType.equals("add")) {
                Attributes changeAttributes = ChangeLog.parseAttributes(changes);
                userSyncModule.addUser(session, targetDn, changeAttributes);

            } else if (changeType.equals("modify")) {
                Collection<Modification> modifications = ChangeLog.parseModifications(changes);
                userSyncModule.modifyUser(session, targetDn, modifications);

            } else if (changeType.equals("delete")) {
                //userSyncModule.deleteUser(session, targetDn);
            }

        } else if (targetDn.endsWith(sourceGroups.getBaseDn())) {
            if (changeType.equals("add")) {
                Attributes changeAttributes = ChangeLog.parseAttributes(changes);
                groupSyncModule.addGroup(session, targetDn, changeAttributes);

            } else if (changeType.equals("modify")) {
                Collection<Modification> modifications = ChangeLog.parseModifications(changes);
                groupSyncModule.modifyGroup(session, targetDn, modifications);

            } else if (changeType.equals("delete")) {
                //groupSyncModule.deleteGroup(session, targetDn);
            }
        }

        addTracker(session, changeNumber);
    }
}