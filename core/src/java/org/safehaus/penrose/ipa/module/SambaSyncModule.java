package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.control.PersistentSearchControl;
import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ldap.connection.LDAPConnection;
import org.safehaus.penrose.ldap.source.LDAPSource;
import org.safehaus.penrose.util.TextUtil;
import org.safehaus.penrose.changelog.ChangeLog;
import org.safehaus.penrose.source.SourceManager;
import org.safehaus.penrose.module.Module;
import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.jdbc.source.JDBCSource;
import org.safehaus.penrose.jdbc.QueryResponse;

import java.util.Collection;
import java.sql.ResultSet;
import java.sql.Timestamp;

/**
 * @author Endi Sukma Dewata
 */
public class SambaSyncModule extends Module implements Runnable {

    LDAPSource source;
    LDAPConnection sourceConnection;

    LDAPSource sourceUsers;
    LDAPSource sourceGroups;

    LDAPSource target;
    LDAPConnection targetConnection;

    LDAPSource changelog;

    JDBCSource tracker;

    Session session;
    LDAPClient client;

    public SambaSyncModule() {
    }

    public void init() throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing Samba Sync Module", 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();

        String sourceName = getParameter("source");
        source = (LDAPSource)sourceManager.getSource(sourceName);
        sourceConnection = (LDAPConnection)source.getConnection();

        String sourceUsersName = getParameter("sourceUsers");
        sourceUsers = (LDAPSource)sourceManager.getSource(sourceUsersName);

        String sourceGroupsName = getParameter("sourceGroups");
        sourceGroups = (LDAPSource)sourceManager.getSource(sourceGroupsName);

        String targetName = getParameter("target");
        target = (LDAPSource)sourceManager.getSource(targetName);
        targetConnection = (LDAPConnection)target.getConnection();

        String changelogName = getParameter("changelog");
        changelog = (LDAPSource)sourceManager.getSource(changelogName);

        session = createAdminSession();
        client = sourceConnection.getClient(session);

        String trackerName = getParameter("tracker");
        tracker = (JDBCSource)sourceManager.getSource(trackerName);

        Thread thread = new Thread(this);
        thread.start();
    }

    public void destroy() throws Exception {
        log.debug("Closing session.");
        session.close();
    }

    public void run() {
        try {
            runImpl();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public void runImpl() throws Exception {

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
                    process(session, searchResult);

                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
        };

        client.search(searchRequest, searchResponse);
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

    public void process(Session session, SearchResult searchResult) throws Exception {

        Attributes attributes = searchResult.getAttributes();

        DN targetDn = new DN((String)attributes.getValue("targetDn"));
        String changeType = (String)attributes.getValue("changeType");
        String changes = (String)attributes.getValue("changes");
        String changeTime = (String)attributes.getValue("changeTime");
        Long changeNumber = Long.parseLong(attributes.getValue("changeNumber").toString());

        if (targetDn.endsWith(sourceUsers.getBaseDn())) {
            if (changeType.equals("add")) {
                Attributes changeAttributes = ChangeLog.parseAttributes(changes);
                addUser(session, targetDn, changeAttributes);

            } else if (changeType.equals("modify")) {
                Collection<Modification> modifications = ChangeLog.parseModifications(changes);
                modifyUser(session, targetDn, modifications);

            } else if (changeType.equals("delete")) {
                deleteUser(session, targetDn);
            }

        } else if (targetDn.endsWith(sourceGroups.getBaseDn())) {
            if (changeType.equals("add")) {
                Attributes changeAttributes = ChangeLog.parseAttributes(changes);
                addGroup(session, targetDn, changeAttributes);

            } else if (changeType.equals("modify")) {
                Collection<Modification> modifications = ChangeLog.parseModifications(changes);
                modifyGroup(session, targetDn, modifications);

            } else if (changeType.equals("delete")) {
                deleteGroup(session, targetDn);
            }
        }

        addTracker(session, changeNumber);
    }

    public void addUser(Session session, DN dn, Attributes attributes) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("ADD USER", 60));
        log.debug(TextUtil.displayLine(" - "+dn, 60));
        log.debug(TextUtil.displaySeparator(60));

        attributes.print();

        log.debug("");

        RDNBuilder rb = new RDNBuilder();
        rb.set("CN", attributes.getValue("cn"));
        RDN rdn = rb.toRdn();

        DN newDn = rdn.append("CN=Users").append(target.getBaseDn());

        Attributes newAttributes = new Attributes();
        newAttributes.addValue("objectClass", "user");
        newAttributes.setValue("sAMAccountName", attributes.getValue("uid"));
        newAttributes.setValue("userAccountControl", "512");

        AddRequest addRequest = new AddRequest();
        addRequest.setDn(newDn);
        addRequest.setAttributes(newAttributes);

        AddResponse addResponse = new AddResponse();
        
        target.add(session, addRequest, addResponse);
    }

    public void modifyUser(Session session, DN dn, Collection<Modification> modifications) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("MODIFY USER", 60));
        log.debug(TextUtil.displayLine(" - "+dn, 60));
        log.debug(TextUtil.displaySeparator(60));

        Object userPassword = null;

        for (Modification modification : modifications) {
            Attribute attribute = modification.getAttribute();
            String attributeName = attribute.getName();

            String op = LDAP.getModificationOperation(modification.getType());
            log.debug(" - " + op + ": " + attributeName + " => " + attribute.getValues());

            if ("unhashed#user#password".equals(attributeName)) {
                userPassword = attribute.getValue();
            }
        }

        log.debug("");

        if (userPassword == null) return;

        SearchResult searchResult = findUser(session, dn);
        if (searchResult == null) return;

        ModifyRequest modifyRequest = new ModifyRequest();
        modifyRequest.setDn(searchResult.getDn());

        modifyRequest.addModification(new Modification(
                Modification.REPLACE,
                new Attribute("userPassword", userPassword)
        ));

        ModifyResponse modifyResponse = new ModifyResponse();

        target.modify(session, modifyRequest, modifyResponse);
    }

    public void deleteUser(Session session, DN dn) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("DELETE USER", 60));
        log.debug(TextUtil.displayLine(" - "+dn, 60));
        log.debug(TextUtil.displaySeparator(60));

        SearchResult searchResult = findUser(session, dn);
        if (searchResult == null) return;

        DeleteRequest deleteRequest = new DeleteRequest();
        deleteRequest.setDn(searchResult.getDn());

        DeleteResponse deleteResponse = new DeleteResponse();

        target.delete(session, deleteRequest, deleteResponse);
    }

    public SearchResult findUser(Session session, DN dn) throws Exception {

        RDN rdn = dn.getRdn();
        Object uid = rdn.get("uid");

        SearchRequest searchRequest = new SearchRequest();
        searchRequest.setDn(target.getBaseDn());
        searchRequest.setFilter("(sAMAccountName="+uid+")");

        SearchResponse searchResponse = new SearchResponse();

        target.search(session, searchRequest, searchResponse);

        if (!searchResponse.hasNext()) {
            log.debug("User not found.");
            return null;
        }

        return searchResponse.next();
    }

    public void addGroup(Session session, DN dn, Attributes attributes) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("ADD GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+dn, 60));
        log.debug(TextUtil.displaySeparator(60));

        attributes.print();

        log.debug("");

        RDNBuilder rb = new RDNBuilder();
        rb.set("CN", attributes.getValue("cn"));
        RDN rdn = rb.toRdn();

        DN newDn = rdn.append("CN=Users").append(target.getBaseDn());

        Attributes newAttributes = new Attributes();
        newAttributes.addValue("objectClass", "group");
        newAttributes.setValue("description", attributes.getValue("description"));

        AddRequest addRequest = new AddRequest();
        addRequest.setDn(newDn);
        addRequest.setAttributes(newAttributes);

        AddResponse addResponse = new AddResponse();

        target.add(session, addRequest, addResponse);
    }

    public void modifyGroup(Session session, DN dn, Collection<Modification> modifications) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("MODIFY GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+dn, 60));
        log.debug(TextUtil.displaySeparator(60));

        for (Modification modification : modifications) {
            Attribute attribute = modification.getAttribute();

            String op = LDAP.getModificationOperation(modification.getType());
            log.debug(" - " + op + ": " + attribute.getName() + " => " + attribute.getValues());
        }

        log.debug("");
    }

    public void deleteGroup(Session session, DN dn) throws Exception {
        
        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("DELETE GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+dn, 60));
        log.debug(TextUtil.displaySeparator(60));

        RDN rdn = dn.getRdn();

        RDNBuilder rb = new RDNBuilder();
        rb.set("CN", rdn.get("cn"));
        RDN newRdn = rb.toRdn();

        DN newDn = newRdn.append("CN=Users").append(target.getBaseDn());

        DeleteRequest deleteRequest = new DeleteRequest();
        deleteRequest.setDn(newDn);

        DeleteResponse deleteResponse = new DeleteResponse();

        target.delete(session, deleteRequest, deleteResponse);
    }
}