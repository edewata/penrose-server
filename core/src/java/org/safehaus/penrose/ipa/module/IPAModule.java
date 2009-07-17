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

import java.util.*;
import java.sql.ResultSet;
import java.sql.Timestamp;

/**
 * @author Endi Sukma Dewata
 */
public class IPAModule extends Module implements Runnable {

    LDAPSource source;
    LDAPConnection sourceConnection;

    LDAPSource sourceUsers;
    LDAPSource sourceGroups;
    LDAPSource sourceHosts;

    LDAPSource target;
    LDAPConnection targetConnection;

    LDAPSource targetUsers;
    LDAPSource targetGroups;
    LDAPSource targetHosts;

    LDAPSource changelog;

    JDBCSource tracker;

    Session session;
    LDAPClient client;

    Map<String,String> sourceSharedAttributes = new LinkedHashMap<String,String>();
    Map<String,String> targetSharedAttributes = new LinkedHashMap<String,String>();

    public IPAModule() {
    }

    public void init() throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing IPA Module", 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();

        String sourceName = getParameter("source");
        source = (LDAPSource)sourceManager.getSource(sourceName);
        sourceConnection = (LDAPConnection)source.getConnection();

        String sourceUsersName = getParameter("sourceUsers");
        sourceUsers = (LDAPSource)sourceManager.getSource(sourceUsersName);

        String sourceGroupsName = getParameter("sourceGroups");
        sourceGroups = (LDAPSource)sourceManager.getSource(sourceGroupsName);

        String sourceHostsName = getParameter("sourceHosts");
        sourceHosts = (LDAPSource)sourceManager.getSource(sourceHostsName);

        String targetName = getParameter("target");
        target = (LDAPSource)sourceManager.getSource(targetName);
        targetConnection = (LDAPConnection)target.getConnection();

        String targetUsersName = getParameter("targetUsers");
        targetUsers = (LDAPSource)sourceManager.getSource(targetUsersName);

        String targetGroupsName = getParameter("targetGroups");
        targetGroups = (LDAPSource)sourceManager.getSource(targetGroupsName);

        String targetHostsName = getParameter("targetHosts");
        targetHosts = (LDAPSource)sourceManager.getSource(targetHostsName);

        String changelogName = getParameter("changelog");
        changelog = (LDAPSource)sourceManager.getSource(changelogName);

        session = createAdminSession();
        client = sourceConnection.getClient(session);

        String trackerName = getParameter("tracker");
        tracker = (JDBCSource)sourceManager.getSource(trackerName);

        targetSharedAttributes.put("cn", "cn");
        targetSharedAttributes.put("sn", "sn");

        targetSharedAttributes.put("objectGUID", "ntUniqueId");
        targetSharedAttributes.put("objectSid", "ntSid");

        //Thread thread = new Thread(this);
        //thread.start();
    }

    public void destroy() throws Exception {
        log.debug("Closing session.");
        session.close();
    }

    public void synchronize() throws Exception {
        synchronizeGroups();
        synchronizeHosts();
    }

    public void synchronizeGroups() throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            synchronizeGroups(session);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void synchronizeGroups(Session session) throws Exception {

        log.debug("Synchronizing Groups:");

        final Map<String,SearchResult> sourceMap = new TreeMap<String,SearchResult>();
        final Map<String,SearchResult> targetMap = new TreeMap<String,SearchResult>();

        SearchRequest sourceRequest = new SearchRequest();

        SearchResponse sourceResponse = new SearchResponse() {
            public void add(SearchResult result) throws Exception {
                DN dn = result.getDn();
                RDN rdn = dn.getRdn();
                String cn = (String)rdn.get("cn");
                sourceMap.put(cn, result);
            }
        };

        sourceGroups.search(session, sourceRequest, sourceResponse);

        SearchRequest targetRequest = new SearchRequest();

        SearchResponse targetResponse = new SearchResponse() {
            public void add(SearchResult result) throws Exception {
                Attribute attribute = result.getAttribute("sAMAccountName");
                if (attribute == null) return;

                String sAMAccountName = (String)attribute.getValue();
                targetMap.put(sAMAccountName, result);
            }
        };

        targetGroups.search(session, targetRequest, targetResponse);

        Set<String> newSourceKeys = new TreeSet<String>();
        newSourceKeys.addAll(targetMap.keySet());
        newSourceKeys.removeAll(sourceMap.keySet());
        log.debug("Adding source: "+newSourceKeys);

        Set<String> newTargetKeys = new TreeSet<String>();
        newTargetKeys.addAll(sourceMap.keySet());
        newTargetKeys.removeAll(targetMap.keySet());
        log.debug("Adding target: "+newTargetKeys);
/*
        for (String key  : newSourceKeys) {
            SearchResult result = targetMap.get(key);
            addSourceGroup(session, result.getDn(), result.getAttributes());
        }
*/
        for (String key  : newTargetKeys) {
            SearchResult result = sourceMap.get(key);
            addTargetGroup(session, result.getDn(), result.getAttributes());
        }
    }

    public void synchronizeHosts() throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            synchronizeHosts(session);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void synchronizeHosts(Session session) throws Exception {

        log.debug("IPA Hosts:");

        SearchRequest request = new SearchRequest();

        SearchResponse response = new SearchResponse() {
            public void add(SearchResult result) throws Exception {
                DN dn = result.getDn();
                log.debug(" - "+dn);
            }
        };

        sourceHosts.search(session, request, response);
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
                addTargetUser(session, targetDn, changeAttributes);

            } else if (changeType.equals("modify")) {
                Collection<Modification> modifications = ChangeLog.parseModifications(changes);
                modifyTargetUser(session, targetDn, modifications);

            } else if (changeType.equals("delete")) {
                deleteUser(session, targetDn);
            }

        } else if (targetDn.endsWith(sourceGroups.getBaseDn())) {
            if (changeType.equals("add")) {
                Attributes changeAttributes = ChangeLog.parseAttributes(changes);
                addTargetGroup(session, targetDn, changeAttributes);

            } else if (changeType.equals("modify")) {
                Collection<Modification> modifications = ChangeLog.parseModifications(changes);
                modifyGroup(session, targetDn, modifications);

            } else if (changeType.equals("delete")) {
                deleteGroup(session, targetDn);
            }
        }

        addTracker(session, changeNumber);
    }

    public void addSourceUser(Session session, DN dn, Attributes attributes) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("ADD SOURCE USER", 60));
        log.debug(TextUtil.displayLine(" - "+dn, 60));
        log.debug(TextUtil.displaySeparator(60));

        attributes.print();

        log.debug("");

        RDNBuilder rb = new RDNBuilder();
        rb.set("uid", attributes.getValue("sAMAccountName"));
        RDN rdn = rb.toRdn();

        DN newDn = rdn.append("cn=users,cn=accounts").append(source.getBaseDn());

        Attributes newAttributes = new Attributes();
        newAttributes.addValue("objectClass", "inetOrgPerson");
        newAttributes.addValue("objectClass", "inetUser");
        newAttributes.addValue("objectClass", "krbPrincipalAux");
        newAttributes.addValue("objectClass", "organizationalPerson");
        newAttributes.addValue("objectClass", "person");
        newAttributes.addValue("objectClass", "posixAccount");
        newAttributes.addValue("objectClass", "radiusProfile");
        newAttributes.setValue("cn", attributes.getValue("cn"));
        newAttributes.setValue("sn", attributes.getValue("sn"));
        newAttributes.setValue("uid", attributes.getValue("sAMAccountName"));

        AddRequest addRequest = new AddRequest();
        addRequest.setDn(newDn);
        addRequest.setAttributes(newAttributes);

        AddResponse addResponse = new AddResponse();

        source.add(session, addRequest, addResponse);
    }

    public void addTargetUser(Session session, DN sourceDn, Attributes sourceAttributes) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("ADD TARGET USER", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        sourceAttributes.print();

        log.debug("");

        RDNBuilder rb = new RDNBuilder();
        rb.set("CN", sourceAttributes.getValue("cn"));
        RDN rdn = rb.toRdn();

        DN targetDn = rdn.append("CN=Users").append(target.getBaseDn());

        Attributes targetAttributes = new Attributes();
        targetAttributes.addValue("objectClass", "user");
        targetAttributes.setValue("sAMAccountName", sourceAttributes.getValue("uid"));
        targetAttributes.setValue("userAccountControl", "512");

        AddRequest addRequest = new AddRequest();
        addRequest.setDn(targetDn);
        addRequest.setAttributes(targetAttributes);

        AddResponse addResponse = new AddResponse();
        
        target.add(session, addRequest, addResponse);

        SearchResult targetResult = target.find(targetDn);
        targetAttributes = targetResult.getAttributes();

        ModifyRequest modifyRequest = new ModifyRequest();
        modifyRequest.setDn(sourceDn);

        Attribute sourceObjectClasses = sourceAttributes.get("objectClass");
        if (!sourceObjectClasses.containsValue("extensibleObject")) {
            modifyRequest.addModification(new Modification(
                    Modification.ADD,
                    new Attribute("objectClass", "extensibleObject")
            ));
        }

        for (String targetAttributeName : targetSharedAttributes.keySet()) {
            String sourceAttributeName = targetSharedAttributes.get(targetAttributeName);
            Collection<Object> values = targetAttributes.getValues(targetAttributeName);
            if (values == null || values.isEmpty()) continue;

            modifyRequest.addModification(new Modification(
                    Modification.REPLACE,
                    new Attribute(sourceAttributeName, values)
            ));
        }

        ModifyResponse modifyResponse = new ModifyResponse();

        source.modify(session, modifyRequest, modifyResponse);
    }

    public void updateTargetUser(Session session, DN sourceDn, Attributes sourceAttributes) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("UPDATE TARGET USER", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        RDNBuilder rb = new RDNBuilder();
        rb.set("CN", sourceAttributes.getValue("cn"));
        RDN rdn = rb.toRdn();

        DN targetDn = rdn.append("CN=Users").append(target.getBaseDn());

        ModifyRequest targetModifyRequest = new ModifyRequest();
        targetModifyRequest.setDn(targetDn);

        ModifyResponse targetModifyResponse = new ModifyResponse();

        target.modify(session, targetModifyRequest, targetModifyResponse);


        // syncback shared attributes

        SearchResult targetResult = target.find(targetDn);
        Attributes targetAttributes = targetResult.getAttributes();

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        Attribute sourceObjectClasses = sourceAttributes.get("objectClass");
        if (!sourceObjectClasses.containsValue("extensibleObject")) {
            sourceModifyRequest.addModification(new Modification(
                    Modification.ADD,
                    new Attribute("objectClass", "extensibleObject")
            ));
        }

        for (String targetAttributeName : targetSharedAttributes.keySet()) {
            String sourceAttributeName = targetSharedAttributes.get(targetAttributeName);
            Collection<Object> values = targetAttributes.getValues(targetAttributeName);
            if (values == null || values.isEmpty()) continue;

            sourceModifyRequest.addModification(new Modification(
                    Modification.REPLACE,
                    new Attribute(sourceAttributeName, values)
            ));
        }

        ModifyResponse sourceModifyResponse = new ModifyResponse();

        source.modify(session, sourceModifyRequest, sourceModifyResponse);
    }

    public void modifyTargetUser(Session session, DN sourceDn, Collection<Modification> modifications) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("MODIFY TARGET USER", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        Object userPassword = null;
        DN modifiersName = null;

        for (Modification modification : modifications) {
            Attribute attribute = modification.getAttribute();
            String attributeName = attribute.getName();

            String op = LDAP.getModificationOperation(modification.getType());
            log.debug(" - " + op + ": " + attributeName + " => " + attribute.getValues());

            if ("unhashed#user#password".equals(attributeName)) {
                userPassword = attribute.getValue();

            } else if ("modifiersName".equalsIgnoreCase(attributeName)) {
                modifiersName = new DN(attribute.getValue().toString());
            }
        }

        log.debug("");

        if (modifiersName != null && modifiersName.matches("cn=ipa-memberof,cn=plugins,cn=config")) {
            log.debug("Skipping changes by ipa-memberof plugin.");
            return;
        }

        if (userPassword == null) return;

        SearchResult searchResult = findTargetUser(session, sourceDn);
        if (searchResult == null) return;

        DN targetDn = searchResult.getDn();

        ModifyRequest modifyRequest = new ModifyRequest();
        modifyRequest.setDn(targetDn);

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

        SearchResult searchResult = findTargetUser(session, dn);
        if (searchResult == null) return;

        DeleteRequest deleteRequest = new DeleteRequest();
        deleteRequest.setDn(searchResult.getDn());

        DeleteResponse deleteResponse = new DeleteResponse();

        target.delete(session, deleteRequest, deleteResponse);
    }

    public SearchResult findTargetUser(Session session, DN dn) throws Exception {

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

    public DN createSourceGroupDn(DN dn, Attributes attributes) throws Exception {

        RDNBuilder rb = new RDNBuilder();
        rb.set("CN", attributes.getValue("sAMAccountName"));
        RDN sourceRdn = rb.toRdn();

        return sourceRdn.append("cn=groups,cn=accounts").append(source.getBaseDn());
    }

    public DN createTargetGroupDn(DN sourceGroupDn) throws Exception {

        RDN rdn = sourceGroupDn.getRdn();

        RDNBuilder rb = new RDNBuilder();
        rb.set("CN", rdn.get("cn"));
        RDN targetRdn = rb.toRdn();

        return targetRdn.append("CN=Users").append(target.getBaseDn());
    }

    public void addSourceGroup(Session session, DN dn, Attributes attributes) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("ADD SOURCE GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+dn, 60));
        log.debug(TextUtil.displaySeparator(60));

        attributes.print();

        log.debug("");

        DN sourceDn = createSourceGroupDn(dn, attributes);

        Attributes newAttributes = new Attributes();
        newAttributes.addValue("objectClass", "groupOfNames");
        newAttributes.addValue("objectClass", "posixGroup");
        newAttributes.setValue("description", attributes.getValue("description"));
        newAttributes.setValue("cn", attributes.getValue("sAMAccountName"));

        AddRequest addRequest = new AddRequest();
        addRequest.setDn(sourceDn);
        addRequest.setAttributes(newAttributes);

        AddResponse addResponse = new AddResponse();

        source.add(session, addRequest, addResponse);
    }

    public void addTargetGroup(Session session, DN sourceDn, Attributes sourceAttributes) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("ADD TARGET GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        sourceAttributes.print();

        log.debug("");

        DN targetDn = createTargetGroupDn(sourceDn);

        Attributes targetAttributes = new Attributes();
        targetAttributes.addValue("objectClass", "group");
        targetAttributes.setValue("description", sourceAttributes.getValue("description"));
        targetAttributes.setValue("sAMAccountName", sourceAttributes.getValue("cn"));

        for (Object value : sourceAttributes.getValues("member")) {
            DN sourceMemberDn = new DN(value.toString());
            DN targetMemberDn;

            if (sourceMemberDn.endsWith(sourceUsers.getBaseDn())) {
                SearchResult searchResult = findTargetUser(session, sourceMemberDn);
                if (searchResult == null) continue;

                targetMemberDn = searchResult.getDn();

            } else if (sourceMemberDn.endsWith(sourceGroups.getBaseDn())) {
                targetMemberDn = createTargetGroupDn(sourceMemberDn);

            } else {
                continue;
            }

            targetAttributes.addValue("member", targetMemberDn.toString());
        }

        AddRequest addRequest = new AddRequest();
        addRequest.setDn(targetDn);
        addRequest.setAttributes(targetAttributes);

        AddResponse addResponse = new AddResponse();

        target.add(session, addRequest, addResponse);

        SearchResult targetResult = target.find(targetDn);
        targetAttributes = targetResult.getAttributes();

        ModifyRequest modifyRequest = new ModifyRequest();
        modifyRequest.setDn(sourceDn);

        Attribute sourceObjectClasses = sourceAttributes.get("objectClass");
        if (!sourceObjectClasses.containsValue("extensibleObject")) {
            modifyRequest.addModification(new Modification(
                    Modification.ADD,
                    new Attribute("objectClass", "extensibleObject")
            ));
        }

        for (String targetAttributeName : targetSharedAttributes.keySet()) {
            String sourceAttributeName = targetSharedAttributes.get(targetAttributeName);
            Collection<Object> values = targetAttributes.getValues(targetAttributeName);
            if (values == null || values.isEmpty()) continue;

            modifyRequest.addModification(new Modification(
                    Modification.REPLACE,
                    new Attribute(sourceAttributeName, values)
            ));
        }

        if (modifyRequest.isEmpty()) return;

        ModifyResponse modifyResponse = new ModifyResponse();

        source.modify(session, modifyRequest, modifyResponse);
    }

    public void modifyGroup(Session session, DN dn, Collection<Modification> modifications) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("MODIFY GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+dn, 60));
        log.debug(TextUtil.displaySeparator(60));

        Modification memberModification = null;

        for (Modification modification : modifications) {
            Attribute attribute = modification.getAttribute();
            String attributeName = attribute.getName();

            String op = LDAP.getModificationOperation(modification.getType());
            log.debug(" - " + op + ": " + attributeName + " => " + attribute.getValues());

            if ("member".equalsIgnoreCase(attributeName)) {
                memberModification = modification;
            }
        }

        log.debug("");

        if (memberModification == null) {
            log.debug("No group member has been modified.");
            return;
        }
        
        Attribute attribute = memberModification.getAttribute();
        DN memberDn = new DN(attribute.getValue().toString());

        DN targetMemberDn;

        if (memberDn.endsWith(sourceUsers.getBaseDn())) {
            SearchResult searchResult = findTargetUser(session, memberDn);
            if (searchResult == null) return;

            targetMemberDn = searchResult.getDn();

        } else if (memberDn.endsWith(sourceGroups.getBaseDn())) {
            targetMemberDn = createTargetGroupDn(memberDn);

        } else {
            return;
        }

        DN targetDn = createTargetGroupDn(dn);

        ModifyRequest modifyRequest = new ModifyRequest();
        modifyRequest.setDn(targetDn);

        modifyRequest.addModification(new Modification(
                memberModification.getType(),
                new Attribute("member", targetMemberDn.toString())
        ));

        ModifyResponse modifyResponse = new ModifyResponse();

        target.modify(session, modifyRequest, modifyResponse);
    }

    public void deleteGroup(Session session, DN dn) throws Exception {
        
        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("DELETE GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+dn, 60));
        log.debug(TextUtil.displaySeparator(60));

        DN targetDn = createTargetGroupDn(dn);

        DeleteRequest deleteRequest = new DeleteRequest();
        deleteRequest.setDn(targetDn);

        DeleteResponse deleteResponse = new DeleteResponse();

        target.delete(session, deleteRequest, deleteResponse);
    }
}