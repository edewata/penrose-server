package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ldap.connection.LDAPConnection;
import org.safehaus.penrose.ldap.source.LDAPSource;
import org.safehaus.penrose.util.TextUtil;
import org.safehaus.penrose.source.SourceManager;
import org.safehaus.penrose.module.Module;
import org.safehaus.penrose.session.Session;

import java.util.*;

/**
 * @author Endi Sukma Dewata
 */
public class IPAGroupModule extends Module {

    LDAPSource source;
    LDAPConnection sourceConnection;

    LDAPSource sourceUsers;
    LDAPSource sourceGroups;

    LDAPSource target;
    LDAPConnection targetConnection;

    LDAPSource targetUsers;
    LDAPSource targetGroups;

    Session session;
    LDAPClient client;

    Map<String,String> sourceSharedAttributes = new LinkedHashMap<String,String>();
    Map<String,String> targetSharedAttributes = new LinkedHashMap<String,String>();

    public IPAGroupModule() {
    }

    public void init() throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing IPA Group Module", 60));
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

        String targetUsersName = getParameter("targetUsers");
        targetUsers = (LDAPSource)sourceManager.getSource(targetUsersName);

        String targetGroupsName = getParameter("targetGroups");
        targetGroups = (LDAPSource)sourceManager.getSource(targetGroupsName);

        session = createAdminSession();
        client = sourceConnection.getClient(session);

        //sourceSharedAttributes.put("description", "description");

        targetSharedAttributes.put("objectGUID", "ntUniqueId");
        targetSharedAttributes.put("objectSid", "ntSid");
    }

    public void destroy() throws Exception {
        log.debug("Closing session.");
        session.close();
    }

    public void synchronize() throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            synchronize(session);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void synchronize(Session session) throws Exception {

        log.info("Synchronizing Groups:");

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
        log.info("Adding source: "+newSourceKeys);

        Set<String> updateTargetKeys = new TreeSet<String>();
        updateTargetKeys.addAll(targetMap.keySet());
        updateTargetKeys.retainAll(sourceMap.keySet());
        log.info("Updating target: "+updateTargetKeys);

        Set<String> newTargetKeys = new TreeSet<String>();
        newTargetKeys.addAll(sourceMap.keySet());
        newTargetKeys.removeAll(targetMap.keySet());
        log.info("Adding target: "+newTargetKeys);

        for (String key  : newSourceKeys) {
            
            if (key.equals("Administrators")) continue;

            SearchResult result = targetMap.get(key);
            addSourceGroup(session, result.getDn(), result.getAttributes());
        }

        for (String key  : updateTargetKeys) {
            SearchResult result = sourceMap.get(key);
            updateTargetGroup(session, result.getDn(), result.getAttributes());
        }

        for (String key  : newTargetKeys) {

            SearchResult result = sourceMap.get(key);

            if (key.equals("admins")) {
                updateTargetGroup(session, result.getDn(), result.getAttributes());
            } else {
                addTargetGroup(session, result.getDn(), result.getAttributes());
            }
        }
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

    public DN createTargetGroupDn(DN sourceDn) throws Exception {

        RDN rdn = sourceDn.getRdn();
        String cn = rdn.get("cn").toString();

        RDNBuilder rb = new RDNBuilder();
        rb.set("CN", cn);
        RDN targetRdn = rb.toRdn();

        return targetRdn.append("CN=Users").append(target.getBaseDn());
    }

    public void addSourceGroup(Session session, DN targetDn, Attributes targetAttributes) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("ADD SOURCE GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+targetDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        targetAttributes.print();

        log.debug("");

        DN sourceDn = createSourceGroupDn(targetDn, targetAttributes);

        Attributes sourceAttributes = new Attributes();
        sourceAttributes.addValue("objectClass", "groupOfNames");
        sourceAttributes.addValue("objectClass", "posixGroup");
        sourceAttributes.addValue("objectClass", "extensibleObject");

        sourceAttributes.setValue("description", targetAttributes.getValue("description"));
        sourceAttributes.setValue("cn", targetAttributes.getValue("sAMAccountName"));

        for (String targetAttributeName : targetSharedAttributes.keySet()) {
            String sourceAttributeName = targetSharedAttributes.get(targetAttributeName);
            Collection<Object> values = targetAttributes.getValues(targetAttributeName);
            if (values == null || values.isEmpty()) continue;

            sourceAttributes.setValues(sourceAttributeName, values);
        }

        AddRequest addRequest = new AddRequest();
        addRequest.setDn(sourceDn);
        addRequest.setAttributes(sourceAttributes);

        AddResponse addResponse = new AddResponse();

        source.add(session, addRequest, addResponse);

        // sync shared attributes

        SearchResult sourceResult = source.find(sourceDn);
        sourceAttributes = sourceResult.getAttributes();

        ModifyRequest modifyRequest = new ModifyRequest();
        modifyRequest.setDn(targetDn);

        for (String sourceAttributeName : sourceSharedAttributes.keySet()) {
            String targetAttributeName = sourceSharedAttributes.get(sourceAttributeName);
            Collection<Object> values = sourceAttributes.getValues(sourceAttributeName);
            if (values == null || values.isEmpty()) continue;

            modifyRequest.addModification(new Modification(
                    Modification.REPLACE,
                    new Attribute(targetAttributeName, values)
            ));
        }

        if (!modifyRequest.isEmpty()) {
            ModifyResponse modifyResponse = new ModifyResponse();

            target.modify(session, modifyRequest, modifyResponse);
        }
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

        // syncback shared attributes

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

        if (!modifyRequest.isEmpty()) {
            ModifyResponse modifyResponse = new ModifyResponse();

            source.modify(session, modifyRequest, modifyResponse);
        }
    }

    public void updateTargetGroup(Session session, DN sourceDn, Attributes sourceAttributes) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("UPDATE TARGET GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        log.debug("");

        RDN rdn = sourceDn.getRdn();
        String cn = rdn.get("cn").toString();

        ModifyRequest targetModifyRequest = new ModifyRequest();
        DN targetDn;

        if (cn.equals("admins")) {
            targetDn = new DN("CN=Administrators,CN=Builtin").append(target.getBaseDn());

        } else {
            targetDn = createTargetGroupDn(sourceDn);
            targetModifyRequest.setDn(targetDn);

            Attribute sourceMemberAttribute = sourceAttributes.get("member");
            if (sourceMemberAttribute != null) {

                Attribute targetMemberAttribute = new Attribute("member");

                for (Object value : sourceMemberAttribute.getValues()) {
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

                    targetMemberAttribute.addValue(targetMemberDn.toString());
                }

                targetModifyRequest.addModification(new Modification(
                        Modification.REPLACE,
                        targetMemberAttribute
                ));
            }
        }

        for (String sourceAttributeName : sourceSharedAttributes.keySet()) {
            String targetAttributeName = sourceSharedAttributes.get(sourceAttributeName);
            Collection<Object> values = sourceAttributes.getValues(sourceAttributeName);
            if (values == null || values.isEmpty()) continue;

            targetModifyRequest.addModification(new Modification(
                    Modification.REPLACE,
                    new Attribute(targetAttributeName, values)
            ));
        }

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            target.modify(session, targetModifyRequest, targetModifyResponse);
        }

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

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    public void modifyTargetGroup(Session session, DN dn, Collection<Modification> modifications) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("MODIFY TARGET GROUP", 60));
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