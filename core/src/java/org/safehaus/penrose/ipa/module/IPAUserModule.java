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
public class IPAUserModule extends Module {

    LDAPSource source;
    LDAPConnection sourceConnection;

    LDAPSource sourceUsers;

    LDAPSource target;
    LDAPConnection targetConnection;

    LDAPSource targetUsers;

    Session session;
    LDAPClient client;

    String sourceDomain;

    Map<String,String> sourceSharedAttributes = new LinkedHashMap<String,String>();
    Map<String,String> targetSharedAttributes = new LinkedHashMap<String,String>();

    public IPAUserModule() {
    }

    public void init() throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing IPA User Module", 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();

        String sourceName = getParameter("source");
        source = (LDAPSource)sourceManager.getSource(sourceName);
        sourceConnection = (LDAPConnection)source.getConnection();

        String sourceUsersName = getParameter("sourceUsers");
        sourceUsers = (LDAPSource)sourceManager.getSource(sourceUsersName);

        String targetName = getParameter("target");
        target = (LDAPSource)sourceManager.getSource(targetName);
        targetConnection = (LDAPConnection)target.getConnection();

        String targetUsersName = getParameter("targetUsers");
        targetUsers = (LDAPSource)sourceManager.getSource(targetUsersName);

        session = createAdminSession();
        client = sourceConnection.getClient(session);

        StringBuilder sb = new StringBuilder();
        for (RDN rdn : source.getBaseDn().getRdns()) {
            if (sb.length() != 0) {
                sb.append(".");
            }
            sb.append(rdn.getValue());
        }
        sourceDomain = sb.toString();

        //targetSharedAttributes.put("cn", "cn");
        //targetSharedAttributes.put("sn", "sn");

        targetSharedAttributes.put("objectGUID", "ntUniqueId");
        targetSharedAttributes.put("objectSid", "ntSid");
        //targetSharedAttributes.put("accountExpires", "krbPasswordExpiration");
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

        log.info("Synchronizing Users:");

        final Map<String,SearchResult> sourceMap = new TreeMap<String,SearchResult>();
        final Map<String,SearchResult> targetMap = new TreeMap<String,SearchResult>();

        SearchRequest sourceRequest = new SearchRequest();

        SearchResponse sourceResponse = new SearchResponse() {
            public void add(SearchResult result) throws Exception {
                DN dn = result.getDn();
                RDN rdn = dn.getRdn();
                String uid = (String)rdn.get("uid");
                sourceMap.put(uid, result);
            }
        };

        sourceUsers.search(session, sourceRequest, sourceResponse);

        SearchRequest targetRequest = new SearchRequest();

        SearchResponse targetResponse = new SearchResponse() {
            public void add(SearchResult result) throws Exception {
                Attribute attribute = result.getAttribute("sAMAccountName");
                if (attribute == null) return;

                String sAMAccountName = (String)attribute.getValue();
                targetMap.put(sAMAccountName, result);
            }
        };

        targetUsers.search(session, targetRequest, targetResponse);

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

            if (key.equals("Administrator")) continue;

            SearchResult result = targetMap.get(key);
            addSourceUser(session, result.getDn(), result.getAttributes());
        }

        for (String key  : updateTargetKeys) {

            SearchResult result = sourceMap.get(key);
            updateTargetUser(session, result.getDn(), result.getAttributes());
        }

        for (String key  : newTargetKeys) {

            SearchResult result = sourceMap.get(key);

            if (key.equals("admin")) {
                updateTargetUser(session, result.getDn(), result.getAttributes());
            } else {
                addTargetUser(session, result.getDn(), result.getAttributes());
            }
        }
    }

    public void addSourceUser(Session session, DN targetDn, Attributes targetAttributes) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("ADD SOURCE USER", 60));
        log.debug(TextUtil.displayLine(" - "+targetDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        targetAttributes.print();

        log.debug("");

        RDNBuilder rb = new RDNBuilder();
        rb.set("uid", targetAttributes.getValue("sAMAccountName"));
        RDN rdn = rb.toRdn();

        DN sourceDn = rdn.append("cn=users,cn=accounts").append(source.getBaseDn());

        Attributes sourceAttributes = new Attributes();
        sourceAttributes.addValue("objectClass", "inetOrgPerson");
        sourceAttributes.addValue("objectClass", "inetUser");
        sourceAttributes.addValue("objectClass", "krbPrincipalAux");
        sourceAttributes.addValue("objectClass", "organizationalPerson");
        sourceAttributes.addValue("objectClass", "person");
        sourceAttributes.addValue("objectClass", "posixAccount");
        sourceAttributes.addValue("objectClass", "radiusProfile");
        sourceAttributes.addValue("objectClass", "extensibleObject");

        String cn = (String)targetAttributes.getValue("cn");
        sourceAttributes.setValue("cn", cn);

        String sn = (String)targetAttributes.getValue("sn");
        sourceAttributes.setValue("sn", sn == null ? cn : sn);

        String uid = (String)targetAttributes.getValue("sAMAccountName");
        sourceAttributes.setValue("uid", uid);

        String homeDirectory = "/home/"+uid;
        sourceAttributes.setValue("homeDirectory", homeDirectory);

        sourceAttributes.setValue("gidNumber", "0");

        sourceAttributes.setValue("krbPrincipalName", targetAttributes.getValue("sAMAccountName")+"@"+sourceDomain);

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

    public void updateTargetUser(Session session, DN sourceDn, Attributes sourceAttributes) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("UPDATE TARGET USER", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        log.debug("");

        RDNBuilder rb = new RDNBuilder();
        rb.set("CN", sourceAttributes.getValue("cn"));
        RDN rdn = rb.toRdn();

        DN targetDn = rdn.append("CN=Users").append(target.getBaseDn());

        ModifyRequest targetModifyRequest = new ModifyRequest();
        targetModifyRequest.setDn(targetDn);

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
}