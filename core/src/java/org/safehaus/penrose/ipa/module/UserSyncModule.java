package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ldap.source.LDAPSource;
import org.safehaus.penrose.util.TextUtil;
import org.safehaus.penrose.filter.*;
import org.safehaus.penrose.source.SourceManager;
import org.safehaus.penrose.module.Module;
import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.mapping.MappingManager;
import org.safehaus.penrose.mapping.Mapping;
import org.safehaus.penrose.interpreter.Interpreter;
import org.ietf.ldap.LDAPException;

import java.util.*;

/**
 * @author Endi Sukma Dewata
 */
public class UserSyncModule extends Module {

    LDAPSource source;
    LDAPSource sourceUsers;
    LDAPSource target;
    LDAPSource targetUsers;

    String sourceKeyAttribute;
    String sourceLinkAttribute;
    String targetKeyAttribute;
    String targetLinkAttribute;

    Mapping importSourceUserMapping;
    Mapping importSourceUserMapping2;
    Mapping linkSourceUserMapping;
    Mapping linkSourceUserMapping2;
    Mapping syncSourceUserMapping;
    Mapping syncSourceUserMapping2;
    Mapping unlinkSourceUserMapping;
    Mapping unlinkSourceUserMapping2;

    Map<String,DN> sourceDns = new LinkedHashMap<String,DN>();
    Map<String,String> sourceDnMapping = new LinkedHashMap<String,String>();
    Map<String,DN> targetDns = new LinkedHashMap<String,DN>();
    Map<String,String> targetDnMapping = new LinkedHashMap<String,String>();

    Set<String> ignoredDns = new HashSet<String>();

    public UserSyncModule() {
    }

    public void init() throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing "+getName(), 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();
        MappingManager mappingManager = partition.getMappingManager();

        String sourceName = getParameter("source");
        source = (LDAPSource)sourceManager.getSource(sourceName);

        String sourceUsersName = getParameter("sourceUsers");
        sourceUsers = (LDAPSource)sourceManager.getSource(sourceUsersName);

        sourceKeyAttribute = getParameter("sourceKeyAttribute");
        sourceLinkAttribute = getParameter("sourceLinkAttribute");

        String importSourceUserMappingName = getParameter("importSourceUserMapping");
        importSourceUserMapping = mappingManager.getMapping(importSourceUserMappingName);

        String importSourceUserMapping2Name = getParameter("importSourceUserMapping2");
        importSourceUserMapping2 = mappingManager.getMapping(importSourceUserMapping2Name);

        String linkSourceUserMappingName = getParameter("linkSourceUserMapping");
        linkSourceUserMapping = mappingManager.getMapping(linkSourceUserMappingName);

        String linkSourceUserMapping2Name = getParameter("linkSourceUserMapping2");
        linkSourceUserMapping2 = mappingManager.getMapping(linkSourceUserMapping2Name);

        String syncSourceUserMappingName = getParameter("syncSourceUserMapping");
        syncSourceUserMapping = mappingManager.getMapping(syncSourceUserMappingName);

        String syncSourceUserMapping2Name = getParameter("syncSourceUserMapping2");
        syncSourceUserMapping2 = mappingManager.getMapping(syncSourceUserMapping2Name);

        String unlinkSourceUserMappingName = getParameter("unlinkSourceUserMapping");
        unlinkSourceUserMapping = mappingManager.getMapping(unlinkSourceUserMappingName);

        String unlinkSourceUserMapping2Name = getParameter("unlinkSourceUserMapping2");
        unlinkSourceUserMapping2 = mappingManager.getMapping(unlinkSourceUserMapping2Name);

        String targetName = getParameter("target");
        target = (LDAPSource)sourceManager.getSource(targetName);

        String targetUsersName = getParameter("targetUsers");
        targetUsers = (LDAPSource)sourceManager.getSource(targetUsersName);

        targetKeyAttribute = getParameter("targetKeyAttribute");
        targetLinkAttribute = getParameter("targetLinkAttribute");

        String s = getParameter("mapDn.count");
        int mapDnCount = s == null ? 0 : Integer.parseInt(s);

        for (int i=0; i<mapDnCount; i++) {
            DN sourceAdminDn = new DN(getParameter("mapDn."+i+".source"));
            DN targetAdminDn = new DN(getParameter("mapDn."+i+".target"));

            sourceDns.put(sourceAdminDn.getNormalizedDn(), sourceAdminDn);
            sourceDnMapping.put(sourceAdminDn.getNormalizedDn(), targetAdminDn.getNormalizedDn());

            targetDns.put(targetAdminDn.getNormalizedDn(), targetAdminDn);
            targetDnMapping.put(targetAdminDn.getNormalizedDn(), sourceAdminDn.getNormalizedDn());
        }

        s = getParameter("ignoreDn.count");
        int ignoreDnCount = s == null ? 0 : Integer.parseInt(s);

        for (int i=0; i<ignoreDnCount; i++) {
            DN targetSyncDn = new DN(getParameter("ignoreDn."+i));
            ignoredDns.add(targetSyncDn.getNormalizedDn());
        }
    }

    public void destroy() throws Exception {
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Public Methods
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void syncUsers() throws Exception {
        final Session session = createAdminSession();

        try {
            SearchRequest sourceRequest = new SearchRequest();

            SearchResponse sourceResponse = new SearchResponse() {
                public void add(SearchResult sourceEntry) throws Exception {
                    syncUser(session, sourceEntry);
                }
            };

            sourceUsers.search(session, sourceRequest, sourceResponse);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void syncUser(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchResult sourceEntry = searchSourceUser(session, key);
            syncUser(session, sourceEntry);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void unlinkUser(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchResult sourceEntry = searchSourceUser(session, key);
            unlinkUser(session, sourceEntry);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void deleteUser(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchResult sourceEntry = searchSourceUser(session, key);
            deleteUser(session, sourceEntry);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Internal Methods
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public SearchResult syncUser(Session session, SearchResult sourceEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        if (log.isInfoEnabled()) log.info("Synchronizing "+sourceDn);

        if (ignoredDns.contains(sourceDn.getNormalizedDn())) {
            if (log.isInfoEnabled()) log.info("Ignoring "+sourceDn);
            return null;
        }

        SearchResult targetEntry = searchTargetUser(session, sourceEntry);

        if (targetEntry == null) {
            if (log.isInfoEnabled()) log.info("Adding "+sourceDn);
            targetEntry = addUser(session, sourceEntry);

        } else {
            Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);

            if (linkAttribute == null) {
                if (log.isInfoEnabled()) log.info("Linking "+sourceDn);
                linkUser(session, sourceEntry, targetEntry);

            } else {
                if (log.isInfoEnabled()) log.info("Syncing "+sourceDn);
                syncUser(session, sourceEntry, targetEntry);
            }
        }

        return targetEntry;
    }

    public void unlinkUser(Session session, SearchResult sourceEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        if (log.isInfoEnabled()) log.info("Unlinking "+sourceDn);

        Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);

        if (linkAttribute == null) {
            if (log.isInfoEnabled()) log.info("Entry not linked.");

        } else {
            SearchResult targetEntry = searchTargetUser(session, sourceEntry);
            if (log.isInfoEnabled()) log.info("Unlinking "+(targetEntry == null ? null : targetEntry.getDn()));
            unlinkUser(session, sourceEntry, targetEntry);
        }
    }

    public void deleteUser(Session session, SearchResult sourceEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        if (log.isInfoEnabled()) log.info("Deleting "+sourceDn);

        Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);

        if (linkAttribute != null) {
            SearchResult targetEntry = searchTargetUser(session, sourceEntry);
            if (targetEntry != null) {
                DN targetDn = targetEntry.getDn();
                if (log.isInfoEnabled()) log.info("Deleting "+targetDn);
                target.delete(session, targetDn);
            }
        }

        source.delete(session, sourceDn);
    }

    public SearchResult addUser(Session session, SearchResult sourceEntry) throws Exception {
        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        return addUser(session, sourceDn, sourceAttributes);
    }

    public SearchResult addUser(Session session, DN sourceDn, Attributes sourceAttributes) throws Exception {

        String normalizedSourceDn = sourceDn.getNormalizedDn();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("ADD USER", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        sourceAttributes.print();

        log.debug("");

        Attributes targetAttributes = new Attributes();

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(source.getName(), sourceAttributes);

        importSourceUserMapping.map(interpreter, targetAttributes);

        String normalizedTargetDn = sourceDnMapping.get(normalizedSourceDn);
        DN targetDn = targetDns.get(normalizedTargetDn);

        Attribute dnAttribute = targetAttributes.remove("dn");
        if (targetDn == null) {
            targetDn = new DN((String)dnAttribute.getValue());
        }

        RDN rdn = targetDn.getRdn();
        String rdnAttribute = rdn.getName();
        Object rdnValue = rdn.getValue();

        int counter = 0;
        boolean done = false;

        while (!done) {
            AddRequest addRequest = new AddRequest();
            addRequest.setDn(targetDn);
            addRequest.setAttributes(targetAttributes);

            AddResponse addResponse = new AddResponse();

            try {
                target.add(session, addRequest, addResponse);
                done = true;

            } catch (LDAPException e) {
                log.error("Error: "+e.getMessage());

                if (e.getResultCode() == LDAP.ENTRY_ALREADY_EXISTS) {

                    ++counter;
                    Object newValue = rdnValue.toString()+" "+counter;

                    RDNBuilder rb = new RDNBuilder();
                    rb.set(rdnAttribute, newValue);
                    rdn = rb.toRdn();

                    targetDn = rdn.append(targetDn.getParentDn());
                    targetAttributes.setValue(rdnAttribute, newValue);
                    log.debug("New target DN: "+targetDn);

                } else {
                    done = true;
                }
            }
        }

        SearchResult targetResult = target.find(session, targetDn);
        targetAttributes = targetResult.getAttributes();

        if (importSourceUserMapping2 == null) return targetResult;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(target.getName(), targetAttributes);

        importSourceUserMapping2.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse modifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, modifyResponse);
        }

        return targetResult;
    }

    public void linkUser(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("LINK USER", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        log.debug("");

        DN targetDn = targetEntry.getDn();
        Attributes targetAttributes = targetEntry.getAttributes();

        ModifyRequest targetModifyRequest = new ModifyRequest();
        targetModifyRequest.setDn(targetDn);

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(source.getName(), sourceAttributes);

        linkSourceUserMapping.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            target.modify(session, targetModifyRequest, targetModifyResponse);
        }

        if (linkSourceUserMapping2 == null) return;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(target.getName(), targetAttributes);

        linkSourceUserMapping2.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    public void syncUser(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("SYNC USER", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        log.debug("");

        DN targetDn = targetEntry.getDn();
        Attributes targetAttributes = targetEntry.getAttributes();

        ModifyRequest targetModifyRequest = new ModifyRequest();
        targetModifyRequest.setDn(targetDn);

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(source.getName(), sourceAttributes);

        syncSourceUserMapping.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            target.modify(session, targetModifyRequest, targetModifyResponse);
        }

        if (syncSourceUserMapping2 == null) return;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(target.getName(), targetAttributes);

        syncSourceUserMapping2.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    public void modifyUser(Session session, DN sourceDn, Collection<Modification> modifications) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("MODIFY USER", 60));
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

        SearchResult sourceEntry = source.find(session, sourceDn);
        SearchResult targetEntry = getLinkedUser(session, sourceEntry);
        if (targetEntry == null) return;

        ModifyRequest modifyRequest = new ModifyRequest();
        modifyRequest.setDn(targetEntry.getDn());

        modifyRequest.addModification(new Modification(
                Modification.REPLACE,
                new Attribute("userPassword", userPassword)
        ));

        ModifyResponse modifyResponse = new ModifyResponse();

        target.modify(session, modifyRequest, modifyResponse);
    }

    public void unlinkUser(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("UNLINK USER", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        log.debug("");

        DN targetDn = null;
        Attributes targetAttributes = null;

        if (targetEntry != null) {
            targetDn = targetEntry.getDn();
            targetAttributes = targetEntry.getAttributes();

            ModifyRequest targetModifyRequest = new ModifyRequest();
            targetModifyRequest.setDn(targetDn);

            Interpreter interpreter = partition.newInterpreter();
            interpreter.set("session", session);
            interpreter.set("module", this);
            interpreter.set(source.getName(), sourceAttributes);

            unlinkSourceUserMapping.map(interpreter, targetAttributes, targetModifyRequest);

            if (!targetModifyRequest.isEmpty()) {
                ModifyResponse targetModifyResponse = new ModifyResponse();

                target.modify(session, targetModifyRequest, targetModifyResponse);
            }
        }

        if (unlinkSourceUserMapping2 == null) return;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        if (targetEntry != null) interpreter.set(target.getName(), targetAttributes);

        unlinkSourceUserMapping2.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Helper Methods
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public SearchResult searchSourceUser(Session session, String key) throws Exception {

        Filter filter = new SimpleFilter(sourceKeyAttribute, "=", key);
        if (log.isInfoEnabled()) log.info("Searching source for "+filter);

        SearchRequest sourceRequest = new SearchRequest();
        sourceRequest.setFilter(filter);

        SearchResponse sourceResponse = new SearchResponse();

        sourceUsers.search(session, sourceRequest, sourceResponse);

        if (!sourceResponse.hasNext()) {
            throw new Exception("User with "+filter+" not found.");
        }

        return sourceResponse.next();
    }

    public SearchResult getLinkedUser(Session session, SearchResult sourceEntry) throws Exception {

        Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);
        if (linkAttribute == null) return null;

        return getLinkedUser(session, linkAttribute.getValue());
    }

    public SearchResult getLinkedUser(Session session, Object link) throws Exception {
    
        Filter filter = new SimpleFilter(targetLinkAttribute, "=", link);
        if (log.isInfoEnabled()) log.info("Searching target for "+filter);

        SearchRequest targetRequest = new SearchRequest();
        targetRequest.setFilter(filter);

        SearchResponse targetResponse = new SearchResponse();

        targetUsers.search(session, targetRequest, targetResponse);

        if (!targetResponse.hasNext()) return null;

        SearchResult targetEntry = targetResponse.next();
        if (log.isInfoEnabled()) log.info("Found target: "+targetEntry.getDn());

        return targetEntry;
    }

    public SearchResult searchTargetUser(Session session, SearchResult sourceEntry) throws Exception {

        SearchResult targetEntry = getLinkedUser(session, sourceEntry);

        if (targetEntry == null) {

            String normalizedSourceDn = sourceEntry.getDn().getNormalizedDn();
            String normalizedTargetDn = sourceDnMapping.get(normalizedSourceDn);

            if (normalizedTargetDn != null) {
                DN targetDn = targetDns.get(normalizedTargetDn);

                if (log.isInfoEnabled()) log.info("Searching target using static mapping: "+targetDn);

                SearchRequest targetRequest = new SearchRequest();
                targetRequest.setDn(targetDn);
                targetRequest.setScope(SearchRequest.SCOPE_BASE);

                SearchResponse targetResponse = new SearchResponse();

                target.search(session, targetRequest, targetResponse);

                if (targetResponse.hasNext()) {
                    targetEntry = targetResponse.next();
                    if (log.isInfoEnabled()) log.info("Found target: "+targetEntry.getDn());
                }
            }
        }

        if (targetEntry == null) {

            Attribute keyAttribute = sourceEntry.getAttribute(sourceKeyAttribute);
            if (keyAttribute != null) {

                String key = (String)keyAttribute.getValue();
                Filter filter = new SimpleFilter(targetKeyAttribute, "=", key);

                if (log.isInfoEnabled()) log.info("Searching target for "+filter);

                SearchRequest targetRequest = new SearchRequest();
                targetRequest.setFilter(filter);

                SearchResponse targetResponse = new SearchResponse();

                targetUsers.search(session, targetRequest, targetResponse);

                if (targetResponse.hasNext()) {
                    targetEntry = targetResponse.next();
                    if (log.isInfoEnabled()) log.info("Found target: "+targetEntry.getDn());
                }
            }
        }

        return targetEntry;
    }
}