package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ldap.connection.LDAPConnection;
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
public class IPAUserModule extends Module {

    LDAPSource source;
    LDAPConnection sourceConnection;

    String sourceKeyAttribute;
    String sourceLinkAttribute;

    LDAPSource sourceUsers;

    Mapping importSourceUserMapping;
    Mapping importSourceUserMapping2;

    Mapping linkSourceUserMapping;
    Mapping linkSourceUserMapping2;

    Mapping syncSourceUserMapping;
    Mapping syncSourceUserMapping2;

    Mapping unlinkSourceUserMapping;
    Mapping unlinkSourceUserMapping2;

    LDAPSource target;
    LDAPConnection targetConnection;

    String targetKeyAttribute;
    String targetLinkAttribute;

    LDAPSource targetUsers;

    Mapping importTargetUserMapping;
    Mapping importTargetUserMapping2;

    Mapping linkTargetUserMapping;
    Mapping linkTargetUserMapping2;

    Mapping syncTargetUserMapping;
    Mapping syncTargetUserMapping2;

    String sourceDomain;

    Map<String,DN> sourceDns = new LinkedHashMap<String,DN>();
    Map<String,String> sourceDnMapping = new LinkedHashMap<String,String>();

    Map<String,DN> targetDns = new LinkedHashMap<String,DN>();
    Map<String,String> targetDnMapping = new LinkedHashMap<String,String>();

    Set<String> ignoredSourceDns = new HashSet<String>();
    Set<String> ignoredTargetDns = new HashSet<String>();

    public IPAUserModule() {
    }

    public void init() throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing IPA User Module", 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();
        MappingManager mappingManager = partition.getMappingManager();

        String sourceName = getParameter("source");
        source = (LDAPSource)sourceManager.getSource(sourceName);
        sourceConnection = (LDAPConnection)source.getConnection();

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
        targetConnection = (LDAPConnection)target.getConnection();

        String targetUsersName = getParameter("targetUsers");
        targetUsers = (LDAPSource)sourceManager.getSource(targetUsersName);

        targetKeyAttribute = getParameter("targetKeyAttribute");
        targetLinkAttribute = getParameter("targetLinkAttribute");

        String importTargetUserMappingName = getParameter("importTargetUserMapping");
        importTargetUserMapping = mappingManager.getMapping(importTargetUserMappingName);

        String importTargetUserMapping2Name = getParameter("importTargetUserMapping2");
        importTargetUserMapping2 = mappingManager.getMapping(importTargetUserMapping2Name);

        String linkTargetUserMappingName = getParameter("linkTargetUserMapping");
        linkTargetUserMapping = mappingManager.getMapping(linkTargetUserMappingName);

        String linkTargetUserMapping2Name = getParameter("linkTargetUserMapping2");
        linkTargetUserMapping2 = mappingManager.getMapping(linkTargetUserMapping2Name);

        String syncTargetUserMappingName = getParameter("syncTargetUserMapping");
        syncTargetUserMapping = mappingManager.getMapping(syncTargetUserMappingName);

        String syncTargetUserMapping2Name = getParameter("syncTargetUserMapping2");
        syncTargetUserMapping2 = mappingManager.getMapping(syncTargetUserMapping2Name);

        StringBuilder sb = new StringBuilder();
        for (RDN rdn : source.getBaseDn().getRdns()) {
            if (sb.length() != 0) {
                sb.append(".");
            }
            sb.append(rdn.getValue());
        }
        sourceDomain = sb.toString();
/*
        DN sourceAdminDn = new DN("uid=admin,cn=users,cn=accounts").append(source.getBaseDn());
        DN targetAdminDn = new DN("CN=Administrator,CN=Users").append(target.getBaseDn());

        sourceDns.put(sourceAdminDn.getNormalizedDn(), sourceAdminDn);
        sourceDnMapping.put(sourceAdminDn.getNormalizedDn(), targetAdminDn.getNormalizedDn());

        targetDns.put(targetAdminDn.getNormalizedDn(), targetAdminDn);
        targetDnMapping.put(targetAdminDn.getNormalizedDn(), sourceAdminDn.getNormalizedDn());
*/
        DN targetSyncDn = new DN("CN=Sync,CN=Users").append(target.getBaseDn());
        ignoredTargetDns.add(targetSyncDn.getNormalizedDn());
    }

    public void destroy() throws Exception {
    }

    public void syncUsers() throws Exception {
        final Session session = createAdminSession();

        try {
            SearchRequest sourceRequest = new SearchRequest();

            SearchResponse sourceResponse = new SearchResponse() {
                public void add(SearchResult sourceEntry) throws Exception {

                    DN sourceDn = sourceEntry.getDn();
                    if (log.isInfoEnabled()) log.info("Initializing "+sourceDn);

                    if (ignoredSourceDns.contains(sourceDn.getNormalizedDn())) {
                        if (log.isInfoEnabled()) log.info("Ignoring "+sourceDn);
                        return;
                    }

                    SearchResult targetEntry = findTargetUser(session, sourceEntry);

                    if (targetEntry == null) {
                        if (log.isInfoEnabled()) log.info("Adding "+sourceDn);
                        importSourceUser(session, sourceEntry);

                    } else {
                        Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);

                        if (linkAttribute == null) {
                            if (log.isInfoEnabled()) log.info("Linking "+sourceEntry.getDn());
                            linkSourceUser(session, sourceEntry, targetEntry);

                        } else {
                            if (log.isInfoEnabled()) log.info("Syncing "+sourceEntry.getDn());
                            syncSourceUser(session, sourceEntry, targetEntry);
                        }
                    }
                }
            };

            sourceUsers.search(session, sourceRequest, sourceResponse);

            SearchRequest targetRequest = new SearchRequest();

            SearchResponse targetResponse = new SearchResponse() {
                public void add(SearchResult targetEntry) throws Exception {

                    DN targetDn = targetEntry.getDn();
                    if (log.isInfoEnabled()) log.info("Initializing "+targetDn);

                    if (ignoredTargetDns.contains(targetDn.getNormalizedDn())) {
                        if (log.isInfoEnabled()) log.info("Ignoring "+targetDn);
                        return;
                    }

                    SearchResult sourceEntry = findSourceUser(session, targetEntry);

                    if (sourceEntry == null) {
                        if (log.isInfoEnabled()) log.info("Adding "+targetDn);
                        importTargetUser(session, targetEntry);

                    } else {
                        if (log.isInfoEnabled()) log.info("Skipping "+targetDn);
                    }
                }
            };

            targetUsers.search(session, targetRequest, targetResponse);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void syncSourceUsers() throws Exception {
        final Session session = createAdminSession();

        try {
            SearchRequest sourceRequest = new SearchRequest();

            SearchResponse sourceResponse = new SearchResponse() {
                public void add(SearchResult sourceEntry) throws Exception {

                    DN sourceDn = sourceEntry.getDn();
                    if (log.isInfoEnabled()) log.info("Initializing "+sourceDn);

                    if (ignoredSourceDns.contains(sourceDn.getNormalizedDn())) {
                        if (log.isInfoEnabled()) log.info("Ignoring "+sourceDn);
                        return;
                    }

                    SearchResult targetEntry = findTargetUser(session, sourceEntry);

                    if (targetEntry == null) {
                        if (log.isInfoEnabled()) log.info("Adding "+sourceDn);
                        importSourceUser(session, sourceEntry);

                    } else {
                        Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);

                        if (linkAttribute == null) {
                            if (log.isInfoEnabled()) log.info("Linking "+sourceEntry.getDn());
                            linkSourceUser(session, sourceEntry, targetEntry);

                        } else {
                            if (log.isInfoEnabled()) log.info("Syncing "+sourceEntry.getDn());
                            syncSourceUser(session, sourceEntry, targetEntry);
                        }
                    }
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

    public void syncTargetUsers() throws Exception {
        final Session session = createAdminSession();

        try {
            SearchRequest targetRequest = new SearchRequest();

            SearchResponse targetResponse = new SearchResponse() {
                public void add(SearchResult targetEntry) throws Exception {

                    DN targetDn = targetEntry.getDn();
                    if (log.isInfoEnabled()) log.info("Initializing "+targetDn);

                    if (ignoredTargetDns.contains(targetDn.getNormalizedDn())) {
                        if (log.isInfoEnabled()) log.info("Ignoring "+targetDn);
                        return;
                    }

                    SearchResult sourceEntry = findSourceUser(session, targetEntry);

                    if (sourceEntry == null) {
                        if (log.isInfoEnabled()) log.info("Adding "+targetDn);
                        importTargetUser(session, targetEntry);

                    } else {
                        Attribute linkAttribute = targetEntry.getAttribute(targetLinkAttribute);

                        if (linkAttribute == null) {
                            if (log.isInfoEnabled()) log.info("Linking "+targetEntry.getDn());
                            linkTargetUser(session, targetEntry, sourceEntry);

                        } else {
                            if (log.isInfoEnabled()) log.info("Syncing "+targetEntry.getDn());
                            syncTargetUser(session, targetEntry, sourceEntry);
                        }
                    }
                }
            };

            targetUsers.search(session, targetRequest, targetResponse);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void syncSourceUser(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            Filter filter = new SimpleFilter(sourceKeyAttribute, "=", key);

            if (log.isInfoEnabled()) log.info("Searching source for "+filter);

            SearchRequest sourceRequest = new SearchRequest();
            sourceRequest.setFilter(filter);

            SearchResponse sourceResponse = new SearchResponse();

            sourceUsers.search(session, sourceRequest, sourceResponse);

            if (!sourceResponse.hasNext()) {
                if (log.isInfoEnabled()) log.info("Entry not found.");
                throw new Exception("Entry not found.");
            }

            SearchResult sourceEntry = sourceResponse.next();
            if (log.isInfoEnabled()) log.info("Synchronizing "+sourceEntry.getDn());

            SearchResult targetEntry = findTargetUser(session, sourceEntry);

            if (targetEntry == null) {
                if (log.isInfoEnabled()) log.info("Adding "+sourceEntry.getDn());
                importSourceUser(session, sourceEntry);

            } else {
                Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);

                if (linkAttribute == null) {
                    if (log.isInfoEnabled()) log.info("Linking "+sourceEntry.getDn());
                    linkSourceUser(session, sourceEntry, targetEntry);
                    
                } else {
                    if (log.isInfoEnabled()) log.info("Syncing "+sourceEntry.getDn());
                    syncSourceUser(session, sourceEntry, targetEntry);
                }
            }

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void syncTargetUser(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            Filter filter = new SimpleFilter(targetKeyAttribute, "=", key);

            if (log.isInfoEnabled()) log.info("Searching target for "+filter);

            SearchRequest targetRequest = new SearchRequest();
            targetRequest.setFilter(filter);

            SearchResponse targetResponse = new SearchResponse();

            targetUsers.search(session, targetRequest, targetResponse);

            if (!targetResponse.hasNext()) {
                if (log.isInfoEnabled()) log.info("Entry not found.");
                throw new Exception("Entry not found.");
            }

            SearchResult targetEntry = targetResponse.next();
            if (log.isInfoEnabled()) log.info("Synchronizing "+targetEntry.getDn());

            SearchResult sourceEntry = findSourceUser(session, targetEntry);

            if (sourceEntry == null) {
                if (log.isInfoEnabled()) log.info("Adding "+targetEntry.getDn());
                importTargetUser(session, targetEntry);

            } else {
                Attribute linkAttribute = sourceEntry.getAttribute(targetLinkAttribute);

                if (linkAttribute == null) {
                    if (log.isInfoEnabled()) log.info("Linking "+targetEntry.getDn());
                    linkTargetUser(session, targetEntry, sourceEntry);

                } else {
                    if (log.isInfoEnabled()) log.info("Syncing "+targetEntry.getDn());
                    syncTargetUser(session, targetEntry, sourceEntry);
                }
            }

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void unlinkSourceUser(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            Filter filter = new SimpleFilter(sourceKeyAttribute, "=", key);

            if (log.isInfoEnabled()) log.info("Searching source for "+filter);

            SearchRequest sourceRequest = new SearchRequest();
            sourceRequest.setFilter(filter);

            SearchResponse sourceResponse = new SearchResponse();

            sourceUsers.search(session, sourceRequest, sourceResponse);

            if (!sourceResponse.hasNext()) {
                if (log.isInfoEnabled()) log.info("Entry not found.");
                throw new Exception("Entry not found.");
            }

            SearchResult sourceEntry = sourceResponse.next();
            if (log.isInfoEnabled()) log.info("Unlinking "+sourceEntry.getDn());

            Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);

            if (linkAttribute == null) {
                if (log.isInfoEnabled()) log.info("Entry not linked.");

            } else {
                SearchResult targetEntry = findTargetUser(session, sourceEntry);
                if (log.isInfoEnabled()) log.info("Unlinking "+(targetEntry == null ? null : targetEntry.getDn()));
                unlinkSourceUser(session, sourceEntry, targetEntry);
            }

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public SearchResult findSourceUser(Session session, SearchResult targetEntry) throws Exception {

        SearchResult sourceEntry = null;

        Attribute linkAttribute = targetEntry.getAttribute(targetLinkAttribute);
        if (linkAttribute != null) {

            Object link = linkAttribute.getValue();
            Filter filter = new SimpleFilter(sourceLinkAttribute, "=", link);

            if (log.isInfoEnabled()) log.info("Searching source for "+filter);

            SearchRequest sourceRequest = new SearchRequest();
            sourceRequest.setFilter(filter);

            SearchResponse sourceResponse = new SearchResponse();

            sourceUsers.search(session, sourceRequest, sourceResponse);

            if (sourceResponse.hasNext()) {
                sourceEntry = sourceResponse.next();
                if (log.isInfoEnabled()) log.info("Found source: "+sourceEntry.getDn());
            }
        }

        if (sourceEntry == null) {
            String normalizedTargetDn = targetEntry.getDn().getNormalizedDn();
            String normalizedSourceDn = targetDnMapping.get(normalizedTargetDn);

            if (normalizedSourceDn != null) {
                DN sourceDn = sourceDns.get(normalizedSourceDn);

                if (log.isInfoEnabled()) log.info("Searching source using static mapping: "+sourceDn);

                SearchRequest sourceRequest = new SearchRequest();
                sourceRequest.setDn(sourceDn);
                sourceRequest.setScope(SearchRequest.SCOPE_BASE);

                SearchResponse sourceResponse = new SearchResponse();

                source.search(session, sourceRequest, sourceResponse);

                if (sourceResponse.hasNext()) {
                    sourceEntry = sourceResponse.next();
                    if (log.isInfoEnabled()) log.info("Found source: "+sourceEntry.getDn());
                }
            }
        }

        if (sourceEntry == null) {

            Attribute keyAttribute = targetEntry.getAttribute(targetKeyAttribute);
            if (keyAttribute != null) {

                String key = (String)keyAttribute.getValue();
                Filter filter =new SimpleFilter(sourceKeyAttribute, "=", key);

                if (log.isInfoEnabled()) log.info("Searching source for "+filter);

                SearchRequest sourceRequest = new SearchRequest();
                sourceRequest.setFilter(filter);

                SearchResponse sourceResponse = new SearchResponse();

                sourceUsers.search(session, sourceRequest, sourceResponse);

                if (sourceResponse.hasNext()) {
                    sourceEntry = sourceResponse.next();
                    if (log.isInfoEnabled()) log.info("Found source: "+sourceEntry.getDn());
                }
            }
        }

        return sourceEntry;
    }

    public SearchResult findTargetUser(Session session, SearchResult sourceEntry) throws Exception {

        SearchResult targetEntry = null;

        Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);
        if (linkAttribute != null) {

            Object link = linkAttribute.getValue();
            Filter filter = new SimpleFilter(targetLinkAttribute, "=", link);

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

    public void importSourceUser(Session session, SearchResult sourceEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        String normalizedSourceDn = sourceDn.getNormalizedDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("IMPORT SOURCE USER", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        sourceAttributes.print();

        log.debug("");

        Attributes targetAttributes = new Attributes();

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set("ipa", sourceAttributes);

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

        if (importSourceUserMapping2 == null) return;

        SearchResult targetResult = target.find(session, targetDn);
        targetAttributes = targetResult.getAttributes();

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set("samba", targetAttributes);

        importSourceUserMapping2.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse modifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, modifyResponse);
        }
    }

    public void linkSourceUser(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("LINK SOURCE USER", 60));
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
        interpreter.set("ipa", sourceAttributes);

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
        interpreter.set("samba", targetAttributes);

        linkSourceUserMapping2.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    public void unlinkSourceUser(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("UNLINK SOURCE USER", 60));
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
            interpreter.set("ipa", sourceAttributes);

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
        if (targetEntry != null) interpreter.set("samba", targetAttributes);

        unlinkSourceUserMapping2.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    public void syncSourceUser(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("SYNC SOURCE USER", 60));
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
        interpreter.set("ipa", sourceAttributes);

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
        interpreter.set("samba", targetAttributes);

        syncSourceUserMapping2.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    public void importTargetUser(Session session, SearchResult targetEntry) throws Exception {

        DN targetDn = targetEntry.getDn();
        String normalizedTargetDn = targetDn.getNormalizedDn();
        Attributes targetAttributes = targetEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("IMPORT TARGET USER", 60));
        log.debug(TextUtil.displayLine(" - "+targetDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        targetAttributes.print();

        log.debug("");

        Attributes sourceAttributes = new Attributes();

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set("samba", targetAttributes);

        importTargetUserMapping.map(interpreter, sourceAttributes);

        String normalizedSourceDn = targetDnMapping.get(normalizedTargetDn);
        DN sourceDn = targetDns.get(normalizedSourceDn);

        Attribute dnAttribute = sourceAttributes.remove("dn");
        if (sourceDn == null) {
            sourceDn = new DN((String)dnAttribute.getValue());
        }

        AddRequest addRequest = new AddRequest();
        addRequest.setDn(sourceDn);
        addRequest.setAttributes(sourceAttributes);

        AddResponse addResponse = new AddResponse();

        source.add(session, addRequest, addResponse);

        if (importTargetUserMapping2 == null) return;

        SearchResult sourceResult = source.find(session, sourceDn);
        sourceAttributes = sourceResult.getAttributes();

        ModifyRequest targetModifyRequest = new ModifyRequest();
        targetModifyRequest.setDn(targetDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set("ipa", sourceAttributes);

        importTargetUserMapping2.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse modifyResponse = new ModifyResponse();

            target.modify(session, targetModifyRequest, modifyResponse);
        }
    }

    public void linkTargetUser(Session session, SearchResult targetEntry, SearchResult sourceEntry) throws Exception {

        DN targetDn = targetEntry.getDn();
        Attributes targetAttributes = targetEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("LINK TARGET USER", 60));
        log.debug(TextUtil.displayLine(" - "+targetDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        log.debug("");

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set("samba", targetAttributes);

        linkTargetUserMapping.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }

        if (linkTargetUserMapping2 == null) return;

        ModifyRequest targetModifyRequest = new ModifyRequest();
        targetModifyRequest.setDn(targetDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set("ipa", sourceAttributes);

        linkTargetUserMapping2.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            target.modify(session, targetModifyRequest, targetModifyResponse);
        }
    }

    public void syncTargetUser(Session session, SearchResult targetEntry, SearchResult sourceEntry) throws Exception {

        DN targetDn = targetEntry.getDn();
        Attributes targetAttributes = targetEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("SYNC TARGET USER", 60));
        log.debug(TextUtil.displayLine(" - "+targetDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        log.debug("");

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set("samba", targetAttributes);

        syncTargetUserMapping.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }

        if (syncTargetUserMapping2 == null) return;

        ModifyRequest targetModifyRequest = new ModifyRequest();
        targetModifyRequest.setDn(targetDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set("ipa", sourceAttributes);

        syncTargetUserMapping2.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            target.modify(session, targetModifyRequest, targetModifyResponse);
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
        Object key = rdn.get(sourceKeyAttribute);

        SearchRequest searchRequest = new SearchRequest();
        searchRequest.setDn(target.getBaseDn());
        searchRequest.setFilter("("+targetKeyAttribute+"="+key+")");

        SearchResponse searchResponse = new SearchResponse();

        target.search(session, searchRequest, searchResponse);

        if (!searchResponse.hasNext()) {
            log.debug("User not found.");
            return null;
        }

        return searchResponse.next();
    }
}