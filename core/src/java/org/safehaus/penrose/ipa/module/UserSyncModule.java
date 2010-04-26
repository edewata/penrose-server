package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.changelog.ChangeLog;
import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ldap.source.LDAPSource;
import org.safehaus.penrose.util.TextUtil;
import org.safehaus.penrose.filter.*;
import org.safehaus.penrose.source.SourceManager;
import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.interpreter.Interpreter;
import org.ietf.ldap.LDAPException;

import java.util.*;

/**
 * @author Endi Sukma Dewata
 */
public class UserSyncModule extends SyncModule {

    protected LDAPSource sourceUsers;

    protected LDAPSource targetUsersFE;
    protected LDAPSource targetUsersBE;

    protected Map<String,DN> sourceDns = new LinkedHashMap<String,DN>();
    protected Map<String,String> sourceDnMapping = new LinkedHashMap<String,String>();
    protected Map<String,DN> targetDns = new LinkedHashMap<String,DN>();
    protected Map<String,String> targetDnMapping = new LinkedHashMap<String,String>();

    protected Set<String> ignoredDns = new HashSet<String>();

    public UserSyncModule() {
    }

    public void init() throws Exception {

        super.init();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing User Sync Module", 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();

        String sourceUsersName = getParameter("sourceUsers");
        sourceUsers = (LDAPSource)sourceManager.getSource(sourceUsersName);

        String targetUsersName = getParameter("targetUsers");
        if (targetUsersName == null) {
            String targetUsersFEName = getParameter("targetUsersFE");
            targetUsersFE = (LDAPSource)sourceManager.getSource(targetUsersFEName);

            String targetUsersBEName = getParameter("targetUsersBE");
            targetUsersBE = (LDAPSource)sourceManager.getSource(targetUsersBEName);

        } else {
            targetUsersFE = (LDAPSource)sourceManager.getSource(targetUsersName);
            targetUsersBE = targetUsersFE;
        }

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

    public Map<String,DN> getDns() throws Exception {
        final Session session = createAdminSession();

        try {
            final Map<String,DN> map = new TreeMap<String,DN>();

            SearchRequest sourceRequest = new SearchRequest();

            SearchResponse sourceResponse = new SearchResponse() {
                public void add(SearchResult result) throws Exception {
                    Attribute attribute = result.getAttribute(sourceKeyAttribute);
                    if (attribute == null) return;

                    Object value = attribute.getValue();
                    if (value == null) return;

                    map.put(value.toString(), result.getDn());
                }
            };

            sourceUsers.search(session, sourceRequest, sourceResponse);

            return map;

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public SearchResult getEntry(String key) throws Exception {
        final Session session = createAdminSession();

        try {
            return searchSourceUser(session, key);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void syncEntries() throws Exception {
        final Session session = createAdminSession();

        try {
            SearchRequest sourceRequest = new SearchRequest();

            SearchResponse sourceResponse = new SearchResponse() {
                public void add(SearchResult sourceEntry) throws Exception {
                    syncEntry(session, sourceEntry);
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

    public void syncEntry(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchResult sourceEntry = searchSourceUser(session, key);
            syncEntry(session, sourceEntry);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void linkEntry(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchResult sourceEntry = searchSourceUser(session, key);
            if (sourceEntry == null) return;

            SearchResult targetEntry = searchTargetUser(session, sourceEntry);
            if (targetEntry == null) return;

            linkEntry(session, sourceEntry, targetEntry);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void unlinkEntry(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchResult sourceEntry = searchSourceUser(session, key);
            if (sourceEntry == null) return;

            SearchResult targetEntry = getTargetUser(session, sourceEntry);

            unlinkEntry(session, sourceEntry, targetEntry);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void deleteEntry(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchResult sourceEntry = searchSourceUser(session, key);
            deleteEntry(session, sourceEntry);

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

    public SearchResult syncEntry(Session session, SearchResult sourceEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        if (log.isInfoEnabled()) log.info("Synchronizing "+sourceDn);

        if (ignoredDns.contains(sourceDn.getNormalizedDn())) {
            if (log.isInfoEnabled()) log.info("Ignoring "+sourceDn);
            return null;
        }

        SearchResult targetEntry = getTargetUser(session, sourceEntry);

        if (targetEntry == null) {

            targetEntry = searchTargetUser(session, sourceEntry);

            if (targetEntry == null) {
                if (log.isInfoEnabled()) log.info("Adding "+sourceDn);
                targetEntry = addUser(session, sourceEntry);

            } else {
                if (log.isInfoEnabled()) log.info("Linking "+sourceDn);
                linkEntry(session, sourceEntry, targetEntry);
            }

        } else {
            if (log.isInfoEnabled()) log.info("Syncing "+sourceDn);
            syncUser(session, sourceEntry, targetEntry);
        }

        return targetEntry;
    }

    public void deleteEntry(Session session, SearchResult sourceEntry) throws Exception {

        Object link = getSourceLink(sourceEntry);
        if (link != null) {
            deleteTargetUser(session, link);
        }

        DN sourceDn = sourceEntry.getDn();
        if (log.isInfoEnabled()) log.info("Deleting source user "+sourceDn);
        source.delete(session, sourceDn);
    }

    public void deleteTargetUser(Session session, Object link) throws Exception {

        SearchResult targetEntry = getTargetUser(session, link);
        if (targetEntry == null) return;

        DN targetDn = targetEntry.getDn();
        deleteTargetUser(session, targetDn);
    }

    public void deleteTargetUser(Session session, DN targetDn) throws Exception {
        if (log.isInfoEnabled()) log.info("Deleting target user "+targetDn);
        targetFE.delete(session, targetDn);
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
        interpreter.set(sourceAlias, sourceAttributes);

        targetImportMapping.map(interpreter, targetAttributes);

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
                targetFE.add(session, addRequest, addResponse);
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
                    throw e;
                }
            }
        }

        SearchResult targetResult = targetUsersFE.find(session, targetDn);
        targetAttributes = targetResult.getAttributes();

        if (sourceImportMapping == null) return targetResult;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(targetAlias, targetAttributes);

        sourceImportMapping.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse modifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, modifyResponse);
        }

        return targetResult;
    }

    public void linkEntry(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

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
        interpreter.set(sourceAlias, sourceAttributes);

        targetLinkMapping.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            targetFE.modify(session, targetModifyRequest, targetModifyResponse);
        }

        if (sourceLinkMapping == null) return;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(targetAlias, targetAttributes);

        sourceLinkMapping.map(interpreter, sourceAttributes, sourceModifyRequest);

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
        interpreter.set(sourceAlias, sourceAttributes);

        targetSyncMapping.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            targetFE.modify(session, targetModifyRequest, targetModifyResponse);
        }

        if (sourceSyncMapping == null) return;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(targetAlias, targetAttributes);

        sourceSyncMapping.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    public void modifyEntry(Session session, DN sourceDn, Collection<Modification> modifications) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("MODIFY USER", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
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

        SearchResult sourceEntry = source.find(session, sourceDn);
        SearchResult targetEntry = getTargetUser(session, sourceEntry);
        if (targetEntry == null) return;

        ModifyRequest modifyRequest = new ModifyRequest();
        modifyRequest.setDn(targetEntry.getDn());

        modifyRequest.addModification(new Modification(
                Modification.REPLACE,
                new Attribute("userPassword", userPassword)
        ));

        ModifyResponse modifyResponse = new ModifyResponse();

        targetFE.modify(session, modifyRequest, modifyResponse);
    }

    public void unlinkEntry(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        DN targetDn = null;
        Attributes targetAttributes = null;

        if (targetEntry != null) {
            targetDn = targetEntry.getDn();
            targetAttributes = targetEntry.getAttributes();
        }

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("UNLINK USER", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        log.debug("");

        if (targetUnlinkMapping != null && targetEntry != null) {

            ModifyRequest targetModifyRequest = new ModifyRequest();
            targetModifyRequest.setDn(targetDn);

            Interpreter interpreter = partition.newInterpreter();
            interpreter.set("session", session);
            interpreter.set("module", this);
            interpreter.set(sourceAlias, sourceAttributes);

            targetUnlinkMapping.map(interpreter, targetAttributes, targetModifyRequest);

            if (!targetModifyRequest.isEmpty()) {
                ModifyResponse targetModifyResponse = new ModifyResponse();

                targetFE.modify(session, targetModifyRequest, targetModifyResponse);
            }
        }

        if (sourceUnlinkMapping != null) {

            ModifyRequest sourceModifyRequest = new ModifyRequest();
            sourceModifyRequest.setDn(sourceDn);

            Interpreter interpreter = partition.newInterpreter();
            interpreter.set("session", session);
            interpreter.set("module", this);
            if (targetEntry != null) interpreter.set(targetAlias, targetAttributes);

            sourceUnlinkMapping.map(interpreter, sourceAttributes, sourceModifyRequest);

            if (!sourceModifyRequest.isEmpty()) {
                ModifyResponse sourceModifyResponse = new ModifyResponse();

                source.modify(session, sourceModifyRequest, sourceModifyResponse);
            }
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

    public Object getSourceLink(SearchResult sourceEntry) {
        Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);
        if (linkAttribute == null) return null;

        return linkAttribute.getValue();
    }

    public SearchResult getSourceUser(Session session, Object link) throws Exception {

        Filter filter = new SimpleFilter(sourceLinkAttribute, "=", link);
        if (log.isInfoEnabled()) log.info("Searching source for "+filter);

        SearchRequest sourceRequest = new SearchRequest();
        sourceRequest.setFilter(filter);

        SearchResponse sourceResponse = new SearchResponse();

        sourceUsers.search(session, sourceRequest, sourceResponse);

        if (!sourceResponse.hasNext()) return null;

        SearchResult sourceEntry = sourceResponse.next();
        if (log.isInfoEnabled()) log.info("Found source: "+sourceEntry.getDn());

        return sourceEntry;
    }

    public Object getTargetLink(SearchResult targetEntry) {
        Attribute linkAttribute = targetEntry.getAttribute(targetLinkAttribute);
        if (linkAttribute == null) return null;

        return linkAttribute.getValue();
    }

    public SearchResult getTargetUser(Session session, SearchResult sourceEntry) throws Exception {

        Object link = getSourceLink(sourceEntry);
        if (link == null) return null;

        return getTargetUser(session, link);
    }

    public SearchResult getTargetUser(Session session, Object link) throws Exception {
    
        Filter filter = new SimpleFilter(targetLinkAttribute, "=", link);
        if (log.isInfoEnabled()) log.info("Searching target for "+filter);

        SearchRequest targetRequest = new SearchRequest();
        targetRequest.setFilter(filter);

        SearchResponse targetResponse = new SearchResponse();

        targetUsersFE.search(session, targetRequest, targetResponse);

        if (!targetResponse.hasNext()) return null;

        SearchResult targetEntry = targetResponse.next();
        if (log.isInfoEnabled()) log.info("Found target: "+targetEntry.getDn());

        return targetEntry;
    }

    public SearchResult searchTargetUser(Session session, SearchResult sourceEntry) throws Exception {

        SearchResult targetEntry = getTargetUser(session, sourceEntry);

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

                targetUsersFE.search(session, targetRequest, targetResponse);

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

                targetUsersFE.search(session, targetRequest, targetResponse);

                if (targetResponse.hasNext()) {
                    targetEntry = targetResponse.next();
                    if (log.isInfoEnabled()) log.info("Found target: "+targetEntry.getDn());
                }
            }
        }

        return targetEntry;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Change Log
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void sync(Session session, SearchResult searchResult) throws Exception {

        Attributes attributes = searchResult.getAttributes();

        DN targetDn = new DN((String)attributes.getValue("targetDn"));
        String changeType = (String)attributes.getValue("changeType");
        String changes = (String)attributes.getValue("changes");
        Object link = attributes.getValue("targetUniqueId");

        if (changeType.equals("add")) {
            Attributes changeAttributes = ChangeLog.parseAttributes(changes);
            changeAttributes.addValue("nsUniqueId", link);
            addUser(session, targetDn, changeAttributes);

        } else if (changeType.equals("modify")) {
            Collection<Modification> modifications = ChangeLog.parseModifications(changes);
            modifyEntry(session, targetDn, modifications);

        } else if (changeType.equals("delete")) {
            deleteTargetUser(session, link);
        }
    }
}
