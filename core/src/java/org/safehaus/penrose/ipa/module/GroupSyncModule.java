package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.changelog.ChangeLog;
import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ldap.source.LDAPSource;
import org.safehaus.penrose.util.TextUtil;
import org.safehaus.penrose.source.SourceManager;
import org.safehaus.penrose.module.ModuleManager;
import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.interpreter.Interpreter;
import org.safehaus.penrose.filter.Filter;
import org.safehaus.penrose.filter.SimpleFilter;
import org.ietf.ldap.LDAPException;

import java.util.*;

/**
 * @author Endi Sukma Dewata
 */
public class GroupSyncModule extends SyncModule {

    protected LDAPSource sourceUsers;
    protected LDAPSource sourceGroups;

    protected LDAPSource targetGroups;

    protected Map<String,DN> sourceDns = new LinkedHashMap<String,DN>();
    protected Map<String,String> sourceDnMapping = new LinkedHashMap<String,String>();
    protected Map<String,DN> targetDns = new LinkedHashMap<String,DN>();
    protected Map<String,String> targetDnMapping = new LinkedHashMap<String,String>();

    protected Set<String> ignoredDns = new HashSet<String>();

    protected UserSyncModule userSyncModule;

    public GroupSyncModule() {
    }

    public void init() throws Exception {

        super.init();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing Group Sync Module", 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();
        ModuleManager moduleManager = partition.getModuleManager();

        String sourceUsersName = getParameter("sourceUsers");
        sourceUsers = (LDAPSource)sourceManager.getSource(sourceUsersName);

        String sourceGroupsName = getParameter("sourceGroups");
        sourceGroups = (LDAPSource)sourceManager.getSource(sourceGroupsName);

        String targetGroupsName = getParameter("targetGroups");
        targetGroups = (LDAPSource)sourceManager.getSource(targetGroupsName);

/*
        DN sourceAdminDn = new DN("cn=admins,cn=groups,cn=accounts").append(source.getBaseDn());
        DN targetAdminDn = new DN("CN=Administrators,CN=Builtin").append(target.getBaseDn());

        sourceDns.put(sourceAdminDn.getNormalizedDn(), sourceAdminDn);
        sourceDnMapping.put(sourceAdminDn.getNormalizedDn(), targetAdminDn.getNormalizedDn());

        targetDns.put(targetAdminDn.getNormalizedDn(), targetAdminDn);
        targetDnMapping.put(targetAdminDn.getNormalizedDn(), sourceAdminDn.getNormalizedDn());
*/
        String userSyncModuleName = getParameter("userSyncModule");
        userSyncModule = (UserSyncModule)moduleManager.getModule(userSyncModuleName);
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

            sourceGroups.search(session, sourceRequest, sourceResponse);

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
            return searchSourceGroup(session, key);

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

            sourceGroups.search(session, sourceRequest, sourceResponse);

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

            SearchResult sourceEntry = searchSourceGroup(session, key);
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

            SearchResult sourceEntry = searchSourceGroup(session, key);
            if (sourceEntry == null) return;

            SearchResult targetEntry = searchTargetGroup(session, sourceEntry);
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

            SearchResult sourceEntry = searchSourceGroup(session, key);
            unlinkEntry(session, sourceEntry);

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

            SearchResult sourceEntry = searchSourceGroup(session, key);
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

        SearchResult targetEntry = searchTargetGroup(session, sourceEntry);

        if (targetEntry == null) {
            if (log.isInfoEnabled()) log.info("Adding "+sourceDn);
            targetEntry = addGroup(session, sourceEntry);

        } else {
            if (log.isInfoEnabled()) log.info("Syncing "+sourceDn);
            syncGroup(session, sourceEntry, targetEntry);
        }

        return targetEntry;
    }

    public void unlinkEntry(Session session, SearchResult sourceEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        if (log.isInfoEnabled()) log.info("Unlinking "+sourceDn);

        SearchResult targetEntry = getTargetGroup(session, sourceEntry);
        if (targetEntry == null) return;

        unlinkGroup(session, sourceEntry, targetEntry);
    }

    public void deleteEntry(Session session, SearchResult sourceEntry) throws Exception {

        Object link = getSourceLink(sourceEntry);
        if (link != null) {
            deleteTargetGroup(session, link);
        }

        DN sourceDn = sourceEntry.getDn();
        if (log.isInfoEnabled()) log.info("Deleting source group "+sourceDn);
        source.delete(session, sourceDn);
    }

    public void deleteTargetGroup(Session session, Object link) throws Exception {

        SearchResult targetEntry = getTargetGroup(session, link);
        if (targetEntry == null) return;

        DN targetDn = targetEntry.getDn();
        if (log.isInfoEnabled()) log.info("Deleting target group "+targetDn);
        targetFE.delete(session, targetDn);
    }

    public SearchResult addGroup(Session session, SearchResult sourceEntry) throws Exception {
        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();
        return addGroup(session, sourceDn, sourceAttributes);
    }

    public SearchResult addGroup(Session session, DN sourceDn, Attributes sourceAttributes) throws Exception {

        String normalizedSourceDn = sourceDn.getNormalizedDn();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("ADD GROUP", 60));
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

        SearchResult targetResult = targetFE.find(session, targetDn);
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
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }

        return targetResult;
    }

    public void syncGroup(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("SYNC GROUP", 60));
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

    public void linkEntry(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("LINK GROUP", 60));
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

    public void unlinkGroup(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("UNLINK GROUP", 60));
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
            interpreter.set(sourceAlias, sourceAttributes);

            targetUnlinkMapping.map(interpreter, targetAttributes, targetModifyRequest);

            if (!targetModifyRequest.isEmpty()) {
                ModifyResponse targetModifyResponse = new ModifyResponse();

                targetFE.modify(session, targetModifyRequest, targetModifyResponse);
            }
        }

        if (sourceUnlinkMapping == null) return;

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

    public void modifyGroup(Session session, DN sourceDn, Collection<Modification> modifications) throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("MODIFY GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
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

        SearchResult sourceEntry = source.find(session, sourceDn);
        SearchResult targetEntry = getTargetGroup(session, sourceEntry);
        if (targetEntry == null) return;

        ModifyRequest modifyRequest = new ModifyRequest();
        modifyRequest.setDn(targetEntry.getDn());

        Attribute attribute = memberModification.getAttribute();
        for (Object value : attribute.getValues()) {

            DN sourceMemberDn = new DN(value.toString());
            DN targetMemberDn = transformSourceMember(session, sourceMemberDn);
            if (targetMemberDn == null) continue;

            modifyRequest.addModification(new Modification(
                    memberModification.getType(),
                    new Attribute("member", targetMemberDn.toString())
            ));
        }

        ModifyResponse modifyResponse = new ModifyResponse();

        targetFE.modify(session, modifyRequest, modifyResponse);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Helper Methods
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public SearchResult searchSourceGroup(Session session, String key) throws Exception {

        Filter filter = new SimpleFilter(sourceKeyAttribute, "=", key);
        if (log.isInfoEnabled()) log.info("Searching source for "+filter);

        SearchRequest sourceRequest = new SearchRequest();
        sourceRequest.setFilter(filter);

        SearchResponse sourceResponse = new SearchResponse();

        sourceGroups.search(session, sourceRequest, sourceResponse);

        if (!sourceResponse.hasNext()) {
            throw new Exception("Group with "+filter+" not found.");
        }

        return sourceResponse.next();
    }

    public Object getSourceLink(SearchResult sourceEntry) {
        Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);
        if (linkAttribute == null) return null;

        return linkAttribute.getValue();
    }

    public SearchResult getSourceGroup(Session session, Object link) throws Exception {

        Filter filter = new SimpleFilter(sourceLinkAttribute, "=", link);
        if (log.isInfoEnabled()) log.info("Searching source for "+filter);

        SearchRequest sourceRequest = new SearchRequest();
        sourceRequest.setFilter(filter);

        SearchResponse sourceResponse = new SearchResponse();

        sourceGroups.search(session, sourceRequest, sourceResponse);

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

    public SearchResult getTargetGroup(Session session, SearchResult sourceEntry) throws Exception {

        Object link = getSourceLink(sourceEntry);
        if (link == null) return null;

        return getTargetGroup(session, link);
    }

    public SearchResult getTargetGroup(Session session, Object link) throws Exception {

        Filter filter = new SimpleFilter(targetLinkAttribute, "=", link);
        if (log.isInfoEnabled()) log.info("Searching target for "+filter);

        SearchRequest targetRequest = new SearchRequest();
        targetRequest.setFilter(filter);

        SearchResponse targetResponse = new SearchResponse();

        targetGroups.search(session, targetRequest, targetResponse);

        if (!targetResponse.hasNext()) return null;

        SearchResult targetEntry = targetResponse.next();
        if (log.isInfoEnabled()) log.info("Found target: "+targetEntry.getDn());

        return targetEntry;
    }

    public SearchResult searchTargetGroup(Session session, SearchResult sourceEntry) throws Exception {

        SearchResult targetEntry = getTargetGroup(session, sourceEntry);

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

                targetGroups.search(session, targetRequest, targetResponse);

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

                targetGroups.search(session, targetRequest, targetResponse);

                if (targetResponse.hasNext()) {
                    targetEntry = targetResponse.next();
                    if (log.isInfoEnabled()) log.info("Found target: "+targetEntry.getDn());
                }
            }
        }

        return targetEntry;
    }

    public Collection<Object> transformSourceMembers(Session session, Object object) throws Exception {
        Collection<Object> input;

        if (object == null) {
            return null;

        } else if (object instanceof Collection) {
            input = (Collection<Object>)object;

        } else {
            input = new ArrayList<Object>();
            input.add(object);
        }

        Collection<Object> output = new ArrayList<Object>();

        for (Object value : input) {
            if (value instanceof DN) {
                DN sourceMemberDn = (DN)value;
                DN targetMemberDn = transformSourceMember(session, sourceMemberDn);
                if (targetMemberDn != null) output.add(targetMemberDn);
            } else {
                String sourceMemberDn = value.toString();
                String targetMemberDn = transformSourceMember(session, sourceMemberDn);
                if (targetMemberDn != null) output.add(targetMemberDn);
            }
        }

        return output;
    }

    public String transformSourceMember(Session session, String sourceMemberDn) throws Exception {
        DN targetMemberDn = transformSourceMember(session, new DN(sourceMemberDn));
        return targetMemberDn == null ? null : targetMemberDn.toString();
    }

    public DN transformSourceMember(Session session, DN sourceMemberDn) throws Exception {
        if (log.isInfoEnabled()) log.info("Transforming source member: "+sourceMemberDn);

        SearchResult sourceMemberEntry = sourceUsers.find(session, sourceMemberDn);
        if (sourceMemberEntry == null) {
            if (log.isDebugEnabled()) log.debug("==> Source member not found.");
            return null;
        }

        SearchResult targetMemberEntry = userSyncModule.getTargetUser(session, sourceMemberEntry);
        if (targetMemberEntry == null) {
            if (log.isDebugEnabled()) log.debug("==> Target member not found.");

            Attribute objectClass = sourceMemberEntry.getAttribute("objectClass");
            if (objectClass.containsValue("person")) {
                targetMemberEntry = userSyncModule.syncEntry(session, sourceMemberEntry);

            } else if (objectClass.containsValue("groupOfNames")) {
                targetMemberEntry = syncEntry(session, sourceMemberEntry);

            } else {
                return null;
            }
        }

        if (targetMemberEntry == null) return null;
        
        DN targetMemberDn = targetMemberEntry.getDn();
        if (log.isInfoEnabled()) log.info("==> Target member: "+targetMemberDn);

        return targetMemberDn;
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
            addGroup(session, targetDn, changeAttributes);

        } else if (changeType.equals("modify")) {
            Collection<Modification> modifications = ChangeLog.parseModifications(changes);
            modifyGroup(session, targetDn, modifications);

        } else if (changeType.equals("delete")) {
            deleteTargetGroup(session, link);
        }
    }
}