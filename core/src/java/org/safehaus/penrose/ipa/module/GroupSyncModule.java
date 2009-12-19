package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ldap.source.LDAPSource;
import org.safehaus.penrose.util.TextUtil;
import org.safehaus.penrose.source.SourceManager;
import org.safehaus.penrose.module.Module;
import org.safehaus.penrose.module.ModuleManager;
import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.mapping.Mapping;
import org.safehaus.penrose.mapping.MappingManager;
import org.safehaus.penrose.interpreter.Interpreter;
import org.safehaus.penrose.filter.Filter;
import org.safehaus.penrose.filter.SimpleFilter;
import org.ietf.ldap.LDAPException;

import java.util.*;

/**
 * @author Endi Sukma Dewata
 */
public class GroupSyncModule extends Module {

    protected String sourceAlias;
    protected LDAPSource source;
    protected LDAPSource sourceUsers;
    protected LDAPSource sourceGroups;

    protected String targetAlias;
    protected LDAPSource target;
    protected LDAPSource targetGroups;

    protected String sourceKeyAttribute;
    protected String sourceLinkAttribute;
    protected String targetKeyAttribute;
    protected String targetLinkAttribute;

    protected Mapping importSourceGroupMapping;
    protected Mapping importTargetGroupMapping;
    protected Mapping linkSourceGroupMapping;
    protected Mapping linkTargetGroupMapping;
    protected Mapping syncSourceGroupMapping;
    protected Mapping syncTargetGroupMapping;
    protected Mapping unlinkSourceGroupMapping;
    protected Mapping unlinkTargetGroupMapping;

    protected Map<String,DN> sourceDns = new LinkedHashMap<String,DN>();
    protected Map<String,String> sourceDnMapping = new LinkedHashMap<String,String>();
    protected Map<String,DN> targetDns = new LinkedHashMap<String,DN>();
    protected Map<String,String> targetDnMapping = new LinkedHashMap<String,String>();

    protected Set<String> ignoredDns = new HashSet<String>();

    protected UserSyncModule userSyncModule;

    public GroupSyncModule() {
    }

    public void init() throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing IPA Group Module", 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();
        MappingManager mappingManager = partition.getMappingManager();
        ModuleManager moduleManager = partition.getModuleManager();

        String sourceName = getParameter("source");
        source = (LDAPSource)sourceManager.getSource(sourceName);

        sourceAlias = getParameter("sourceAlias");
        if (sourceAlias == null) {
            sourceAlias = source.getName();
        }

        String sourceUsersName = getParameter("sourceUsers");
        sourceUsers = (LDAPSource)sourceManager.getSource(sourceUsersName);

        String sourceGroupsName = getParameter("sourceGroups");
        sourceGroups = (LDAPSource)sourceManager.getSource(sourceGroupsName);

        sourceKeyAttribute = getParameter("sourceKeyAttribute");
        sourceLinkAttribute = getParameter("sourceLinkAttribute");

        String importSourceGroupMappingName = getParameter("importSourceGroupMapping");
        importSourceGroupMapping = mappingManager.getMapping(importSourceGroupMappingName);

        String importTargetGroupMappingName = getParameter("importTargetGroupMapping");
        importTargetGroupMapping = mappingManager.getMapping(importTargetGroupMappingName);

        String linkSourceGroupMappingName = getParameter("linkSourceGroupMapping");
        linkSourceGroupMapping = mappingManager.getMapping(linkSourceGroupMappingName);

        String linkTargetGroupMappingName = getParameter("linkTargetGroupMapping");
        linkTargetGroupMapping = mappingManager.getMapping(linkTargetGroupMappingName);

        String syncSourceGroupMappingName = getParameter("syncSourceGroupMapping");
        syncSourceGroupMapping = mappingManager.getMapping(syncSourceGroupMappingName);

        String syncTargetGroupMappingName = getParameter("syncTargetGroupMapping");
        syncTargetGroupMapping = mappingManager.getMapping(syncTargetGroupMappingName);

        String unlinkSourceGroupMappingName = getParameter("unlinkSourceGroupMapping");
        unlinkSourceGroupMapping = mappingManager.getMapping(unlinkSourceGroupMappingName);

        String unlinkTargetGroupMappingName = getParameter("unlinkTargetGroupMapping");
        unlinkTargetGroupMapping = mappingManager.getMapping(unlinkTargetGroupMappingName);

        String targetName = getParameter("target");
        target = (LDAPSource)sourceManager.getSource(targetName);

        targetAlias = getParameter("targetAlias");
        if (targetAlias == null) {
            targetAlias = target.getName();
        }

        String targetGroupsName = getParameter("targetGroups");
        targetGroups = (LDAPSource)sourceManager.getSource(targetGroupsName);

        targetKeyAttribute = getParameter("targetKeyAttribute");
        targetLinkAttribute = getParameter("targetLinkAttribute");

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

    public Map<String,SearchResult> getGroups() throws Exception {
        final Session session = createAdminSession();

        try {
            final Map<String,SearchResult> map = new TreeMap<String,SearchResult>();

            SearchRequest sourceRequest = new SearchRequest();

            SearchResponse sourceResponse = new SearchResponse() {
                public void add(SearchResult result) throws Exception {
                    Attribute attribute = result.getAttribute(sourceKeyAttribute);
                    if (attribute == null) return;

                    Object value = attribute.getValue();
                    if (value == null) return;

                    map.put(value.toString(), result);
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

    public SearchResult getGroup(String key) throws Exception {
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

    public void syncGroups() throws Exception {
        final Session session = createAdminSession();

        try {
            SearchRequest sourceRequest = new SearchRequest();

            SearchResponse sourceResponse = new SearchResponse() {
                public void add(SearchResult sourceEntry) throws Exception {
                    syncGroup(session, sourceEntry);
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

    public void syncGroup(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchResult sourceEntry = searchSourceGroup(session, key);
            syncGroup(session, sourceEntry);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void linkGroup(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchResult sourceEntry = searchSourceGroup(session, key);
            SearchResult targetEntry = searchTargetGroup(session, sourceEntry);

            if (targetEntry == null) return;

            linkGroup(session, sourceEntry, targetEntry);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void unlinkGroup(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchResult sourceEntry = searchSourceGroup(session, key);
            unlinkGroup(session, sourceEntry);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void deleteGroup(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            SearchResult sourceEntry = searchSourceGroup(session, key);
            deleteGroup(session, sourceEntry);

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

    public SearchResult syncGroup(Session session, SearchResult sourceEntry) throws Exception {

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

    public void unlinkGroup(Session session, SearchResult sourceEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        if (log.isInfoEnabled()) log.info("Unlinking "+sourceDn);

        SearchResult targetEntry = getLinkedGroup(session, sourceEntry);
        if (targetEntry == null) return;

        unlinkGroup(session, sourceEntry, targetEntry);
    }

    public void deleteGroup(Session session, SearchResult sourceEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        if (log.isInfoEnabled()) log.info("Deleting "+sourceDn);

        SearchResult targetEntry = getLinkedGroup(session, sourceEntry);
        if (targetEntry != null) {
            DN targetDn = targetEntry.getDn();
            if (log.isInfoEnabled()) log.info("Deleting "+targetDn);
            target.delete(session, targetDn);
        }

        source.delete(session, sourceDn);
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

        importSourceGroupMapping.map(interpreter, targetAttributes);

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
                    throw e;
                }
            }
        }

        SearchResult targetResult = target.find(session, targetDn);
        targetAttributes = targetResult.getAttributes();

        if (importTargetGroupMapping == null) return targetResult;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(targetAlias, targetAttributes);

        importTargetGroupMapping.map(interpreter, sourceAttributes, sourceModifyRequest);

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

        syncSourceGroupMapping.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            target.modify(session, targetModifyRequest, targetModifyResponse);
        }

        if (syncTargetGroupMapping == null) return;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(targetAlias, targetAttributes);

        syncTargetGroupMapping.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    public void linkGroup(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

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

        linkTargetGroupMapping.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            target.modify(session, targetModifyRequest, targetModifyResponse);
        }

        if (linkSourceGroupMapping == null) return;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(targetAlias, targetAttributes);

        linkSourceGroupMapping.map(interpreter, sourceAttributes, sourceModifyRequest);

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

            unlinkSourceGroupMapping.map(interpreter, targetAttributes, targetModifyRequest);

            if (!targetModifyRequest.isEmpty()) {
                ModifyResponse targetModifyResponse = new ModifyResponse();

                target.modify(session, targetModifyRequest, targetModifyResponse);
            }
        }

        if (unlinkTargetGroupMapping == null) return;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        if (targetEntry != null) interpreter.set(targetAlias, targetAttributes);

        unlinkTargetGroupMapping.map(interpreter, sourceAttributes, sourceModifyRequest);

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
        SearchResult targetEntry = getLinkedGroup(session, sourceEntry);
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

        target.modify(session, modifyRequest, modifyResponse);
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

    public SearchResult getLinkedGroup(Session session, SearchResult sourceEntry) throws Exception {

        Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);
        if (linkAttribute == null) return null;

        return getLinkedGroup(session, linkAttribute.getValue());
    }

    public SearchResult getLinkedGroup(Session session, Object link) throws Exception {

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

        SearchResult targetEntry = getLinkedGroup(session, sourceEntry);

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

        SearchResult targetMemberEntry = userSyncModule.getLinkedUser(session, sourceMemberEntry);
        if (targetMemberEntry == null) {
            if (log.isDebugEnabled()) log.debug("==> Target member not found.");

            Attribute objectClass = sourceMemberEntry.getAttribute("objectClass");
            if (objectClass.containsValue("person")) {
                targetMemberEntry = userSyncModule.syncUser(session, sourceMemberEntry);

            } else if (objectClass.containsValue("groupOfNames")) {
                targetMemberEntry = syncGroup(session, sourceMemberEntry);

            } else {
                return null;
            }
        }

        if (targetMemberEntry == null) return null;
        
        DN targetMemberDn = targetMemberEntry.getDn();
        if (log.isInfoEnabled()) log.info("==> Target member: "+targetMemberDn);

        return targetMemberDn;
    }
}