package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ldap.connection.LDAPConnection;
import org.safehaus.penrose.ldap.source.LDAPSource;
import org.safehaus.penrose.util.TextUtil;
import org.safehaus.penrose.source.SourceManager;
import org.safehaus.penrose.module.Module;
import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.mapping.Mapping;
import org.safehaus.penrose.mapping.MappingManager;
import org.safehaus.penrose.interpreter.Interpreter;
import org.safehaus.penrose.filter.Filter;
import org.safehaus.penrose.filter.SimpleFilter;

import java.util.*;

/**
 * @author Endi Sukma Dewata
 */
public class IPAGroupModule extends Module {

    LDAPSource source;
    LDAPConnection sourceConnection;

    String sourceKeyAttribute;
    String sourceLinkAttribute;

    LDAPSource sourceUsers;
    LDAPSource sourceGroups;

    Mapping importSourceGroupMapping;
    Mapping importSourceGroupMapping2;

    Mapping syncSourceGroupMapping;
    Mapping syncSourceGroupMapping2;

    Mapping unlinkSourceGroupMapping;
    Mapping unlinkSourceGroupMapping2;

    LDAPSource target;
    LDAPConnection targetConnection;

    String targetKeyAttribute;
    String targetLinkAttribute;

    LDAPSource targetUsers;
    LDAPSource targetGroups;

    Mapping importTargetGroupMapping;
    Mapping importTargetGroupMapping2;

    Mapping syncTargetGroupMapping;
    Mapping syncTargetGroupMapping2;

    Map<String,DN> sourceDns = new LinkedHashMap<String,DN>();
    Map<String,String> sourceDnMapping = new LinkedHashMap<String,String>();

    Map<String,DN> targetDns = new LinkedHashMap<String,DN>();
    Map<String,String> targetDnMapping = new LinkedHashMap<String,String>();

    Set<String> ignoredSourceDns = new HashSet<String>();
    Set<String> ignoredTargetDns = new HashSet<String>();

    public IPAGroupModule() {
    }

    public void init() throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing IPA Group Module", 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();
        MappingManager mappingManager = partition.getMappingManager();

        String sourceName = getParameter("source");
        source = (LDAPSource)sourceManager.getSource(sourceName);
        sourceConnection = (LDAPConnection)source.getConnection();

        String sourceUsersName = getParameter("sourceUsers");
        sourceUsers = (LDAPSource)sourceManager.getSource(sourceUsersName);

        String sourceGroupsName = getParameter("sourceGroups");
        sourceGroups = (LDAPSource)sourceManager.getSource(sourceGroupsName);

        sourceKeyAttribute = getParameter("sourceKeyAttribute");
        sourceLinkAttribute = getParameter("sourceLinkAttribute");

        String importSourceGroupMappingName = getParameter("importSourceGroupMapping");
        importSourceGroupMapping = mappingManager.getMapping(importSourceGroupMappingName);

        String importSourceGroupMapping2Name = getParameter("importSourceGroupMapping2");
        importSourceGroupMapping2 = mappingManager.getMapping(importSourceGroupMapping2Name);

        String syncSourceGroupMappingName = getParameter("syncSourceGroupMapping");
        syncSourceGroupMapping = mappingManager.getMapping(syncSourceGroupMappingName);

        String syncSourceGroupMapping2Name = getParameter("syncSourceGroupMapping2");
        syncSourceGroupMapping2 = mappingManager.getMapping(syncSourceGroupMapping2Name);

        String unlinkSourceGroupMappingName = getParameter("unlinkSourceGroupMapping");
        unlinkSourceGroupMapping = mappingManager.getMapping(unlinkSourceGroupMappingName);

        String unlinkSourceGroupMapping2Name = getParameter("unlinkSourceGroupMapping2");
        unlinkSourceGroupMapping2 = mappingManager.getMapping(unlinkSourceGroupMapping2Name);

        String targetName = getParameter("target");
        target = (LDAPSource)sourceManager.getSource(targetName);
        targetConnection = (LDAPConnection)target.getConnection();

        String targetUsersName = getParameter("targetUsers");
        targetUsers = (LDAPSource)sourceManager.getSource(targetUsersName);

        String targetGroupsName = getParameter("targetGroups");
        targetGroups = (LDAPSource)sourceManager.getSource(targetGroupsName);

        targetKeyAttribute = getParameter("targetKeyAttribute");
        targetLinkAttribute = getParameter("targetLinkAttribute");

        String importTargetGroupMappingName = getParameter("importTargetGroupMapping");
        importTargetGroupMapping = mappingManager.getMapping(importTargetGroupMappingName);

        String importTargetGroupMapping2Name = getParameter("importTargetGroupMapping2");
        importTargetGroupMapping2 = mappingManager.getMapping(importTargetGroupMapping2Name);

        String syncTargetGroupMappingName = getParameter("syncTargetGroupMapping");
        syncTargetGroupMapping = mappingManager.getMapping(syncTargetGroupMappingName);

        String syncTargetGroupMapping2Name = getParameter("syncTargetGroupMapping2");
        syncTargetGroupMapping2 = mappingManager.getMapping(syncTargetGroupMapping2Name);

/*
        DN sourceAdminDn = new DN("cn=admins,cn=groups,cn=accounts").append(source.getBaseDn());
        DN targetAdminDn = new DN("CN=Administrators,CN=Builtin").append(target.getBaseDn());

        sourceDns.put(sourceAdminDn.getNormalizedDn(), sourceAdminDn);
        sourceDnMapping.put(sourceAdminDn.getNormalizedDn(), targetAdminDn.getNormalizedDn());

        targetDns.put(targetAdminDn.getNormalizedDn(), targetAdminDn);
        targetDnMapping.put(targetAdminDn.getNormalizedDn(), sourceAdminDn.getNormalizedDn());
*/
    }

    public void destroy() throws Exception {
    }

    public void syncGroups() throws Exception {
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

                    SearchResult targetEntry = findTargetGroup(session, sourceEntry);

                    if (targetEntry == null) {
                        if (log.isInfoEnabled()) log.info("Adding "+sourceDn);
                        importSourceGroup(session, sourceEntry);

                    } else {
                        if (log.isInfoEnabled()) log.info("Syncing "+sourceDn);
                        syncSourceGroup(session, sourceEntry, targetEntry);
                    }
                }
            };

            sourceGroups.search(session, sourceRequest, sourceResponse);

            SearchRequest targetRequest = new SearchRequest();

            SearchResponse targetResponse = new SearchResponse() {
                public void add(SearchResult targetEntry) throws Exception {

                    DN targetDn = targetEntry.getDn();
                    if (log.isInfoEnabled()) log.info("Initializing "+targetDn);

                    if (ignoredTargetDns.contains(targetDn.getNormalizedDn())) {
                        if (log.isInfoEnabled()) log.info("Ignoring "+targetDn);
                        return;
                    }

                    SearchResult sourceEntry = findSourceGroup(session, targetEntry);

                    if (sourceEntry == null) {
                        if (log.isInfoEnabled()) log.info("Adding "+targetDn);
                        importTargetGroup(session, targetEntry);

                    } else {
                        if (log.isInfoEnabled()) log.info("Skipping "+targetDn);
                    }
                }
            };

            targetGroups.search(session, targetRequest, targetResponse);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void syncSourceGroups() throws Exception {
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

                    SearchResult targetEntry = findTargetGroup(session, sourceEntry);

                    if (targetEntry == null) {
                        if (log.isInfoEnabled()) log.info("Adding "+sourceDn);
                        importSourceGroup(session, sourceEntry);

                    } else {
                        if (log.isInfoEnabled()) log.info("Syncing "+sourceDn);
                        syncSourceGroup(session, sourceEntry, targetEntry);
                    }
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

    public void syncTargetGroups() throws Exception {
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

                    SearchResult sourceEntry = findSourceGroup(session, targetEntry);

                    if (sourceEntry == null) {
                        if (log.isInfoEnabled()) log.info("Adding "+targetDn);
                        importTargetGroup(session, targetEntry);

                    } else {
                        if (log.isInfoEnabled()) log.info("Syncing "+targetDn);
                        syncTargetGroup(session, targetEntry, sourceEntry);
                    }
                }
            };

            targetGroups.search(session, targetRequest, targetResponse);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void syncSourceGroup(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            Filter filter = new SimpleFilter(sourceKeyAttribute, "=", key);

            if (log.isInfoEnabled()) log.info("Searching source for "+filter);

            SearchRequest sourceRequest = new SearchRequest();
            sourceRequest.setFilter(filter);

            SearchResponse sourceResponse = new SearchResponse();

            sourceGroups.search(session, sourceRequest, sourceResponse);

            if (!sourceResponse.hasNext()) {
                if (log.isInfoEnabled()) log.info("Entry not found.");
                throw new Exception("Entry not found.");
            }

            SearchResult sourceEntry = sourceResponse.next();
            if (log.isInfoEnabled()) log.info("Initializing "+sourceEntry.getDn());

            SearchResult targetEntry = findTargetGroup(session, sourceEntry);

            if (targetEntry == null) {
                if (log.isInfoEnabled()) log.info("Adding "+sourceEntry.getDn());
                importSourceGroup(session, sourceEntry);

            } else {
                if (log.isInfoEnabled()) log.info("Syncing "+sourceEntry.getDn());
                syncSourceGroup(session, sourceEntry, targetEntry);
            }

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void syncTargetGroup(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            Filter filter = new SimpleFilter(targetKeyAttribute, "=", key);

            if (log.isInfoEnabled()) log.info("Searching target for "+filter);

            SearchRequest targetRequest = new SearchRequest();
            targetRequest.setFilter(filter);

            SearchResponse targetResponse = new SearchResponse();

            targetGroups.search(session, targetRequest, targetResponse);

            if (!targetResponse.hasNext()) {
                if (log.isInfoEnabled()) log.info("Entry not found.");
                throw new Exception("Entry not found.");
            }

            SearchResult targetEntry = targetResponse.next();
            if (log.isInfoEnabled()) log.info("Initializing "+targetEntry.getDn());

            SearchResult sourceEntry = findSourceGroup(session, targetEntry);

            if (sourceEntry == null) {
                if (log.isInfoEnabled()) log.info("Adding "+targetEntry.getDn());
                importTargetGroup(session, targetEntry);

            } else {
                if (log.isInfoEnabled()) log.info("Syncing "+targetEntry.getDn());
                syncTargetGroup(session, targetEntry, sourceEntry);
            }

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public void unlinkSourceGroup(String key) throws Exception {
        Session session = null;

        try {
            session = createAdminSession();

            Filter filter = new SimpleFilter(sourceKeyAttribute, "=", key);

            if (log.isInfoEnabled()) log.info("Searching source for "+filter);

            SearchRequest sourceRequest = new SearchRequest();
            sourceRequest.setFilter(filter);

            SearchResponse sourceResponse = new SearchResponse();

            sourceGroups.search(session, sourceRequest, sourceResponse);

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
                SearchResult targetEntry = findTargetGroup(session, sourceEntry);
                if (log.isInfoEnabled()) log.info("Unlinking "+(targetEntry == null ? null : targetEntry.getDn()));
                unlinkSourceGroup(session, sourceEntry, targetEntry);
            }

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;

        } finally {
            if (session != null) try { session.close(); } catch (Exception e) { log.error(e.getMessage(), e); }
        }
    }

    public SearchResult findSourceUser(Session session, DN dn) throws Exception {

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

    public SearchResult findSourceGroup(Session session, SearchResult targetEntry) throws Exception {

        SearchResult sourceEntry = null;

        Attribute linkAttribute = targetEntry.getAttribute(targetLinkAttribute);
        if (linkAttribute != null) {

            Object link = linkAttribute.getValue();
            Filter filter = new SimpleFilter(sourceLinkAttribute, "=", link);

            if (log.isInfoEnabled()) log.info("Searching source for "+filter);

            SearchRequest sourceRequest = new SearchRequest();
            sourceRequest.setFilter(filter);

            SearchResponse sourceResponse = new SearchResponse();

            sourceGroups.search(session, sourceRequest, sourceResponse);

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

                sourceGroups.search(session, sourceRequest, sourceResponse);

                if (sourceResponse.hasNext()) {
                    sourceEntry = sourceResponse.next();
                    if (log.isInfoEnabled()) log.info("Found source: "+sourceEntry.getDn());
                }
            }
        }

        return sourceEntry;
    }

    public SearchResult findTargetGroup(Session session, SearchResult sourceEntry) throws Exception {

        SearchResult targetEntry = null;

        Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);
        if (linkAttribute != null) {

            Object link = linkAttribute.getValue();
            Filter filter = new SimpleFilter(targetLinkAttribute, "=", link);

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

                targetGroups.search(session, targetRequest, targetResponse);

                if (targetResponse.hasNext()) {
                    targetEntry = targetResponse.next();
                    if (log.isInfoEnabled()) log.info("Found target: "+targetEntry.getDn());
                }
            }
        }

        return targetEntry;
    }

    public DN createSourceGroupDn(DN dn, Attributes attributes) throws Exception {

        RDNBuilder rb = new RDNBuilder();
        rb.set("CN", attributes.getValue("sAMAccountName"));
        RDN sourceRdn = rb.toRdn();

        return sourceRdn.append(sourceGroups.getBaseDn());
    }

    public DN createTargetGroupDn(DN sourceDn) throws Exception {

        RDN rdn = sourceDn.getRdn();
        String cn = rdn.get("cn").toString();

        RDNBuilder rb = new RDNBuilder();
        rb.set("CN", cn);
        RDN targetRdn = rb.toRdn();

        return targetRdn.append("CN=Users").append(target.getBaseDn());
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

        SearchResult sourceMemberEntry = source.find(session, sourceMemberDn);
        if (sourceMemberEntry == null) {
            if (log.isDebugEnabled()) log.debug("==> Source entry not found.");
            return null;
        }

        SearchResult targetMemberEntry = findTargetEntry(session, sourceMemberEntry);
        if (targetMemberEntry == null) {
            if (log.isDebugEnabled()) log.debug("==> Target entry not found.");
            return null;
        }

        DN targetMemberDn = targetMemberEntry.getDn();
        if (log.isInfoEnabled()) log.info("==> Target member: "+targetMemberDn);

        return targetMemberDn;
    }

    public SearchResult findSourceEntry(Session session, SearchResult targetEntry) throws Exception {

        Attribute linkAttribute = targetEntry.getAttribute(targetLinkAttribute);
        if (linkAttribute == null) return null;

        Object link = linkAttribute.getValue();
        Filter filter = new SimpleFilter(sourceLinkAttribute, "=", link);

        if (log.isInfoEnabled()) log.info("Searching source for "+filter);

        SearchRequest sourceRequest = new SearchRequest();
        sourceRequest.setFilter(filter);

        SearchResponse sourceResponse = new SearchResponse();

        source.search(session, sourceRequest, sourceResponse);

        if (!sourceResponse.hasNext()) return null;

        SearchResult sourceEntry = sourceResponse.next();
        if (log.isInfoEnabled()) log.info("Found source: "+sourceEntry.getDn());

        return sourceEntry;
    }

    public void importSourceGroup(Session session, SearchResult sourceEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        String normalizedSourceDn = sourceDn.getNormalizedDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("IMPORT SOURCE GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+sourceDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        sourceAttributes.print();

        log.debug("");

        Attributes targetAttributes = new Attributes();

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(source.getName(), sourceAttributes);

        importSourceGroupMapping.map(interpreter, targetAttributes);

        String normalizedTargetDn = sourceDnMapping.get(normalizedSourceDn);
        DN targetDn = targetDns.get(normalizedTargetDn);

        Attribute dnAttribute = targetAttributes.remove("dn");
        if (targetDn == null) {
            targetDn = new DN((String)dnAttribute.getValue());
        }

        AddRequest addRequest = new AddRequest();
        addRequest.setDn(targetDn);
        addRequest.setAttributes(targetAttributes);

        AddResponse addResponse = new AddResponse();

        target.add(session, addRequest, addResponse);

        if (importSourceGroupMapping2 == null) return;

        SearchResult targetResult = target.find(session, targetDn);
        targetAttributes = targetResult.getAttributes();

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(target.getName(), targetAttributes);

        importSourceGroupMapping2.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    public void syncSourceGroup(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("SYNC SOURCE GROUP", 60));
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

        syncSourceGroupMapping.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            target.modify(session, targetModifyRequest, targetModifyResponse);
        }

        if (syncSourceGroupMapping2 == null) return;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(target.getName(), targetAttributes);

        syncSourceGroupMapping2.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    public void unlinkSourceGroup(Session session, SearchResult sourceEntry, SearchResult targetEntry) throws Exception {

        DN sourceDn = sourceEntry.getDn();
        Attributes sourceAttributes = sourceEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("UNLINK SOURCE GROUP", 60));
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

            unlinkSourceGroupMapping.map(interpreter, targetAttributes, targetModifyRequest);

            if (!targetModifyRequest.isEmpty()) {
                ModifyResponse targetModifyResponse = new ModifyResponse();

                target.modify(session, targetModifyRequest, targetModifyResponse);
            }
        }

        if (unlinkSourceGroupMapping2 == null) return;

        ModifyRequest sourceModifyRequest = new ModifyRequest();
        sourceModifyRequest.setDn(sourceDn);

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        if (targetEntry != null) interpreter.set(target.getName(), targetAttributes);

        unlinkSourceGroupMapping2.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }
    }

    public Collection<Object> transformTargetMembers(Session session, Object object) throws Exception {
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
                DN targetMemberDn = (DN)value;
                DN sourceMemberDn = transformTargetMember(session, targetMemberDn);
                if (sourceMemberDn != null) output.add(sourceMemberDn);
            } else {
                String targetMemberDn = value.toString();
                String sourceMemberDn = transformTargetMember(session, targetMemberDn);
                if (sourceMemberDn != null) output.add(sourceMemberDn);
            }
        }

        return output;
    }

    public String transformTargetMember(Session session, String targetMemberDn) throws Exception {
        DN sourceMemberDn = transformTargetMember(session, new DN(targetMemberDn));
        return sourceMemberDn == null ? null : sourceMemberDn.toString();
    }

    public DN transformTargetMember(Session session, DN targetMemberDn) throws Exception {
        if (log.isInfoEnabled()) log.info("Transforming target member: "+targetMemberDn);

        SearchResult targetMemberEntry = target.find(session, targetMemberDn);
        if (targetMemberEntry == null) {
            if (log.isDebugEnabled()) log.debug("==> Target entry not found.");
            return null;
        }

        SearchResult sourceMemberEntry = findSourceEntry(session, targetMemberEntry);
        if (sourceMemberEntry == null) {
            if (log.isDebugEnabled()) log.debug("==> Source entry not found.");
            return null;
        }

        DN sourceMemberDn = sourceMemberEntry.getDn();
        if (log.isInfoEnabled()) log.info("==> Source member: "+sourceMemberDn);

        return sourceMemberDn;
    }

    public SearchResult findTargetEntry(Session session, SearchResult sourceEntry) throws Exception {

        Attribute linkAttribute = sourceEntry.getAttribute(sourceLinkAttribute);
        if (linkAttribute == null) return null;

        Object link = linkAttribute.getValue();
        Filter filter = new SimpleFilter(targetLinkAttribute, "=", link);

        if (log.isInfoEnabled()) log.info("Searching target for "+filter);

        SearchRequest targetRequest = new SearchRequest();
        targetRequest.setFilter(filter);

        SearchResponse targetResponse = new SearchResponse();

        target.search(session, targetRequest, targetResponse);

        if (!targetResponse.hasNext()) return null;

        SearchResult targetEntry = targetResponse.next();
        if (log.isInfoEnabled()) log.info("Found target: "+targetEntry.getDn());

        return targetEntry;
    }

    public void importTargetGroup(Session session, SearchResult targetEntry) throws Exception {

        DN targetDn = targetEntry.getDn();
        String normalizedTargetDn = targetDn.getNormalizedDn();
        Attributes targetAttributes = targetEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("IMPORT TARGET GROUP", 60));
        log.debug(TextUtil.displayLine(" - "+targetDn, 60));
        log.debug(TextUtil.displaySeparator(60));

        targetAttributes.print();

        log.debug("");

        Attributes sourceAttributes = new Attributes();

        Interpreter interpreter = partition.newInterpreter();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(target.getName(), targetAttributes);

        importTargetGroupMapping.map(interpreter, sourceAttributes);

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

        if (importTargetGroupMapping2 == null) return;

        SearchResult sourceResult = source.find(session, sourceDn);
        sourceAttributes = sourceResult.getAttributes();

        ModifyRequest targetModifyRequest = new ModifyRequest();
        targetModifyRequest.setDn(targetDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(source.getName(), sourceAttributes);

        importTargetGroupMapping2.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            target.modify(session, targetModifyRequest, targetModifyResponse);
        }
    }

    public void syncTargetGroup(Session session, SearchResult targetEntry, SearchResult sourceEntry) throws Exception {

        DN targetDn = targetEntry.getDn();
        Attributes targetAttributes = targetEntry.getAttributes();

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("SYNC TARGET GROUP", 60));
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
        interpreter.set(target.getName(), targetAttributes);

        syncTargetGroupMapping.map(interpreter, sourceAttributes, sourceModifyRequest);

        if (!sourceModifyRequest.isEmpty()) {
            ModifyResponse sourceModifyResponse = new ModifyResponse();

            source.modify(session, sourceModifyRequest, sourceModifyResponse);
        }

        if (syncTargetGroupMapping2 == null) return;

        ModifyRequest targetModifyRequest = new ModifyRequest();
        targetModifyRequest.setDn(targetDn);

        interpreter.clear();
        interpreter.set("session", session);
        interpreter.set("module", this);
        interpreter.set(source.getName(), sourceAttributes);

        syncTargetGroupMapping2.map(interpreter, targetAttributes, targetModifyRequest);

        if (!targetModifyRequest.isEmpty()) {
            ModifyResponse targetModifyResponse = new ModifyResponse();

            target.modify(session, targetModifyRequest, targetModifyResponse);
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
        SearchResult sourceMemberEntry = source.find(session, memberDn);

        DN targetMemberDn;

        if (memberDn.endsWith(sourceUsers.getBaseDn())) {
            SearchResult searchResult = findTargetEntry(session, sourceMemberEntry);
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

    public LDAPSource getSource() {
        return source;
    }

    public void setSource(LDAPSource source) {
        this.source = source;
    }
}