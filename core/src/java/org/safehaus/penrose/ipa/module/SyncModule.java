package org.safehaus.penrose.ipa.module;

import org.safehaus.penrose.ipa.Sync;
import org.safehaus.penrose.ldap.SearchResult;
import org.safehaus.penrose.ldap.source.LDAPSource;
import org.safehaus.penrose.mapping.Mapping;
import org.safehaus.penrose.mapping.MappingManager;
import org.safehaus.penrose.module.Module;
import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.source.SourceManager;
import org.safehaus.penrose.util.TextUtil;

/**
 * @author Endi Sukma Dewata
 */
public abstract class SyncModule extends Module implements Sync {

    protected String sourceAlias;
    protected LDAPSource source;

    protected String targetAlias;
    protected LDAPSource targetFE;
    protected LDAPSource targetBE;

    protected String sourceKeyAttribute;
    protected String sourceLinkAttribute;
    protected String targetKeyAttribute;
    protected String targetLinkAttribute;

    protected Mapping sourceImportMapping;
    protected Mapping targetImportMapping;
    protected Mapping sourceLinkMapping;
    protected Mapping targetLinkMapping;
    protected Mapping sourceSyncMapping;
    protected Mapping targetSyncMapping;
    protected Mapping sourceUnlinkMapping;
    protected Mapping targetUnlinkMapping;

    public void init() throws Exception {

        log.debug(TextUtil.displaySeparator(60));
        log.debug(TextUtil.displayLine("Initializing Sync Module", 60));
        log.debug(TextUtil.displaySeparator(60));

        SourceManager sourceManager = partition.getSourceManager();

        String sourceName = getParameter("source");
        source = (LDAPSource)sourceManager.getSource(sourceName);

        sourceAlias = getParameter("sourceAlias");
        if (sourceAlias == null) {
            sourceAlias = source.getName();
        }

        String targetName = getParameter("target");
        if (targetName == null) {
            String targetFEName = getParameter("targetFE");
            targetFE = (LDAPSource)sourceManager.getSource(targetFEName);

            String targetBEName = getParameter("targetBE");
            targetBE = (LDAPSource)sourceManager.getSource(targetBEName);

        } else {
            targetFE = (LDAPSource)sourceManager.getSource(targetName);
            targetBE = targetFE;
        }

        targetAlias = getParameter("targetAlias");
        if (targetAlias == null) {
            targetAlias = targetBE.getName();
        }

        sourceKeyAttribute = getParameter("sourceKeyAttribute");
        sourceLinkAttribute = getParameter("sourceLinkAttribute");

        targetKeyAttribute = getParameter("targetKeyAttribute");
        targetLinkAttribute = getParameter("targetLinkAttribute");

        MappingManager mappingManager = partition.getMappingManager();

        String sourceImportMappingName = getParameter("sourceImportMapping");
        sourceImportMapping = mappingManager.getMapping(sourceImportMappingName);

        String targetImportMappingName = getParameter("targetImportMapping");
        targetImportMapping = mappingManager.getMapping(targetImportMappingName);

        String sourceLinkMappingName = getParameter("sourceLinkMapping");
        sourceLinkMapping = mappingManager.getMapping(sourceLinkMappingName);

        String targetLinkMappingName = getParameter("targetLinkMapping");
        targetLinkMapping = mappingManager.getMapping(targetLinkMappingName);

        String sourceSyncMappingName = getParameter("sourceSyncMapping");
        sourceSyncMapping = mappingManager.getMapping(sourceSyncMappingName);

        String targetSyncMappingName = getParameter("targetSyncMapping");
        targetSyncMapping = mappingManager.getMapping(targetSyncMappingName);

        String sourceUnlinkMappingName = getParameter("sourceUnlinkMapping");
        sourceUnlinkMapping = mappingManager.getMapping(sourceUnlinkMappingName);

        String targetUnlinkMappingName = getParameter("targetUnlinkMapping");
        targetUnlinkMapping = mappingManager.getMapping(targetUnlinkMappingName);
    }

    public void sync(Session session, SearchResult searchResult) throws Exception {
    }
}
