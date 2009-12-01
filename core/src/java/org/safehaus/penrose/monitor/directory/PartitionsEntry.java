package org.safehaus.penrose.monitor.directory;

import org.safehaus.penrose.directory.Entry;
import org.safehaus.penrose.directory.EntryConfig;
import org.safehaus.penrose.directory.EntryContext;
import org.safehaus.penrose.filter.Filter;
import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.operation.SearchOperation;
import org.safehaus.penrose.util.TextUtil;

/**
 * @author Endi Sukma Dewata
 */
public class PartitionsEntry extends Entry {

    public void init() throws Exception {

        DN entryDn = getDn();
        DN partitionDn = new RDN("cn=...").append(entryDn);

        EntryConfig partitionEntryConfig = new EntryConfig();
        partitionEntryConfig.setName(getName()+"_partition");
        partitionEntryConfig.setDn(partitionDn);
        partitionEntryConfig.addObjectClass("monitoredObject");

        EntryContext partitionEntryContext = new EntryContext();
        partitionEntryContext.setDirectory(directory);
        partitionEntryContext.setParent(this);

        PartitionEntry partitionEntry = new PartitionEntry();
        partitionEntry.init(partitionEntryConfig, partitionEntryContext);

        addChild(partitionEntry);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Search
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void search(
            SearchOperation operation
    ) throws Exception {

        boolean debug = log.isDebugEnabled();

        final DN baseDn     = operation.getDn();
        final Filter filter = operation.getFilter();
        final int scope     = operation.getScope();

        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("PARTITIONS ENTRY SEARCH", 70));
            log.debug(TextUtil.displayLine("Filter : "+filter, 70));
            log.debug(TextUtil.displayLine("Scope  : "+ LDAP.getScope(scope), 70));
            log.debug(TextUtil.displayLine("Entry  : "+getDn(), 70));
            log.debug(TextUtil.displayLine("Base   : "+baseDn, 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        try {
            if (!validate(operation)) return;

            expand(operation);

        } finally {
            operation.close();
        }
    }

    public void expand(
            SearchOperation operation
    ) throws Exception {

        DN entryDn = getDn();

        DN baseDn = operation.getDn();
        int scope = operation.getScope();

        int baseLength = baseDn.getLength();
        int entryLength = entryDn.getLength();

        if (baseLength < entryLength && scope == SearchRequest.SCOPE_SUB
                || baseLength == entryLength-1 && scope == SearchRequest.SCOPE_ONE
                || baseDn.matches(entryDn) && (scope == SearchRequest.SCOPE_SUB || scope == SearchRequest.SCOPE_BASE)) {

            SearchResult result = createSearchResult(operation);
            operation.add(result);
        }
   }

    public SearchResult createSearchResult(
            SearchOperation operation
    ) throws Exception {

        DN entryDn = getDn();

        Attributes attributes = new Attributes();
        attributes.addValue("objectClass", "monitoredObject");
        attributes.addValue("cn", "Partitions");

        SearchResult result = new SearchResult(entryDn, attributes);
        result.setEntryName(getName());

        return result;
    }
}