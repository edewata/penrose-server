package org.safehaus.penrose.directory;

import org.safehaus.penrose.acl.ACLEvaluator;
import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.partition.Partition;
import org.safehaus.penrose.pipeline.Pipeline;
import org.safehaus.penrose.schema.SchemaManager;
import org.safehaus.penrose.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

/**
 * @author Endi Sukma Dewata
 */
public class EntrySearchResponse extends Pipeline {

    public Logger log = LoggerFactory.getLogger(getClass());
    public boolean debug = log.isDebugEnabled();

    Session session;
    SearchRequest request;
    SearchResponse response;
    Entry entry;

    SchemaManager schemaManager;
    ACLEvaluator aclEvaluator;

    Collection<String> requestedAttributes;
    boolean allRegularAttributes;
    boolean allOpAttributes;

    SearchResult lastResult;

    public EntrySearchResponse(
            Session session,
            SearchRequest request,
            SearchResponse response,
            Entry entry
    ) {
        super(response);

        if (debug) log.debug("Creating default search result processor.");

        this.session = session;
        this.request = request;
        this.response = response;
        this.entry = entry;

        Partition partition = entry.getPartition();
        this.schemaManager = partition.getSchemaManager();
        this.aclEvaluator = partition.getAclEvaluator();

        requestedAttributes = request.getAttributes();
        allRegularAttributes = requestedAttributes.isEmpty() || requestedAttributes.contains("*");
        allOpAttributes = requestedAttributes.contains("+");
    }

    public void add(SearchResult result) throws Exception {

        if (debug) log.debug("Processing search result "+result.getDn()+".");

        if (lastResult == null) {
            lastResult = result;
            return;
        }

        if (result.getDn().equals(lastResult.getDn())) {
            if (debug) log.debug("Merging with previous search result.");
            mergeSearchResult(result, lastResult);
            return;
        }

        returnLastSearchResult();

        lastResult = result;
    }

    public void returnLastSearchResult() throws Exception {
        try {
            if (debug) log.debug("Validating ACL.");
            entry.validatePermission(session, lastResult);

        } catch (Exception e) {
            if (debug) log.debug("Search result "+lastResult.getDn()+" failed ACL check.");
            return;
        }

        if (debug) log.debug("Validating search filter.");
        if (!entry.validateSearchResult(request, lastResult)) {
            if (debug) log.debug("Search result "+lastResult.getDn()+" failed search filter check.");
            return;
        }

        if (debug) log.debug("Filtering attributes.");
        aclEvaluator.filterAttributes(session, lastResult);
        filterAttributes(lastResult);

        super.add(lastResult);
    }

    public void mergeSearchResult(SearchResult source, SearchResult destination) {

        Attributes sourceAttributes = source.getAttributes();
        Attributes destinationAttributes = destination.getAttributes();
        destinationAttributes.add(sourceAttributes);

        SourceAttributes sourceValues = source.getSourceAttributes();
        SourceAttributes destinationValues = destination.getSourceAttributes();
        destinationValues.add(sourceValues);
    }

    public void filterAttributes(SearchResult result) throws Exception {

        Attributes attributes = result.getAttributes();
        Collection<String> attributeNames = attributes.getNames();

        if (debug) {
            log.debug("Attribute names: "+attributeNames);
        }

        if (allRegularAttributes && allOpAttributes) {
            if (debug) log.debug("Returning all attributes.");
            return;
        }

        if (allRegularAttributes) {
            if (debug) log.debug("Returning regular attributes.");

            for (String attributeName : attributeNames) {
                if (schemaManager.isOperational(attributeName)) {
                    if (debug) log.debug("Remove operational attribute " + attributeName);
                    attributes.remove(attributeName);
                }
            }

        } else if (allOpAttributes) {
            if (debug) log.debug("Returning operational attributes.");

            for (String attributeName : attributeNames) {
                if (!schemaManager.isOperational(attributeName)) {
                    if (debug) log.debug("Remove regular attribute " + attributeName);
                    attributes.remove(attributeName);
                }
            }

        } else {
            if (debug) log.debug("Returning requested attributes.");
            attributes.retain(requestedAttributes);
        }

        if (debug) log.debug("Returning: "+attributes.getNames());
    }


    public void close() throws Exception {
        if (lastResult != null) {
            returnLastSearchResult();
        }
        super.close();
    }
}
