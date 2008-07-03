package org.safehaus.penrose.nis.directory;

import org.safehaus.penrose.directory.DynamicEntry;
import org.safehaus.penrose.directory.FieldRef;
import org.safehaus.penrose.directory.FilterBuilder;
import org.safehaus.penrose.directory.SourceRef;
import org.safehaus.penrose.filter.Filter;
import org.safehaus.penrose.filter.FilterTool;
import org.safehaus.penrose.filter.SimpleFilter;
import org.safehaus.penrose.interpreter.Interpreter;
import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.pipeline.Pipeline;
import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.source.Source;
import org.safehaus.penrose.util.TextUtil;

import java.util.Collection;

/**
 * @author Endi S. Dewata
 */
public class NISEntry extends DynamicEntry {

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Search
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void search(
            Session session,
            SearchRequest request,
            SearchResponse response
    ) throws Exception {

        final DN baseDn     = request.getDn();
        final Filter filter = request.getFilter();
        final int scope     = request.getScope();

        if (debug) {
            log.debug(TextUtil.displaySeparator(80));
            log.debug(TextUtil.displayLine("NIS SEARCH", 80));
            log.debug(TextUtil.displayLine("Entry  : "+getDn(), 80));
            log.debug(TextUtil.displayLine("Base   : "+baseDn, 80));
            log.debug(TextUtil.displayLine("Filter : "+filter, 80));
            log.debug(TextUtil.displayLine("Scope  : "+ LDAP.getScope(scope), 80));
            log.debug(TextUtil.displaySeparator(80));
        }

        response = createSearchResponse(session, request, response);

        try {
            validateScope(request);
            validatePermission(session, request);
            validateFilter(filter);

        } catch (Exception e) {
            response.close();
            return;
        }

        try {
            generateSearchResults(session, request, response);

        } finally {
            response.close();
        }
    }

    public void generateSearchResults(
            final Session session,
            final SearchRequest request,
            final SearchResponse response
    ) throws Exception {

        DN baseDn = request.getDn();

        if (debug) log.debug("Searching entry "+ entryConfig.getDn());

        final Interpreter interpreter = partition.newInterpreter();
        final SourceRef primarySourceRef = getSourceRef(0);

        SearchRequest newRequest = createSearchRequest(session, request, interpreter);

        SearchResponse newResponse = new Pipeline(response) {
            public void add(SearchResult primaryResult) throws Exception {

                SourceValues sv = new SourceValues();
                sv.set(primarySourceRef.getAlias(), primaryResult.getAttributes());

                interpreter.set(sv);

                for (int i=1; i<getSourceRefsCount(); i++) {
                    try {
                        SourceRef sourceRef = getSourceRef(i);

                        SearchResult secondaryResult = find(session, sourceRef, interpreter);
                        if (secondaryResult == null) continue;

                        sv.set(sourceRef.getAlias(), secondaryResult.getAttributes());
                        interpreter.set(sv);

                    } catch (Exception e) {
                        log.debug(e.getMessage(), e);
                    }
                }

                DN dn = computeDn(interpreter);
                Attributes attributes = computeAttributes(interpreter);

                interpreter.clear();

                SearchResult newResult = new SearchResult();
                newResult.setDn(dn);
                newResult.setAttributes(attributes);
                newResult.setEntryId(getId());

                super.add(newResult);
            }
        };

        Source source = primarySourceRef.getSource();
        source.search(session, newRequest, newResponse);
    }

    public SearchRequest createSearchRequest(
            Session session,
            SearchRequest request,
            Interpreter interpreter
    ) throws Exception {

        SearchRequest newRequest = (SearchRequest)request.clone();

        DN baseDn = request.getDn();
        Filter filter = request.getFilter();
        int scope = request.getScope();

        final SourceRef primarySourceRef = getSourceRef(0);

        DN primaryBaseDn = null;
        Filter primaryFilter = null;

        if (getDn().matches(baseDn) && (scope == SearchRequest.SCOPE_BASE || scope == SearchRequest.SCOPE_SUB)) {
            primaryBaseDn = createPrimaryBaseDn(session, primarySourceRef, baseDn, interpreter);

            if (primaryBaseDn == null) {
                interpreter.set(baseDn.getRdn());

                for (FieldRef fieldRef : primarySourceRef.getFieldRefs()) {

                    Object value = interpreter.eval(fieldRef);
                    if (value == null) continue;

                    String name = fieldRef.getName();
                    SimpleFilter sf = new SimpleFilter(name, "=", value);
                    primaryFilter = FilterTool.appendAndFilter(sf, primaryFilter);
                }

                interpreter.clear();
            }
        }

        newRequest.setDn(primaryBaseDn);

        Filter newFilter = createPrimaryFilter(session, primarySourceRef, filter, interpreter);
        primaryFilter = FilterTool.appendOrFilter(newFilter, primaryFilter);

        newRequest.setFilter(primaryFilter);

        return newRequest;
    }

    public DN createPrimaryBaseDn(
            Session session,
            SourceRef primarySourceRef,
            DN baseDn,
            Interpreter interpreter
    ) throws Exception {

        try {
            interpreter.set(baseDn.getRdn());

            RDNBuilder rb = new RDNBuilder();

            for (FieldRef fieldRef : primarySourceRef.getPrimaryKeyFieldRefs()) {

                Object value = interpreter.eval(fieldRef);
                if (value == null) return null;

                String fieldName = fieldRef.getName();
                rb.set(fieldName, value);
            }

            return new DN(rb.toRdn());

        } finally {
            interpreter.clear();
        }
    }

    public Filter createPrimaryFilter(
            Session session,
            SourceRef primarySourceRef,
            Filter filter,
            Interpreter interpreter
    ) throws Exception {

        FilterBuilder filterBuilder = new FilterBuilder(this, interpreter);
        Filter primaryFilter = filterBuilder.convert(filter, primarySourceRef);

        for (int i=getSourceRefsCount()-1; i>0; i--) {
            try {
                SourceRef sourceRef = getSourceRef(i);

                Filter sourceFilter = filterBuilder.convert(filter, sourceRef);
                if (sourceFilter == null) continue;

                SearchRequest newRequest = new SearchRequest();
                newRequest.setDn((DN)null);
                newRequest.setFilter(sourceFilter);

                SearchResponse newResponse = new SearchResponse();

                Source source = sourceRef.getSource();
                source.search(session, newRequest, newResponse);

                Filter newFilter = createFilter(primarySourceRef, sourceRef, newResponse.getAll());
                primaryFilter = FilterTool.appendOrFilter(newFilter, primaryFilter);

            } catch (Exception e) {
                log.debug(e.getMessage(), e);
            }
        }

        return primaryFilter;
    }

    public Filter createFilter(
            SourceRef primarySourceRef,
            SourceRef sourceRef,
            Collection<SearchResult> results
    ) throws Exception {

        String primaryAlias = primarySourceRef.getAlias();

        Filter filter = null;

        for (SearchResult result : results) {
            Attributes attributes = result.getAttributes();

            Filter af = null;
            for (FieldRef fieldRef : sourceRef.getFieldRefs()) {
                String variable = fieldRef.getVariable();
                if (variable == null) continue;
                if (!variable.startsWith(primaryAlias+".")) continue;

                Object value = attributes.getValue(fieldRef.getName());
                if (value == null) continue;

                String name = variable.substring(primaryAlias.length()+1);
                SimpleFilter sf = new SimpleFilter(name, "=", value);
                af = FilterTool.appendAndFilter(sf, af);
            }

            filter = FilterTool.appendOrFilter(af, filter);
        }

        return filter;
    }

    public SearchResult find(
            final Session session,
            final SourceRef sourceRef,
            final Interpreter interpreter
    ) throws Exception {

        if (debug) log.debug("Searching source "+sourceRef.getAlias());

        RDNBuilder rb = new RDNBuilder();

        for (FieldRef fieldRef : sourceRef.getFieldRefs()) {

            Object value = interpreter.eval(fieldRef);
            if (value == null) continue;

            rb.set(fieldRef.getName(), value);
        }

        if (rb.isEmpty()) return null;

        Source source = sourceRef.getSource();
        return source.find(session, rb.toRdn());
    }
}
