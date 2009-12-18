package org.safehaus.penrose.ldap.source;

import org.safehaus.penrose.filter.Filter;
import org.safehaus.penrose.filter.FilterTool;
import org.safehaus.penrose.filter.FilterProcessor;
import org.safehaus.penrose.filter.SimpleFilter;
import org.safehaus.penrose.ldap.*;
import org.safehaus.penrose.ldap.connection.LDAPConnection;
import org.safehaus.penrose.session.Session;
import org.safehaus.penrose.session.SessionManager;
import org.safehaus.penrose.source.Field;
import org.safehaus.penrose.source.Source;
import org.safehaus.penrose.util.TextUtil;
import org.safehaus.penrose.control.Control;
import org.safehaus.penrose.pipeline.Pipeline;
import org.safehaus.penrose.schema.SchemaManager;

import java.util.*;

/**
 * @author Endi S. Dewata
 */
public class LDAPSource extends Source {

    LDAPConnection connection;

    DN sourceBaseDn;
    DN newSourceBaseDn;
    boolean hideBaseDn;

    int sourceScope;
    Filter sourceFilter;
    String objectClasses;

    long sourceSizeLimit;
    long sourceTimeLimit;

    Collection<String> attributeNames = new HashSet<String>();
    Collection<String> mapAttributeNames = new HashSet<String>();

    public LDAPSource() {
    }

    public void init() throws Exception {

        boolean debug = log.isDebugEnabled();

        connection = (LDAPConnection)getConnection();

        String value = getParameter(LDAP.BASE_DN);
        sourceBaseDn = new DN(value);
        if (debug) log.debug("Base DN: "+sourceBaseDn);

        value = getParameter(LDAP.NEW_BASE_DN);
        newSourceBaseDn = value == null ? null : new DN(value);
        if (debug) log.debug("New Base DN: "+newSourceBaseDn);

        value = getParameter(LDAP.HIDE_BASE_DN);
        hideBaseDn = value == null ? false : Boolean.parseBoolean(value);
        if (debug) log.debug("Hide Base DN: "+hideBaseDn);

        sourceScope = getScope(getParameter(LDAP.SCOPE));
        if (debug) log.debug("Scope: "+sourceScope);

        sourceFilter = FilterTool.parseFilter(getParameter(LDAP.FILTER));
        if (debug) log.debug("Filter: "+sourceFilter);

        objectClasses = getParameter(LDAP.OBJECT_CLASSES);
        if (debug) log.debug("Object classes: "+objectClasses);

        String s = getParameter(LDAP.SIZE_LIMIT);
        if (s != null) {
            sourceSizeLimit = Long.parseLong(s);
            if (debug) log.debug("Size Limit: "+sourceSizeLimit);
        }

        s = getParameter(LDAP.TIME_LIMIT);
        if (s != null) {
            sourceTimeLimit = Long.parseLong(s);
            if (debug) log.debug("Time Limit: "+sourceTimeLimit);
        }

        s = getParameter(LDAP.ATTRIBUTES);
        if (s != null) {
            StringTokenizer st = new StringTokenizer(s, ", \n");
            while (st.hasMoreTokens()) {
                String attributeName = st.nextToken();
                attributeNames.add(attributeName);
            }
            if (debug) log.debug("Attributes: "+attributeNames);
        }

        s = getParameter(LDAP.MAP_ATTRIBUTES);
        if (s != null) {
            StringTokenizer st = new StringTokenizer(s, ", \n");
            while (st.hasMoreTokens()) {
                String attributeName = st.nextToken();
                mapAttributeNames.add(attributeName.toLowerCase());
            }
            if (debug) log.debug("Map attributes: "+mapAttributeNames);
        }
    }

    public int getScope(String scope) {
        if ("OBJECT".equals(scope)) {
            return SearchRequest.SCOPE_BASE;

        } else if ("ONELEVEL".equals(scope)) {
            return SearchRequest.SCOPE_ONE;

        } else { // if ("SUBTREE".equals(scope)) {
            return SearchRequest.SCOPE_SUB;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Add
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void add(
            Session session,
            AddRequest request,
            AddResponse response
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("Add "+partition.getName()+"."+getName(), 70));
            log.debug(TextUtil.displayLine(" - DN : "+request.getDn(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        DNBuilder db = new DNBuilder();
        db.append(request.getDn());

        if (hideBaseDn) {
            db.append(sourceBaseDn);
        }

        DN dn = db.toDn();

        if (newSourceBaseDn != null) {
            dn = dn.getPrefix(newSourceBaseDn).append(sourceBaseDn);
        }

        AddRequest newRequest = (AddRequest)request.clone();
        newRequest.setDn(dn);

        Attributes newAttributes = newRequest.getAttributes();

        if (objectClasses != null) {
            Attribute ocAttribute = new Attribute("objectClass");
            for (StringTokenizer st = new StringTokenizer(objectClasses, ","); st.hasMoreTokens(); ) {
                String objectClass = st.nextToken().trim();
                ocAttribute.addValue(objectClass);
            }
            newAttributes.set(ocAttribute);
        }

        if (newSourceBaseDn != null && !mapAttributeNames.isEmpty()) {
            for (Attribute attribute : newAttributes.getAll()) {
                if (!mapAttributeNames.contains(attribute.getName().toLowerCase())) continue;

                Collection<Object> values = new ArrayList<Object>();
                for (Object value : attribute.getValues()) {
                    DN newDn = new DN(value.toString());
                    newDn = newDn.getPrefix(newSourceBaseDn).append(sourceBaseDn);
                    values.add(newDn.toString());
                }

                attribute.setValues(values);
            }
        }

        if (debug) log.debug("Adding entry "+dn+".");

        LDAPClient client = connection.getClient(session);

        try {
            client.add(newRequest, response);

        } finally {
            connection.closeClient(session);
        }

        log.debug("Add operation completed.");
     }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Bind
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void bind(
            Session session,
            BindRequest request,
            BindResponse response
    ) throws Exception {
        bind(session, request, response, null);
    }

    public void bind(
            Session session,
            BindRequest request,
            BindResponse response,
            Attributes attributes
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("Bind "+partition.getName()+"."+getName(), 70));
            log.debug(TextUtil.displayLine(" - DN : "+request.getDn(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        DNBuilder db = new DNBuilder();
        db.append(request.getDn());

        if (hideBaseDn) {
            db.append(sourceBaseDn);
        }

        DN bindDn = db.toDn();

        if (bindDn == null && attributes != null) {
            Object dn = attributes.getValue("dn");
            bindDn = dn == null ? null : new DN(dn.toString());
        }

        if (bindDn != null && newSourceBaseDn != null) {
            bindDn = bindDn.getPrefix(newSourceBaseDn).append(sourceBaseDn);
        }

        BindRequest newRequest = (BindRequest)request.clone();
        newRequest.setDn(bindDn);
        newRequest.setPassword(request.getPassword());

        if (debug) log.debug("Binding as "+bindDn+".");

        String authentication = getParameter(LDAP.AUTHENTICATION);
        //if (debug) log.debug("Authentication: "+authentication);

        if (LDAP.AUTHENTICATION_DISABLED.equals(authentication)) {
            if (debug) log.debug("Pass-Through Authentication is disabled.");
            throw LDAP.createException(LDAP.INVALID_CREDENTIALS);
        }

        LDAPClient client = connection.getClient(session);

        try {
            client.bind(newRequest, response);

        } finally {
            connection.closeClient(session);
        }

        log.debug("Bind operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Compare
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void compare(
            Session session,
            CompareRequest request,
            CompareResponse response
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("Compare "+partition.getName()+"."+getName(), 70));
            log.debug(TextUtil.displayLine(" - DN : "+request.getDn(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        DNBuilder db = new DNBuilder();
        db.append(request.getDn());

        if (hideBaseDn) {
            db.append(sourceBaseDn);
        }

        DN dn = db.toDn();

        if (newSourceBaseDn != null) {
            dn = dn.getPrefix(newSourceBaseDn).append(sourceBaseDn);
        }

        CompareRequest newRequest = (CompareRequest)request.clone();
        newRequest.setDn(dn);

        if (newSourceBaseDn != null) {
            if (mapAttributeNames.contains(newRequest.getAttributeName().toLowerCase())) {
                Object value = newRequest.getAttributeValue();
                DN newDn;
                if (value instanceof byte[]) {
                    newDn = new DN(new String((byte[])value));
                } else {
                    newDn = new DN(value.toString());
                }
                newDn = newDn.getPrefix(newSourceBaseDn).append(sourceBaseDn);
                newRequest.setAttributeValue(newDn.toString());
            }
        }

        if (debug) log.debug("Comparing entry "+dn);

        LDAPClient client = connection.getClient(session);

        try {
            client.compare(newRequest, response);

        } finally {
            connection.closeClient(session);
        }

        log.debug("Compare operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Delete
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void delete(
            Session session,
            DeleteRequest request,
            DeleteResponse response
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("Delete "+partition.getName()+"."+getName(), 70));
            log.debug(TextUtil.displayLine(" - DN : "+request.getDn(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        DNBuilder db = new DNBuilder();
        db.append(request.getDn());

        if (hideBaseDn) {
            db.append(sourceBaseDn);
        }

        DN dn = db.toDn();

        if (newSourceBaseDn != null) {
            dn = dn.getPrefix(newSourceBaseDn).append(sourceBaseDn);
        }

        DeleteRequest newRequest = (DeleteRequest)request.clone();
        newRequest.setDn(dn);

        if (debug) log.debug("Deleting entry "+dn);

        LDAPClient client = connection.getClient(session);

        try {
            client.delete(newRequest, response);

        } finally {
            connection.closeClient(session);
        }

        log.debug("Delete operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Modify
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void modify(
            Session session,
            ModifyRequest request,
            ModifyResponse response
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("Modify "+partition.getName()+"."+getName(), 70));
            log.debug(TextUtil.displayLine(" - DN : "+request.getDn(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        DNBuilder db = new DNBuilder();
        db.append(request.getDn());

        if (hideBaseDn) {
            db.append(sourceBaseDn);
        }

        DN dn = db.toDn();

        if (newSourceBaseDn != null) {
            dn = dn.getPrefix(newSourceBaseDn).append(sourceBaseDn);
        }

        ModifyRequest newRequest = (ModifyRequest)request.clone();
        newRequest.setDn(dn);

        if (newSourceBaseDn != null && !mapAttributeNames.isEmpty()) {
            for (Modification modification : newRequest.getModifications()) {
                Attribute attribute = modification.getAttribute();
                if (!mapAttributeNames.contains(attribute.getName().toLowerCase())) continue;

                Collection<Object> values = new ArrayList<Object>();
                for (Object value : attribute.getValues()) {
                    DN newDn = new DN(value.toString());
                    newDn = newDn.getPrefix(newSourceBaseDn).append(sourceBaseDn);
                    values.add(newDn.toString());
                }

                attribute.setValues(values);
            }
        }

        if (debug) log.debug("Modifying entry "+dn);

        LDAPClient client = connection.getClient(session);

        try {
            client.modify(newRequest, response);

        } finally {
            connection.closeClient(session);
        }

        log.debug("Modify operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // ModRDN
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void modrdn(
            Session session,
            ModRdnRequest request,
            ModRdnResponse response
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("ModRdn "+partition.getName()+"."+getName(), 70));
            log.debug(TextUtil.displayLine(" - DN : "+request.getDn(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        DNBuilder db = new DNBuilder();
        db.append(request.getDn());

        if (hideBaseDn) {
            db.append(sourceBaseDn);
        }

        DN dn = db.toDn();

        if (newSourceBaseDn != null) {
            dn = dn.getPrefix(newSourceBaseDn).append(sourceBaseDn);
        }

        ModRdnRequest newRequest = new ModRdnRequest(request);
        newRequest.setDn(dn);

        if (debug) log.debug("Renaming entry "+dn);

        LDAPClient client = connection.getClient(session);

        try {
            client.modrdn(newRequest, response);

        } finally {
            connection.closeClient(session);
        }

        log.debug("Rename operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Search
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void search(
            final Session session,
            final SearchRequest request,
            final SearchResponse response
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("SEARCH "+partition.getName()+"."+getName(), 70));
            log.debug(TextUtil.displayLine(" - Base DN : "+request.getDn(), 70));
            log.debug(TextUtil.displayLine(" - Scope   : "+LDAP.getScope(request.getScope()), 70));
            log.debug(TextUtil.displayLine(" - Filter  : "+request.getFilter(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        if (sourceBaseDn == null || sourceBaseDn.isEmpty()) {
            searchFullTree(session, request, response);

        } else if (sourceScope != SearchRequest.SCOPE_ONE) {
            searchSubTree(session, request, response);

        } else {
            searchFlatTree(session, request, response);
        }

        log.debug("Search operation completed.");
    }

    public void searchFullTree(
            final Session session,
            final SearchRequest request,
            final SearchResponse response
    ) throws Exception {

        final boolean debug = log.isDebugEnabled();
        try {

            DN baseDn = request.getDn();
            int scope = request.getScope();

            final Filter filter = createFilter(request);
            long sizeLimit = createSizeLimit(request);
            long timeLimit = createTimeLimit(request);

            Collection<String> attributes = createAttributes(request);
            Collection<Control> controls = createControls(request);

            LDAPClient client = connection.getClient(session);

            if (baseDn != null && baseDn.isEmpty()) {

                SearchRequest rootRequest = new SearchRequest();
                rootRequest.setScope(SearchRequest.SCOPE_BASE);
                rootRequest.setAttributes(new String[] { "+", "*" });

                SearchResponse rootResponse = new SearchResponse();

                client.search(rootRequest, rootResponse);

                SearchResult root = rootResponse.next();

                if (scope == SearchRequest.SCOPE_BASE || scope == SearchRequest.SCOPE_SUB) {
                    response.add(root);
                }

                if (scope == SearchRequest.SCOPE_ONE || scope == SearchRequest.SCOPE_SUB) {

                    if (debug) log.debug("Naming contexts:");
                    Attribute namingContexts = root.getAttribute("namingContexts");

                    for (Object value : namingContexts.getValues()) {
                        String dn = value.toString();
                        if (debug) log.debug(" - "+dn);

                        SearchRequest newRequest = new SearchRequest();
                        newRequest.setDn(dn);
                        newRequest.setScope(scope == SearchRequest.SCOPE_ONE ? SearchRequest.SCOPE_BASE : scope);

                        newRequest.setFilter(filter);
                        newRequest.setSizeLimit(sizeLimit);
                        newRequest.setTimeLimit(timeLimit);
                        newRequest.setAttributes(attributeNames);
                        newRequest.addAttributes(attributes);
                        newRequest.setControls(controls);

                        SearchResponse newResponse = new Pipeline(response) {
                            public void add(SearchResult searchResult) throws Exception {

                                if (isClosed()) {
                                    if (debug) log.debug("Search response has been closed.");
                                    return;
                                }

                                SearchResult newSearchResult = createSearchResult(sourceBaseDn, searchResult);

                                if (debug) {
                                    newSearchResult.print();
                                }

                                super.add(newSearchResult);
                            }
                            public void close() {
                                // ignore
                            }
                        };

                        client.search(newRequest, newResponse);
                    }
                }

            } else {

                if (sourceScope == SearchRequest.SCOPE_BASE) {
                    if (scope == SearchRequest.SCOPE_ONE) {
                        return;
                    } else {
                        scope = SearchRequest.SCOPE_BASE;
                    }
                }

                SearchRequest newRequest = new SearchRequest();
                newRequest.setDn(baseDn);
                newRequest.setScope(scope);

                newRequest.setFilter(filter);
                newRequest.setSizeLimit(sizeLimit);
                newRequest.setTimeLimit(timeLimit);
                newRequest.setAttributes(attributeNames);
                newRequest.addAttributes(attributes);
                newRequest.setControls(controls);

                SearchResponse newResponse = new Pipeline(response) {
                    public void add(SearchResult searchResult) throws Exception {

                        if (isClosed()) {
                            if (debug) log.debug("Search response has been closed.");
                            return;
                        }

                        SearchResult newSearchResult = createSearchResult(sourceBaseDn, searchResult);

                        if (debug) {
                            newSearchResult.print();
                        }

                        super.add(newSearchResult);
                    }
                    public void close() {
                        // ignore
                    }
                };

                client.search(newRequest, newResponse);
            }

        } finally {
            connection.closeClient(session);
            response.close();
        }
    }

    public void searchSubTree(
            final Session session,
            final SearchRequest request,
            final SearchResponse response
    ) throws Exception {

        final boolean debug = log.isDebugEnabled();
        try {

            if (debug) log.debug("Source "+getName()+" is an LDAP subtree.");

            DN baseDn = request.getDn();

            if (baseDn != null && !baseDn.isEmpty() && newSourceBaseDn != null) {
                baseDn = baseDn.getPrefix(newSourceBaseDn).append(sourceBaseDn);
            }

            int scope = request.getScope();

            final Filter filter = createFilter(request);

            if (newSourceBaseDn != null && !mapAttributeNames.isEmpty()) {
                FilterProcessor fp = new FilterProcessor() {
                    public Filter process(Stack<Filter> path, Filter filter) throws Exception {
                        if (!(filter instanceof SimpleFilter)) {
                            return super.process(path, filter);
                        }

                        SimpleFilter sf = (SimpleFilter)filter;

                        String attribute = sf.getAttribute();
                        if (!mapAttributeNames.contains(attribute.toLowerCase())) return filter;

                        DN dn = new DN(sf.getValue().toString());
                        dn = dn.getPrefix(newSourceBaseDn).append(sourceBaseDn);
                        sf.setValue(dn.toString());

                        return filter;
                    }
                };

                fp.process(filter);
            }

            long sizeLimit = createSizeLimit(request);
            long timeLimit = createTimeLimit(request);

            Collection<String> attributes = createAttributes(request);
            Collection<Control> controls = createControls(request);

            LDAPClient client = connection.getClient(session);

            if (baseDn != null && baseDn.isEmpty()) {

                log.debug("Searching from root entry.");

                if (scope == SearchRequest.SCOPE_BASE || scope == SearchRequest.SCOPE_SUB) {

                    log.debug("Returning root entry.");

                    SearchResult root = client.find(baseDn);

/*
                    SearchResult root = new SearchResult();

                    if (debug) log.debug("Naming contexts:");
                    Attribute namingContexts = new Attribute("namingContexts");

                    String dn = sourceBaseDn.toString();
                    if (debug) log.debug(" - "+dn);

                    namingContexts.addValue(dn);

                    root.setAttribute(namingContexts);
*/
                    response.add(root);
                }

                if (scope == SearchRequest.SCOPE_ONE || scope == SearchRequest.SCOPE_SUB) {

                    log.debug("Returning top entry.");

                    SearchRequest newRequest = new SearchRequest();
                    newRequest.setDn(sourceBaseDn);
                    newRequest.setScope(scope == SearchRequest.SCOPE_ONE ? SearchRequest.SCOPE_BASE : scope);

                    newRequest.setFilter(filter);
                    newRequest.setSizeLimit(sizeLimit);
                    newRequest.setTimeLimit(timeLimit);
                    newRequest.setAttributes(attributeNames);
                    newRequest.addAttributes(attributes);
                    newRequest.setControls(controls);

                    SearchResponse newResponse = new Pipeline(response) {
                        public void add(SearchResult searchResult) throws Exception {

                            if (isClosed()) {
                                if (debug) log.debug("Search response has been closed.");
                                return;
                            }

                            SearchResult newSearchResult = createSearchResult(sourceBaseDn, searchResult);

                            if (debug) {
                                newSearchResult.print();
                            }

                            super.add(newSearchResult);
                        }
                        public void close() {
                            // ignore
                        }
                    };

                    client.search(newRequest, newResponse);
                }

            } else {

                baseDn = baseDn == null ? sourceBaseDn : baseDn;

                if (debug) log.debug("Searching subtree \""+baseDn+"\".");

                if (sourceScope == SearchRequest.SCOPE_BASE) {
                    if (scope == SearchRequest.SCOPE_ONE) {
                        return;
                    } else {
                        scope = SearchRequest.SCOPE_BASE;
                    }
                }

                SearchRequest newRequest = new SearchRequest();
                newRequest.setDn(baseDn);
                newRequest.setScope(scope);

                newRequest.setFilter(filter);
                newRequest.setSizeLimit(sizeLimit);
                newRequest.setTimeLimit(timeLimit);
                newRequest.setAttributes(attributeNames);
                newRequest.addAttributes(attributes);
                newRequest.setControls(controls);

                SearchResponse newResponse = new Pipeline(response) {
                    public void add(SearchResult searchResult) throws Exception {

                        if (isClosed()) {
                            if (debug) log.debug("Search response has been closed.");
                            return;
                        }

                        SearchResult newSearchResult = createSearchResult(sourceBaseDn, searchResult);

                        if (debug) {
                            newSearchResult.print();
                        }

                        super.add(newSearchResult);
                    }
                    public void close() {
                        // ignore
                    }
                };

                client.search(newRequest, newResponse);
            }

        } finally {
            connection.closeClient(session);
            response.close();
        }
    }

    public void searchFlatTree(
            final Session session,
            final SearchRequest request,
            final SearchResponse response
    ) throws Exception {

        final boolean debug = log.isDebugEnabled();
        try {

            if (debug) log.debug("Source "+getName()+" is a flat LDAP tree.");

            DN baseDn = request.getDn();
            int scope = request.getScope();

            final Filter filter = createFilter(request);
            long sizeLimit = createSizeLimit(request);
            long timeLimit = createTimeLimit(request);

            Collection<String> attributes = createAttributes(request);
            Collection<Control> controls = createControls(request);

            LDAPClient client = connection.getClient(session);

            if (baseDn != null && baseDn.isEmpty()) {

                if (scope == SearchRequest.SCOPE_BASE || scope == SearchRequest.SCOPE_SUB) {

                    if (debug) log.debug("Searching root entry.");

                    SearchResult result = new SearchResult();
                    response.add(result);
                }

                if (scope == SearchRequest.SCOPE_ONE || scope == SearchRequest.SCOPE_SUB) {

                    if (debug) log.debug("Searching top entries.");

                    SearchRequest newRequest = new SearchRequest();
                    newRequest.setDn(sourceBaseDn);
                    newRequest.setScope(sourceScope);

                    newRequest.setFilter(filter);
                    newRequest.setSizeLimit(sizeLimit);
                    newRequest.setTimeLimit(timeLimit);
                    newRequest.setAttributes(attributeNames);
                    newRequest.addAttributes(attributes);
                    newRequest.setControls(controls);

                    SearchResponse newResponse = new Pipeline(response) {
                        public void add(SearchResult searchResult) throws Exception {

                            if (isClosed()) {
                                if (debug) log.debug("Search response has been closed.");
                                return;
                            }

                            SearchResult newSearchResult = createSearchResult(sourceBaseDn, searchResult);
                            //DN newDn = new DN(newSearchResult.getDn().getRdn());
                            //newSearchResult.setDn(newDn);

                            if (debug) {
                                newSearchResult.print();
                            }

                            super.add(newSearchResult);
                        }
                        public void close() {
                            // ignore
                        }
                    };

                    client.search(newRequest, newResponse);
                }

            } else if (baseDn != null && (scope == SearchRequest.SCOPE_BASE || scope == SearchRequest.SCOPE_SUB)) {

                DNBuilder db = new DNBuilder();
                db.append(baseDn);

                if (hideBaseDn) {
                    db.append(sourceBaseDn);
                }

                DN dn = db.toDn();

                if (debug) log.debug("Searching entry: "+dn);

                SearchRequest newRequest = new SearchRequest();
                newRequest.setDn(dn);
                newRequest.setScope(SearchRequest.SCOPE_BASE);

                newRequest.setFilter(filter);
                newRequest.setSizeLimit(sizeLimit);
                newRequest.setTimeLimit(timeLimit);
                newRequest.setAttributes(attributeNames);
                newRequest.addAttributes(attributes);
                newRequest.setControls(controls);

                SearchResponse newResponse = new Pipeline(response) {
                    public void add(SearchResult searchResult) throws Exception {

                        if (isClosed()) {
                            if (debug) log.debug("Search response has been closed.");
                            return;
                        }

                        SearchResult newSearchResult = createSearchResult(sourceBaseDn, searchResult);
                        //DN newDn = new DN(newSearchResult.getDn().getRdn());
                        //newSearchResult.setDn(newDn);

                        if (debug) {
                            newSearchResult.print();
                        }

                        super.add(newSearchResult);
                    }
                    public void close() {
                        // ignore
                    }
                };

                client.search(newRequest, newResponse);

            } else if (baseDn == null) {

                if (debug) log.debug("Searching all entries.");

                SearchRequest newRequest = new SearchRequest();
                newRequest.setDn(sourceBaseDn);
                newRequest.setScope(sourceScope);

                newRequest.setFilter(filter);
                newRequest.setSizeLimit(sizeLimit);
                newRequest.setTimeLimit(timeLimit);
                newRequest.setAttributes(attributeNames);
                newRequest.addAttributes(attributes);
                newRequest.setControls(controls);

                SearchResponse newResponse = new Pipeline(response) {
                    public void add(SearchResult searchResult) throws Exception {

                        if (isClosed()) {
                            if (debug) log.debug("Search response has been closed.");
                            return;
                        }

                        SearchResult newSearchResult = createSearchResult(sourceBaseDn, searchResult);
                        //DN newDn = new DN(newSearchResult.getDn().getRdn());
                        //newSearchResult.setDn(newDn);

                        if (debug) {
                            newSearchResult.print();
                        }

                        super.add(newSearchResult);
                    }
                    public void close() {
                        // ignore
                    }
                };

                client.search(newRequest, newResponse);
            }

        } finally {
            connection.closeClient(session);
            response.close();
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Unbind
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void unbind(
            Session session,
            UnbindRequest request,
            UnbindResponse response
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("Unbind "+partition.getName()+"."+getName(), 70));
            log.debug(TextUtil.displayLine(" - DN : "+request.getDn(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        DNBuilder db = new DNBuilder();
        db.append(request.getDn());

        if (hideBaseDn) {
            db.append(sourceBaseDn);
        }

        DN dn = db.toDn();

        UnbindRequest newRequest = (UnbindRequest)request.clone();
        newRequest.setDn(dn);

        if (debug) log.debug("Unbinding as "+dn);

        LDAPClient client = connection.getClient(session);

        try {
            client.unbind(request, response);

        } finally {
            connection.closeClient(session);
        }

        log.debug("Unbind operation completed.");
    }

    public Filter createFilter(SearchRequest operation) throws Exception {
        return FilterTool.appendAndFilter(operation.getFilter(), sourceFilter);
    }
    
    public long createSizeLimit(SearchRequest operation) {
        long sizeLimit = operation.getSizeLimit();
        if (sourceSizeLimit > sizeLimit) sizeLimit = sourceSizeLimit;
        return sizeLimit;
    }

    public long createTimeLimit(SearchRequest operation) {
        long timeLimit = operation.getTimeLimit();
        if (sourceTimeLimit > timeLimit) timeLimit = sourceTimeLimit;
        return timeLimit;
    }

    public Collection<String> createAttributes(SearchRequest operation) {
        Collection<String> attributes = new ArrayList<String>();
        attributes.addAll(getFieldNames());

        if (attributes.isEmpty()) {
            attributes.addAll(operation.getAttributes());
        }

        return attributes;
    }

    public Collection<Control> createControls(SearchRequest operation) {
        return operation.getControls();
    }

    public SearchResult createSearchResult(
            DN baseDn,
            SearchResult sr
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        DN dn = sr.getDn();
        if (newSourceBaseDn != null) {
            dn = dn.getPrefix(sourceBaseDn).append(newSourceBaseDn);
        }
        if (debug) log.debug("Creating search result ["+dn+"]");

        Attributes attributes = sr.getAttributes();
        Attributes newAttributes;

        if (getFields().isEmpty()) {
            newAttributes = (Attributes)attributes.clone();

        } else {
            newAttributes = new Attributes();

            RDN rdn = dn.getRdn();

            if (rdn != null) {
                SchemaManager schemaManager = partition.getSchemaManager();
                for (String name : rdn.getNames()) {
                    String normalizedName = schemaManager.normalizeAttributeName(name);

                    Object value = rdn.get(name);
                    newAttributes.addValue("primaryKey." + normalizedName, value);
                }
            }

            for (Field field : getFields()) {

                String fieldName = field.getName();
                String originalName = field.getOriginalName();

                if ("dn".equals(originalName)) {
                    newAttributes.addValue(fieldName, dn.toString());

                } else {
                    Attribute attr = attributes.remove(originalName);
                    if (attr == null) continue;

                    newAttributes.addValues(fieldName, attr.getValues());
                }
            }
        }

        for (String attributeName : mapAttributeNames) {
            Attribute attribute = newAttributes.get(attributeName);
            if (attribute == null) continue;

            Collection<Object> newValues = new ArrayList<Object>();
            for (Object value : attribute.getValues()) {
                DN dnValue = new DN(value.toString());
                dnValue = dnValue.getPrefix(sourceBaseDn).append(newSourceBaseDn);
                if (debug) log.debug(" - "+attributeName+": "+dnValue);
                newValues.add(dnValue.toString());
            }

            attribute.setValues(newValues);
        }

        return new SearchResult(dn, newAttributes);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Storage
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public void create() throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("Create "+getName(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }
    }

    public void rename(Source newSource) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("Rename "+getName(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }
    }

    public void clear(Session session) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("Clear "+getName(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        final ArrayList<DN> dns = new ArrayList<DN>();

        SearchRequest request = new SearchRequest();

        SearchResponse response = new SearchResponse() {
            public void add(SearchResult result) throws Exception {
                DN dn = result.getDn();
                if (sourceScope == SearchRequest.SCOPE_ONE && sourceBaseDn.matches(dn)) return;
                dns.add(dn);
            }
        };

        search(session, request, response);

        for (int i=dns.size()-1; i>=0; i--) {
            DN dn = dns.get(i);
            delete(session, dn);
        }
    }

    public void drop() throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("Drop "+getName(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }
    }

    public long getCount(Session session) throws Exception {

        final boolean warn = log.isWarnEnabled();
        boolean debug = log.isDebugEnabled();

        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("Count "+sourceConfig.getName(), 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        SearchRequest request = new SearchRequest();

        String baseDn = getParameter(LDAP.BASE_DN);
        request.setDn(baseDn);

        String scope = getParameter(LDAP.SCOPE);
        request.setScope(getScope(scope));

        String filter = getParameter(LDAP.FILTER);
        request.setFilter(filter);

        request.setAttributes(new String[] { "dn" });
        request.setTypesOnly(true);

        SearchResponse response = new SearchResponse() {
            public void add(SearchResult result) throws Exception {
                totalCount++;
                if (warn && (totalCount % 100 == 0)) log.warn("Found "+totalCount+" entries.");
            }
            public void close() throws Exception {
                if (warn && (totalCount % 100 != 0)) log.warn("Found "+totalCount+" entries.");
            }
        };

        LDAPClient client = connection.getClient(session);

        try {
            client.search(request, response);
            return response.getTotalCount();

        } finally {
            connection.closeClient(session);
        }
    }

    public Session createAdminSession() throws Exception {
        SessionManager sessionManager = partition.getPartitionContext().getSessionManager();
        return sessionManager.createAdminSession();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Clone
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public Object clone() throws CloneNotSupportedException {

        LDAPSource source = (LDAPSource)super.clone();

        source.connection       = connection;

        return source;
    }

    public DN getBaseDn() {
        return sourceBaseDn;
    }

    public void setBaseDn(DN baseDn) {
        this.sourceBaseDn = baseDn;
    }

    public int getScope() {
        return sourceScope;
    }

    public void setScope(int scope) {
        this.sourceScope = scope;
    }

    public Filter getFilter() {
        return sourceFilter;
    }

    public void setFilter(Filter filter) {
        this.sourceFilter = filter;
    }

    public String getObjectClasses() {
        return objectClasses;
    }

    public void setObjectClasses(String objectClasses) {
        this.objectClasses = objectClasses;
    }
}
