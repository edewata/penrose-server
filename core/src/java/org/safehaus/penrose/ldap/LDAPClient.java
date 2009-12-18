/**
 * Copyright 2009 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package org.safehaus.penrose.ldap;

import org.ietf.ldap.*;
import org.safehaus.penrose.control.Control;
import org.safehaus.penrose.control.PagedResultsControl;
import org.safehaus.penrose.schema.Schema;
import org.safehaus.penrose.schema.SchemaUtil;
import org.safehaus.penrose.util.BinaryUtil;
import org.safehaus.penrose.util.TextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class LDAPClient implements Cloneable, LDAPAuthHandler {

    public Logger log    = LoggerFactory.getLogger(getClass());

    public final static Collection<String> DEFAULT_BINARY_ATTRIBUTES = Arrays.asList(
        "photo", "personalSignature", "audio", "jpegPhoto", "javaSerializedData",
        "thumbnailPhoto", "thumbnailLogo", "userPassword", "userCertificate",
        "cACertificate", "authorityRevocationList", "certificateRevocationList",
        "crossCertificatePair", "x500UniqueIdentifier"
    );

    public Collection<String> binaryAttributes = new HashSet<String>();

    public LDAPConnectionFactory connectionFactory;
    public LDAPConnection connection;

    public SearchResult rootDSE;
    public Schema schema;

    public String bindDn;
    public byte[] bindPassword;

    public String referral;
    public int pageSize;


    public LDAPClient(String url) throws Exception {
        this(new LDAPConnectionFactory(url), false);
    }

    public LDAPClient(String url, boolean connect) throws Exception {
        this(new LDAPConnectionFactory(url), connect);
    }

    public LDAPClient(Map<String,String> parameters) throws Exception {
        this(new LDAPConnectionFactory(parameters), false);
    }

    public LDAPClient(Map<String,String> parameters, boolean connect) throws Exception {
        this(new LDAPConnectionFactory(parameters), connect);
    }

    public LDAPClient(LDAPConnectionFactory connectionFactory) throws Exception {
        this(connectionFactory, false);
    }

    public LDAPClient(LDAPConnectionFactory connectionFactory, boolean connect) throws Exception {
        this.connectionFactory = connectionFactory;
        init();
        if (connect) connect();
    }

    public void init() throws Exception {

        bindDn       = connectionFactory.bindDn;
        bindPassword = connectionFactory.bindPassword;

        referral     = connectionFactory.referral;
        pageSize     = connectionFactory.pageSize;
        
        binaryAttributes.addAll(connectionFactory.binaryAttributes);
    }

    public synchronized void connect() throws Exception {

        if (connection == null) {
            log.debug("Creating new LDAP connection.");
            connection = connectionFactory.createConnection();
        }

        initConnection();
    }

    public void initConnection() throws Exception {
        
        if (!connection.isConnected()) {
            log.debug("Disconnected, recreating LDAP connection.");
            connectionFactory.connect(connection);
        }

        for (int i=0; i<2; i++) {
            try {
                if (bindDn != null && bindPassword != null) {
                    log.debug("Initializing authenticated connection as ["+bindDn+"] with ["+new String(bindPassword)+"].");
                    connection.bind(3, bindDn, bindPassword);

                } else {
                    log.debug("Initializing anonymous connection.");
                    connection.bind(3, null, null);
                }
                break;
                
            } catch (Exception e) {
                log.debug(e.getMessage(), e);
                if (i == 0) {
                    log.debug("Second attempt...");
                    connectionFactory.connect(connection);
                } else {
                    log.debug("Failed 2 times.");
                    throw e;
                }
            }
        }

        log.debug("Connection initialized.");

        LDAPConstraints constraints = new LDAPConstraints();
        constraints.setReferralHandler(this);

        connection.setConstraints(constraints);
    }

    public LDAPAuthProvider getAuthProvider(com.novell.ldap.LDAPUrl url) {
        log.debug("Creating authentication provider.");
        return new LDAPAuthProvider(bindDn, bindPassword);
    }

    public LDAPAuthProvider getAuthProvider(String host, int port) {
        log.debug("Creating authentication provider.");
        return new LDAPAuthProvider(bindDn, bindPassword);
    }

    public void close() throws Exception {
        log.debug("Closing LDAP connection.");
        if (connection != null) connection.disconnect();
    }

    public synchronized LDAPConnection getConnection() throws Exception {
        connect();
        return connection;
    }

    public void initConstraints(LDAPConstraints constraints) throws Exception {
        boolean referralFollowing = "follow".equals(referral);
        constraints.setReferralFollowing(referralFollowing);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Add
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public synchronized void add(
            AddRequest request,
            AddResponse response
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        boolean warn = log.isWarnEnabled();

        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("LDAP ADD", 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        String dn = request.getDn().toString();
        Attributes attributes = request.getAttributes();

        LDAPAttributeSet attributeSet = convertAttributes(attributes);

        if (warn) log.warn("Adding entry "+dn+".");

        if (debug) {
            log.debug("Attributes:");
            for (Object attr : attributeSet) {
                LDAPAttribute attribute = (LDAPAttribute) attr;
                String name = attribute.getName();

                if (binaryAttributes.contains(name)) {
                    for (byte[] value : attribute.getByteValueArray()) {
                        log.debug(" - " + name + ": " + BinaryUtil.encode(BinaryUtil.BIG_INTEGER, value, 0, 10)+"...");
                    }

                } else {
                    for (String value : attribute.getStringValueArray()) {
                        log.debug(" - " + name + ": " + value);
                    }
                }
            }
        }

        Collection<Control> requestControls = request.getControls();
        if (!requestControls.isEmpty()) {
            log.debug("Request Controls:");
            for (Control control : requestControls) {
                log.debug(" - "+control.getOid());
            }
        }

        LDAPConstraints constraints = new LDAPConstraints();
        initConstraints(constraints);

        constraints.setControls(convertControls(request.getControls()));

        LDAPEntry entry = new LDAPEntry(dn, attributeSet);

        LDAPConnection connection = getConnection();

        try {
            if (debug) log.debug("Executing LDAP add...");

            long startTime = System.currentTimeMillis();

            connection.add(entry, constraints);

            long endTime = System.currentTimeMillis();

            if (debug) log.debug("Elapsed time: "+(endTime - startTime)+" ms");

        } catch (Exception e) {
            log.info("LDAP Result: "+e.getMessage());
            //response.setException(e);
            throw e;
        }

        log.debug("Add operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Bind
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public synchronized void bind(
            BindRequest request,
            BindResponse response
    ) throws Exception {

        boolean warn = log.isWarnEnabled();
        boolean info  = log.isInfoEnabled();
        boolean debug = log.isDebugEnabled();

        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("LDAP BIND", 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        String bindDn = request.getDn().toString();
        byte[] bindPassword = request.getPassword();

        if (warn) log.warn("Binding as "+bindDn+".");
        
        if (debug) {
            if (bindPassword != null) log.debug("Password: "+new String(bindPassword));
        }

        LDAPConnection connection = getConnection();

        if (debug) log.debug("Executing LDAP bind...");

        long startTime = System.currentTimeMillis();

        try {
            connection.bind(3, bindDn, bindPassword);

        } catch (Exception e) {
            if (info) log.info("LDAP Result: "+e.getMessage());
            //response.setException(e);
            throw e;

        } finally {
            long endTime = System.currentTimeMillis();
            if (debug) log.debug("Elapsed time: "+(endTime - startTime)+" ms");
        }

        this.bindDn       = bindDn;
        this.bindPassword = bindPassword;

        log.debug("Bind operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Compare
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public synchronized void compare(
            CompareRequest request,
            CompareResponse response
    ) throws Exception {

        boolean warn = log.isWarnEnabled();
        boolean debug = log.isDebugEnabled();

        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("LDAP COMPARE", 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        String dn = request.getDn().toString();
        String name = request.getAttributeName();
        Object value = request.getAttributeValue();

        if (warn) log.warn("Comparing entry "+dn+".");

        if (debug) {
            if (binaryAttributes.contains(name.toLowerCase())) {
                log.debug(" - " + name + ": " + BinaryUtil.encode(BinaryUtil.BIG_INTEGER, (byte[]) value, 0, 10)+"...");

            } else {
                log.debug(" - " + name + ": " + value);
            }
        }

        LDAPAttribute attr = new LDAPAttribute(name);

        if (value instanceof byte[]) {
            attr.addValue((byte[])value);
        } else {
            attr.addValue(value.toString());
        }

        Collection<Control> requestControls = request.getControls();
        if (!requestControls.isEmpty()) {
            log.debug("Request Controls:");
            for (Control control : requestControls) {
                log.debug(" - "+control.getOid());
            }
        }

        LDAPConstraints constraints = new LDAPConstraints();
        initConstraints(constraints);

        constraints.setControls(convertControls(request.getControls()));

        LDAPConnection connection = getConnection();

        try {
            if (debug) log.debug("Executing LDAP compare...");

            long startTime = System.currentTimeMillis();

            boolean result = connection.compare(dn, attr, constraints);

            long endTime = System.currentTimeMillis();

            if (debug) log.debug("Elapsed time: "+(endTime - startTime)+" ms");

            response.setReturnCode(result ? LDAP.COMPARE_TRUE : LDAP.COMPARE_FALSE);

        } catch (Exception e) {
            log.info("LDAP Result: "+e.getMessage());
            //response.setException(e);
            throw e;
        }

        log.debug("Compare operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Delete
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public synchronized void delete(
            DeleteRequest request,
            DeleteResponse response
    ) throws Exception {

        boolean warn = log.isWarnEnabled();
        boolean debug = log.isDebugEnabled();

        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("LDAP DELETE", 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        String dn = request.getDn().toString();

        if (warn) log.warn("Deleting entry "+dn+".");

        Collection<Control> requestControls = request.getControls();
        if (!requestControls.isEmpty()) {
            log.debug("Request Controls:");
            for (Control control : requestControls) {
                log.debug(" - "+control.getOid());
            }
        }

        LDAPConstraints constraints = new LDAPConstraints();
        initConstraints(constraints);

        constraints.setControls(convertControls(request.getControls()));

        LDAPConnection connection = getConnection();

        try {
            if (debug) log.debug("Executing LDAP delete...");

            long startTime = System.currentTimeMillis();

            connection.delete(dn, constraints);

            long endTime = System.currentTimeMillis();

            if (debug) log.debug("Elapsed time: "+(endTime - startTime)+" ms");

        } catch (Exception e) {
            log.info("LDAP Result: "+e.getMessage());
            //response.setException(e);
            throw e;
        }

        log.debug("Delete operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Find
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public synchronized SearchResult find(String dn) throws Exception {
        return find(new DN(dn));
    }

    public synchronized SearchResult find(DN dn) throws Exception {

        SearchRequest request = new SearchRequest();
        request.setDn(dn);
        request.setScope(SearchRequest.SCOPE_BASE);

        SearchResponse response = new SearchResponse();

        search(request, response);

        if (!response.hasNext()) return null;

        return response.next();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Modify
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public synchronized void modify(
            ModifyRequest request,
            ModifyResponse response
    ) throws Exception {

        boolean warn = log.isWarnEnabled();
        boolean debug = log.isDebugEnabled();

        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("LDAP MODIFY", 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        String dn = request.getDn().toString();
        if (warn) log.warn("Modifying entry "+dn+".");

        Collection<LDAPModification> list = new ArrayList<LDAPModification>();

        for (Modification modification : request.getModifications()) {
            int type = modification.getType();
            Attribute attribute = modification.getAttribute();
            String name = attribute.getName();

            if (debug) {
                log.debug(" - "+LDAP.getModificationOperation(type)+": "+name);

                for (Object value : attribute.getValues()) {
                    if (value instanceof byte[]) {
                        log.debug(" - " + name + ": " + BinaryUtil.encode(BinaryUtil.BIG_INTEGER, (byte[])value, 0, 10)+"...");
                    } else {
                        log.debug(" - " + name + ": " + value);
                    }
                }
            }

            int newType;
            switch (type) {
                case Modification.ADD:
                    newType = LDAPModification.ADD;
                    break;
                case Modification.DELETE:
                    newType = LDAPModification.DELETE;
                    break;
                case Modification.REPLACE:
                    newType = LDAPModification.REPLACE;
                    break;
                default:
                    throw LDAP.createException(LDAP.PROTOCOL_ERROR);
            }

            LDAPAttribute newAttribute = convertAttribute(attribute);
            list.add(new LDAPModification(newType, newAttribute));
        }

        LDAPModification modifications[] = list.toArray(new LDAPModification[list.size()]);

        Collection<Control> requestControls = request.getControls();
        if (!requestControls.isEmpty()) {
            log.debug("Request Controls:");
            for (Control control : requestControls) {
                log.debug(" - "+control.getOid());
            }
        }

        LDAPConstraints constraints = new LDAPConstraints();
        initConstraints(constraints);

        constraints.setControls(convertControls(request.getControls()));

        LDAPConnection connection = getConnection();

        try {
            if (debug) log.debug("Executing LDAP modify...");

            long startTime = System.currentTimeMillis();

            connection.modify(dn, modifications, constraints);

            long endTime = System.currentTimeMillis();

            if (debug) log.debug("Elapsed time: "+(endTime - startTime)+" ms");

        } catch (Exception e) {
            log.info("LDAP Result: "+e.getMessage());
            //response.setException(e);
            throw e;
        }

        log.debug("Modify operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // ModRdn
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public synchronized void modrdn(
            ModRdnRequest request,
            ModRdnResponse response
    ) throws Exception {

        boolean warn = log.isWarnEnabled();
        boolean debug = log.isDebugEnabled();

        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("LDAP MODRDN", 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        String dn = request.getDn().toString();
        String newRdn = request.getNewRdn().toString();
        boolean deleteOldRdn = request.getDeleteOldRdn();

        if (warn) log.warn("Renaming entry "+dn+" to "+newRdn+".");

        Collection<Control> requestControls = request.getControls();
        if (!requestControls.isEmpty()) {
            log.debug("Request Controls:");
            for (Control control : requestControls) {
                log.debug(" - "+control.getOid());
            }
        }

        LDAPConstraints constraints = new LDAPConstraints();
        initConstraints(constraints);

        constraints.setControls(convertControls(request.getControls()));

        LDAPConnection connection = getConnection();

        try {
            if (debug) log.debug("Executing LDAP modrdn...");

            long startTime = System.currentTimeMillis();

            connection.rename(dn, newRdn, deleteOldRdn, constraints);

            long endTime = System.currentTimeMillis();

            if (debug) log.debug("Elapsed time: "+(endTime - startTime)+" ms");

        } catch (Exception e) {
            log.info("LDAP Result: "+e.getMessage());
            //response.setException(e);
            throw e;
        }

        log.debug("Rename operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Search
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public synchronized void search(
            SearchRequest request,
            SearchResponse response
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        try {
            if (debug) {
                log.debug(TextUtil.displaySeparator(70));
                log.debug(TextUtil.displayLine("LDAP SEARCH", 70));
                log.debug(TextUtil.displaySeparator(70));
            }

            String baseDn = request.getDn() == null ? "" : request.getDn().toString();
            String filter = request.getFilter() == null ? "(objectClass=*)" : request.getFilter().toString();
            int scope = request.getScope();

            Collection<String> attributes = request.getAttributes();
            String attributeNames[] = attributes.toArray(new String[attributes.size()]);

            long sizeLimit = request.getSizeLimit();
            long timeLimit = request.getTimeLimit();
            boolean typesOnly = request.isTypesOnly();

            if (debug) {
                log.debug("Base       : "+baseDn);
                log.debug("Scope      : "+LDAP.getScope(scope));
                log.debug("Filter     : "+filter);
                log.debug("Attributes : "+attributes);
                log.debug("Size Limit : "+sizeLimit);
                log.debug("Time Limit : "+timeLimit);
            }

            Collection<Control> requestControls = new ArrayList<Control>();

            PagedResultsControl pagedResultsRequestControl = null;
            byte[] cookie = null;

            Collection<Control> controls = request.getControls();
            if (!controls.isEmpty()) {
                log.debug("Request Controls:");
                for (Control control : controls) {
                    log.debug(" - "+control.getOid());

                    if (control instanceof PagedResultsControl) {
                        pagedResultsRequestControl = (PagedResultsControl)control;

                    } else if (PagedResultsControl.OID.equals(control.getOid())) {
                        pagedResultsRequestControl = new PagedResultsControl(control);
                        control = pagedResultsRequestControl;
                    }

                    requestControls.add(control);
                }
            }

            if (pageSize > 0) {
                if (pagedResultsRequestControl == null) {
                    pagedResultsRequestControl = new PagedResultsControl(pageSize,  false);
                    requestControls.add(pagedResultsRequestControl);

                } else {
                    if (pagedResultsRequestControl.getPageSize() > pageSize) pagedResultsRequestControl.setPageSize(pageSize); 
                }
            }

            LDAPConnection connection = getConnection();

            LDAPSearchConstraints constraints = new LDAPSearchConstraints();
            initConstraints(constraints);

            constraints.setMaxResults((int)sizeLimit);
            constraints.setTimeLimit((int)timeLimit);

            do {
                constraints.setControls(convertControls(requestControls));

                if (debug) log.debug("Executing LDAP search...");

                long startTime = System.currentTimeMillis();

                LDAPSearchResults rs = connection.search(baseDn, scope, filter, attributeNames, typesOnly, constraints);

                long endTime = System.currentTimeMillis();

                if (debug) log.debug("Elapsed time: "+(endTime - startTime)+" ms");
                
                while (rs.hasMore()) {
                    if (response.isClosed()) {
                        if (debug) log.debug("Search response has been closed.");
                        return;
                    }

                    try {
                        LDAPEntry entry = rs.next();
                        //if (debug) log.debug("Entry: ["+entry.getDN()+"]");

                        SearchResult result = createSearchResult(entry);
                        response.add(result);

                    } catch (LDAPReferralException e) {
                        log.debug("Referrals:");
                        for (String ref : e.getReferrals()) {
                            log.debug(" - "+ref);
                        }

                        if ("throw".equals(referral)) {
                            SearchReference reference = createReference(e);
                            response.add(reference);

                        } else { // ignore

                        }
                    }
                }

                LDAPControl[] responseControls = rs.getResponseControls();
                if (responseControls != null && responseControls.length != 0) {
                    log.debug("Response Controls:");
                    for (LDAPControl control : responseControls) {
                        log.debug(" - "+control.getID());

                        if (pagedResultsRequestControl != null && control.getID().equals(PagedResultsControl.OID)) {
                            PagedResultsControl pagedResultsResponseControl = new PagedResultsControl(
                                    control.getID(),
                                    control.getValue(),
                                    control.isCritical()
                            );

                            cookie = pagedResultsResponseControl.getCookie();
                            pagedResultsRequestControl.setCookie(cookie);
                            pagedResultsRequestControl.encodeValue();
                        }

                        response.addControl(new Control(control.getID(), control.getValue(), control.isCritical()));
                    }
                }

                if (cookie != null) {
                    log.debug("Cookie length: "+cookie.length);
                }

            } while (cookie != null && cookie.length > 0);

        } catch (Exception e) {
            log.info("LDAP Result: "+e.getMessage());
            //response.setException(e);
            throw e;

        } finally {
            response.close();
        }

        log.debug("Search operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Unbind
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public synchronized void unbind(
            UnbindRequest request,
            UnbindResponse response
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug(TextUtil.displaySeparator(70));
            log.debug(TextUtil.displayLine("LDAP UNBIND", 70));
            log.debug(TextUtil.displaySeparator(70));
        }

        DN dn = request.getDn();
        
        if (debug) log.debug("Unbinding as "+dn);

        LDAPConnection connection = getConnection();

        try {
            if (debug) log.debug("Executing LDAP unbind...");

            long startTime = System.currentTimeMillis();

            connection.bind(3, null, null);

            long endTime = System.currentTimeMillis();

            if (debug) log.debug("Elapsed time: "+(endTime - startTime)+" ms");

        } catch (Exception e) {
            log.info("LDAP Result: "+e.getMessage());
            //response.setException(e);
            throw e;
        }

        log.debug("Unbind operation completed.");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Miscelleanous
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public SearchResult createSearchResult(
            LDAPEntry entry
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        String dn = entry.getDN();

        Attributes attributes = new Attributes();

        for (Object object : entry.getAttributeSet()) {
            LDAPAttribute ldapAttribute = (LDAPAttribute) object;
            String name = ldapAttribute.getName();

            Attribute attribute = new Attribute(name);

            if (binaryAttributes.contains(name.toLowerCase())) {
                for (byte[] value : ldapAttribute.getByteValueArray()) {
                    //if (debug) log.debug(" - " + name + ": " + BinaryUtil.encode(BinaryUtil.BIG_INTEGER, value, 0, 10)+"...");
                    attribute.addValue(value);
                }

            } else {
                for (String value : ldapAttribute.getStringValueArray()) {
                    //if (debug) log.debug(" - " + name + ": " + value);
                    attribute.addValue(value);
                }
            }

            if (attribute.isEmpty()) {
                //if (debug) log.debug(" - " + name);
            }
            
            attributes.add(attribute);
        }

        return new SearchResult(dn, attributes);
    }

    public SearchReference createReference(LDAPReferralException e) throws Exception {

        DN dn = new DN();

        Collection<String> urls = new ArrayList<String>();
        urls.addAll(Arrays.asList(e.getReferrals()));
/*
        Attributes attributes = new Attributes();
        attributes.addValue("objectClass", "referral");
        attributes.addValue("objectClass", "extensibleObject");

        for (String url : e.getReferences()) {
            urls.add(url);

            if (dn.isEmpty()) {
                LDAPUrl ldapUrl = new LDAPUrl(url);
                dn = new DN(ldapUrl.getDN());
                RDN rdn = dn.getRdn();
                for (String name : rdn.getNames()) {
                    Object value = rdn.get(name);
                    attributes.addValue(name, value);
                }
            }

        }
*/
        return new SearchReference(dn, urls);
    }

    public SearchResult getRootDSE() throws Exception {

        boolean debug = log.isDebugEnabled();
        if (rootDSE != null) return rootDSE;

        if (debug) log.debug("Searching Root DSE ...");

        SearchRequest request = new SearchRequest();
        request.setScope(SearchRequest.SCOPE_BASE);
        request.setAttributes(new String[] { "*", "+" });

        SearchResponse response = new SearchResponse();
        search(request, response);

        if (!response.hasNext()) {
            rootDSE = null;
            return null;
        }

        rootDSE = response.next();

        return rootDSE;
    }

    public Schema getSchema() throws Exception {

        boolean debug = log.isDebugEnabled();
        if (schema != null) return schema;

        getRootDSE();

        if (debug) log.debug("Searching Schema ...");

        try {
            Attribute schemaNamingContext = rootDSE.getAttributes().get("schemaNamingContext");
            Attribute subschemaSubentry = rootDSE.getAttributes().get("subschemaSubentry");

            SchemaUtil schemaUtil = new SchemaUtil();
            String schemaDn;

            if (schemaNamingContext != null) {
                schemaDn = (String)schemaNamingContext.getValue();
                if (debug) log.debug("Active Directory Schema: "+schemaDn);
                schema = schemaUtil.getActiveDirectorySchema(this, schemaDn);

            } else if (subschemaSubentry != null) {
                schemaDn = (String)subschemaSubentry.getValue();
                if (debug) log.debug("Standard LDAP Schema: "+schemaDn);
                schema = schemaUtil.getLDAPSchema(this, schemaDn);

            } else {
                schemaDn = "cn=schema";
                if (debug) log.debug("Default Schema: "+schemaDn);
                schema = schemaUtil.getLDAPSchema(this, schemaDn);
            }

        } catch (Exception e) {
            log.info("LDAP Result: "+e.getMessage());
            throw e;
        }

        return schema;
    }

    public LDAPControl[] convertControls(Collection<org.safehaus.penrose.control.Control> controls) throws Exception {
        Collection<LDAPControl> list = new ArrayList<LDAPControl>();
        for (org.safehaus.penrose.control.Control control : controls) {

            String oid = control.getOid();
            boolean critical = control.isCritical();
            byte[] value = control.getValue();

            list.add(new LDAPControl(oid, critical, value));
        }

        return list.toArray(new LDAPControl[list.size()]);
    }

    public Collection<SearchResult> findChildren(String baseDn) throws Exception {
        return findChildren(new DN(baseDn));
    }

    public Collection<SearchResult> findChildren(DN baseDn) throws Exception {

        boolean debug = log.isDebugEnabled();
        Collection<SearchResult> results = new ArrayList<SearchResult>();

        DNBuilder db = new DNBuilder();
        db.set(baseDn);
        DN searchBase = db.toDn();

        if (searchBase.isEmpty()) {
            SearchResult rootDse = getRootDSE();

            Attributes attributes = rootDse.getAttributes();
            Attribute attribute = attributes.get("namingContexts");

            for (Object value : attribute.getValues()) {
                String dn = (String)value;
                if (debug) log.debug(" - "+dn);

                SearchResult entry = find(dn);
                results.add(entry);
            }

        } else {
            if (debug) log.debug("Searching "+searchBase+":");

            SearchRequest request = new SearchRequest();
            request.setDn(baseDn);
            request.setScope(SearchRequest.SCOPE_ONE);

            SearchResponse response = new SearchResponse();

            search(request, response);

            while (response.hasNext()) {
                SearchResult sr = response.next();
                if (debug) log.debug(" - "+sr.getDn());
                results.add(sr);
            }
        }

        return results;
    }

    public static String[] parseURL(String s) {

        String[] result = new String[4]; // 0 = ldap/ldaps, 1 = hostname, 2 = port, 3 = suffix

        int i = s.indexOf("://");
        if (i < 0) return null;

        result[0] = s.substring(0, i);

        int j = s.indexOf("/", i+3);
        String hostPort;
        if (j > 0) {
            hostPort = s.substring(i+3, j);
            result[3] = s.substring(j+1);
        } else {
            hostPort = s.substring(i+3);
        }

        int k = hostPort.indexOf(":");
        if (k < 0) {
            result[1] = hostPort;
            if ("ldap".equals(result[0])) {
                result[2] = "389";
            } else if ("ldaps".equals(result[0])) {
                result[2] = "636";
            } else {
                return null;
            }
        } else {
            result[1] = hostPort.substring(0, k);
            result[2] = hostPort.substring(k+1);
        }

        return result;
    }

    public void setRootDSE(SearchResult rootDSE) {
        this.rootDSE = rootDSE;
    }

    public void setSchema(Schema schema) {
        this.schema = schema;
    }

    public LDAPAttributeSet convertAttributes(Attributes attributes) throws Exception {

        LDAPAttributeSet attributeSet = new LDAPAttributeSet();
        for (Attribute attribute : attributes.getAll()) {
            attributeSet.add(convertAttribute(attribute));
        }

        return attributeSet;
    }

    public LDAPAttribute convertAttribute(Attribute attribute) throws Exception {

        String name = attribute.getName();
        LDAPAttribute attr = new LDAPAttribute(name);

        for (Object value : attribute.getValues()) {
            if (value instanceof byte[]) {
                attr.addValue((byte[])value);
            } else {
                attr.addValue(value.toString());
            }
        }

        return attr;
    }

    public LDAPModification[] convertModifications(Collection<Modification> modifications) throws Exception {
        Collection<LDAPModification> list = new ArrayList<LDAPModification>();

        for (Modification modification : modifications) {
            int type = modification.getType();
            Attribute attribute = modification.getAttribute();

            LDAPAttribute attr = convertAttribute(attribute);
            list.add(new LDAPModification(type, attr));
        }

        return list.toArray(new LDAPModification[list.size()]);
    }

    public String escape(RDN rdn) {
        return escape(rdn.toString());
    }

    public String escape(DN dn) {
        return escape(dn.toString());
    }

    public String escape(String string) {
        boolean debug = log.isDebugEnabled();
        String s = string.replaceAll("/", "\\\\/");
        if (debug) log.debug("Escape ["+string+"] => ["+s+"].");
        return s;
    }

    public Object clone() throws CloneNotSupportedException {

        LDAPClient client = (LDAPClient)super.clone();

        client.binaryAttributes = new ArrayList<String>();
        client.binaryAttributes.addAll(binaryAttributes);

        client.rootDSE = rootDSE;
        client.schema = schema;

        client.pageSize = pageSize;

        try {
            if (connection != null) client.connection = (LDAPConnection)connection.clone();

        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        return client;
    }
}
