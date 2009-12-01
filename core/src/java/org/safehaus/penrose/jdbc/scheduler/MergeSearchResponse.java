package org.safehaus.penrose.jdbc.scheduler;

import org.safehaus.penrose.ldap.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Endi S. Dewata
 */
public class MergeSearchResponse extends SearchResponse {

    public Logger log = LoggerFactory.getLogger(getClass());

    SearchResponse response;

    DN lastDn;
    SourceAttributes lastSourceValues;

    public MergeSearchResponse(
            SearchResponse response
    ) throws Exception {
        this.response = response;
    }

    public void add(SearchResult result) throws Exception {

        boolean debug = log.isDebugEnabled();

        DN dn = result.getDn();

        if (debug) {
            log.debug("Synchronizing "+dn);
        }

        SourceAttributes sv = result.getSourceAttributes();

        if (lastDn == null) {
            if (debug) log.debug("Generating entry "+dn);
            lastDn = dn;
            lastSourceValues = sv;

        } else if (lastDn.equals(dn)) {
            if (debug) log.debug("Merging entry " + dn);
            lastSourceValues.add(sv);

        } else {
            if (debug) log.debug("Returning entry " + lastDn);
            SearchResult searchResult = new SearchResult();
            searchResult.setDn(lastDn);
            searchResult.setSourceAttributes(lastSourceValues);
            response.add(searchResult);

            if (debug) log.debug("Generating entry "+dn);
            lastDn = dn;
            lastSourceValues = sv;
        }
    }

    public void close() throws Exception {

        boolean debug = log.isDebugEnabled();

        if (lastDn != null) {
            if (debug) log.debug("Returning entry " + lastDn);
            SearchResult searchResult = new SearchResult();
            searchResult.setDn(lastDn);
            searchResult.setSourceAttributes(lastSourceValues);
            response.add(searchResult);
        }

        response.close();
    }
}
