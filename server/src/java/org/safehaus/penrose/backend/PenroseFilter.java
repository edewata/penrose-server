package org.safehaus.penrose.backend;

import org.safehaus.penrose.filter.Filter;


/**
 * @author Endi S. Dewata
 */
public class PenroseFilter implements org.safehaus.penrose.ldapbackend.Filter {

    Filter filter;

    public PenroseFilter(Filter filter) {
        this.filter = filter;
    }

    public Filter getFilter() {
        return filter;
    }

    public String toString() {
        return filter == null ? "(objectClass=*)" : filter.toString();
    }
}
