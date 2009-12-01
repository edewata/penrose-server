package org.safehaus.penrose.backend;

import org.safehaus.penrose.ldap.UnbindResponse;

/**
 * @author Endi S. Dewata
 */
public class PenroseUnbindResponse
        extends PenroseResponse
        implements org.safehaus.penrose.ldapbackend.UnbindResponse {

    UnbindResponse unbindResponse;

    public PenroseUnbindResponse(UnbindResponse unbindResponse) {
        super(unbindResponse);
        this.unbindResponse = unbindResponse;
    }

    public UnbindResponse getUnbindResponse() {
        return unbindResponse;
    }
}
