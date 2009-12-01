package org.safehaus.penrose.backend;

import org.safehaus.penrose.ldap.DeleteResponse;

/**
 * @author Endi S. Dewata
 */
public class PenroseDeleteResponse
        extends PenroseResponse
        implements org.safehaus.penrose.ldapbackend.DeleteResponse {

    DeleteResponse deleteResponse;

    public PenroseDeleteResponse(DeleteResponse deleteResponse) {
        super(deleteResponse);
        this.deleteResponse = deleteResponse;
    }

    public DeleteResponse getDeleteResponse() {
        return deleteResponse;
    }
}
