package org.safehaus.penrose.backend;

import org.safehaus.penrose.ldap.ModRdnRequest;
import org.safehaus.penrose.ldapbackend.DN;
import org.safehaus.penrose.ldapbackend.RDN;

/**
 * @author Endi S. Dewata
 */
public class PenroseModRdnRequest
        extends PenroseRequest
        implements org.safehaus.penrose.ldapbackend.ModRdnRequest {

    ModRdnRequest modRdnRequest;

    public PenroseModRdnRequest(ModRdnRequest modRdnRequest) {
        super(modRdnRequest);
        this.modRdnRequest = modRdnRequest;
    }

    public void setDn(DN dn) throws Exception {
        PenroseDN penroseDn = (PenroseDN)dn;
        modRdnRequest.setDn(penroseDn.getDn());
    }

    public DN getDn() throws Exception {
        return new PenroseDN(modRdnRequest.getDn());
    }

    public void setNewRdn(RDN rdn) throws Exception {
        PenroseRDN penroseRdn = (PenroseRDN)rdn;
        modRdnRequest.setNewRdn(penroseRdn.getRdn());
    }

    public RDN getNewRdn() throws Exception {
        return new PenroseRDN(modRdnRequest.getNewRdn());
    }

    public void setDeleteOldRdn(boolean deleteOldRdn) throws Exception {
        modRdnRequest.setDeleteOldRdn(deleteOldRdn);
    }

    public boolean getDeleteOldRdn() throws Exception {
        return modRdnRequest.getDeleteOldRdn();
    }

    public ModRdnRequest getModRdnRequest() {
        return modRdnRequest;
    }
}
