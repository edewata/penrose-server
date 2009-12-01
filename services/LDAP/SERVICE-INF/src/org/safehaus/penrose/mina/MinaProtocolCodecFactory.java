package org.safehaus.penrose.mina;

import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.apache.mina.filter.codec.ProtocolEncoder;
import org.apache.mina.filter.codec.ProtocolDecoder;
import org.apache.directory.shared.asn1.codec.Asn1CodecEncoder;
import org.apache.directory.shared.asn1.codec.Asn1CodecDecoder;
import org.apache.directory.shared.ldap.message.MessageEncoder;
import org.apache.directory.shared.ldap.message.MessageDecoder;

import java.util.Hashtable;

/**
 * @author Endi S. Dewata
 */
public class MinaProtocolCodecFactory implements ProtocolCodecFactory {

    Hashtable<Object,Object> env;

    public MinaProtocolCodecFactory() {
        env = new Hashtable<Object,Object>();
    }
    
    public MinaProtocolCodecFactory(Hashtable<Object,Object> env) {
        this.env = env;
    }

    public ProtocolEncoder getEncoder() {
        return new Asn1CodecEncoder(new MessageEncoder(env));
    }

    public ProtocolDecoder getDecoder() {
        return new Asn1CodecDecoder(new MessageDecoder(env));
    }
}
