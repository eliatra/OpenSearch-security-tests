package org.opensearch.test.framework.certificate;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.util.Objects;

enum PrivateKeyUsage {
    DIGITAL_SIGNATURE(KeyUsage.digitalSignature),
    KEY_CERT_SIGN(KeyUsage.keyCertSign),
    CRL_SIGN(KeyUsage.cRLSign),
    NON_REPUDIATION(KeyUsage.nonRepudiation),
    KEY_ENCIPHERMENT(KeyUsage.keyEncipherment),

    ID_KP_SERVERAUTH(KeyPurposeId.id_kp_serverAuth),

    ID_KP_CLIENTAUTH(KeyPurposeId.id_kp_clientAuth);

    private final int keyUsage;
    private final KeyPurposeId id;

    PrivateKeyUsage(int keyUsage) {
        this.keyUsage = keyUsage;
        this.id = null;
    }

    PrivateKeyUsage(KeyPurposeId id) {
        this.id = Objects.requireNonNull(id, "Key purpose id is required.");
        this.keyUsage = 0;
    }

    boolean isExtendedUsage() {
        return this.id != null;
    }

    boolean isNotExtendedUsage() {
        return this.id == null;
    }

    int asInt(){
        if(isExtendedUsage()) {
            throw new CertificateException("Integer value is not available for extended key usage");
        }
        return keyUsage;
    }
    KeyPurposeId getKeyPurposeId() {
        if(isExtendedUsage() == false){
            throw new CertificateException("Key purpose id is not available.");
        }
        return id;
    }
}
