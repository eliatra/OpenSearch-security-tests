package org.opensearch.test.framework.certificate;

import org.bouncycastle.asn1.x509.KeyPurposeId;

enum ExtendedPrivateKeyUsage {
    ID_KP_SERVERAUTH(KeyPurposeId.id_kp_serverAuth),
    ID_KP_CLIENTAUTH(KeyPurposeId.id_kp_clientAuth);
    private final KeyPurposeId id;

    ExtendedPrivateKeyUsage(KeyPurposeId id) {
        this.id = id;
    }

    KeyPurposeId getKeyPurposeId() {
        return id;
    }
}
