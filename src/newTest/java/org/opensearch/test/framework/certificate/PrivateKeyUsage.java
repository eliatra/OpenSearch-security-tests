package org.opensearch.test.framework.certificate;

import org.bouncycastle.asn1.x509.KeyUsage;

enum PrivateKeyUsage {
    DIGITAL_SIGNATURE(KeyUsage.digitalSignature),
    KEY_CERT_SIGN(KeyUsage.keyCertSign),
    CRL_SIGN(KeyUsage.cRLSign),
    NON_REPUDIATION(KeyUsage.nonRepudiation),
    KEY_ENCIPHERMENT(KeyUsage.keyEncipherment);

    private final int keyUsage;

    PrivateKeyUsage(int keyUsage) {
        this.keyUsage = keyUsage;
    }

    int asInt(){
        return keyUsage;
    }
}
