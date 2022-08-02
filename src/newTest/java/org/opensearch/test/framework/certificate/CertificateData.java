/*
 * Copyright 2021 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.test.framework.certificate;

import java.security.KeyPair;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

class CertificateData {

    private final X509CertificateHolder certificate;
    private final KeyPair keyPair;

    public CertificateData(X509CertificateHolder certificate, KeyPair keyPair) {
        this.certificate = certificate;
        this.keyPair = keyPair;
    }

    public String certificateInPemFormat() {
        return CertificateAndPrivateKeyWriter.writeCertificate(certificate);
    }

    public String privateKeyInPemFormat(String privateKeyPassword) {
        return CertificateAndPrivateKeyWriter.writePrivateKey(keyPair.getPrivate(), privateKeyPassword);
    }

    public X509CertificateHolder getCertificate() {
        return certificate;
    }


    X500Name getCertificateSubject() {
        return certificate.getSubject();
    }

    KeyPair getKeyPair() {
        return keyPair;
    }
}
