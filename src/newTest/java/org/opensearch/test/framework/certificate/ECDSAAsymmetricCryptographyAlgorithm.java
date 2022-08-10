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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.ECGenParameterSpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class ECDSAAsymmetricCryptographyAlgorithm implements AsymmetricCryptographyAlgorithm {

    private static final Logger log = LogManager.getLogger(ECDSAAsymmetricCryptographyAlgorithm.class);
    private final KeyPairGenerator generator;

    public ECDSAAsymmetricCryptographyAlgorithm(Provider securityProvider, String ellipticCurve) {
        try {
            this.generator = KeyPairGenerator.getInstance("EC", securityProvider);
            log.info("Initialize key pair generator with elliptic curve: {}", ellipticCurve);
            ECGenParameterSpec ecsp = new ECGenParameterSpec(ellipticCurve);
            generator.initialize(ecsp);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            String message = "Error while initializing ECDSA asymmetric key generator.";
            log.error(message, e);
            throw new CertificateException(message, e);
        }
    }

    @Override
    public String getSignatureAlgorithmName() {
        return "SHA256withECDSA";
    }

    @Override
    public KeyPair generateKeyPair() {
        log.info("Create key pair");
        return generator.generateKeyPair();
    }

}
