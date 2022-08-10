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
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class RSAAsymmetricCryptographyAlgorithm implements AsymmetricCryptographyAlgorithm {

    private static final Logger log = LogManager.getLogger(RSAAsymmetricCryptographyAlgorithm.class);
    private final KeyPairGenerator generator;

    public RSAAsymmetricCryptographyAlgorithm(Provider securityProvider, int keySize) {
        try {
            this.generator = KeyPairGenerator.getInstance("RSA", securityProvider);
            log.info("Initialize key pair generator with keySize: {}", keySize);
            this.generator.initialize(keySize);
        } catch (NoSuchAlgorithmException e) {
            String message = "Error while initializing RSA asymmetric key generator.";
            log.error(message, e);
            throw new CertificateException(message, e);
        }
    }

    @Override
    public String getSignatureAlgorithmName() {
        return "SHA256withRSA";
    }

    @Override
    public KeyPair generateKeyPair() {
        log.info("Create key pair");
        return generator.generateKeyPair();
    }
}
