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

import com.google.common.base.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.ECGenParameterSpec;
import java.util.Objects;
import java.util.function.Supplier;

class AlgorithmKit {

    private static final Logger log = LogManager.getLogger(AlgorithmKit.class);

    private final String signatureAlgorithmName;
    private final Supplier<KeyPair> keyPariSupplier;

    private AlgorithmKit(String signatureAlgorithmName, Supplier<KeyPair> keyPariSupplier) {
        notEmptyAlgorithmName(signatureAlgorithmName);
        this.signatureAlgorithmName = signatureAlgorithmName;
        this.keyPariSupplier = Objects.requireNonNull(keyPariSupplier, "Key pair supplier is required.");
    }

    private static void notEmptyAlgorithmName(String signatureAlgorithmName) {
        if(Strings.isNullOrEmpty(signatureAlgorithmName)){
            throw new CertificateException("Algorithm name is required.");
        }
    }

    public static AlgorithmKit ecdsaSha256withEcdsa(Provider securityProvider, String ellipticCurve) {
        notEmptyAlgorithmName(ellipticCurve);
        Supplier<KeyPair> supplier = ecdsaKeyPairSupplier(securityProvider, ellipticCurve);
        return new AlgorithmKit("SHA256withECDSA", supplier);
    }

    public static AlgorithmKit rsaSha256withRsa(Provider securityProvider, int keySize) {
        positiveKeySize(keySize);
        Supplier<KeyPair> supplier = rsaKeyPairSupplier(securityProvider, keySize);
        return new AlgorithmKit("SHA256withRSA", supplier);
    }

    private static void positiveKeySize(int keySize) {
        if(keySize <= 0) {
            throw new CertificateException("Key size must be a positive integer value, provided: " + keySize);
        }
    }

    public String getSignatureAlgorithmName(){
        return signatureAlgorithmName;
    }

    public KeyPair generateKeyPair(){
        return keyPariSupplier.get();
    }
    private static Supplier<KeyPair> rsaKeyPairSupplier(Provider securityProvider, int keySize) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", securityProvider);
            log.info("Initialize key pair generator with keySize: {}", keySize);
            generator.initialize(keySize);
            return generator::generateKeyPair;
        } catch (NoSuchAlgorithmException e) {
            String message = "Error while initializing RSA asymmetric key generator.";
            log.error(message, e);
            throw new CertificateException(message, e);
        }
    }

    private static Supplier<KeyPair> ecdsaKeyPairSupplier(Provider securityProvider, String ellipticCurve) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", securityProvider);
            log.info("Initialize key pair generator with elliptic curve: {}", ellipticCurve);
            ECGenParameterSpec ecsp = new ECGenParameterSpec(ellipticCurve);
            generator.initialize(ecsp);
            return generator::generateKeyPair;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            String message = "Error while initializing ECDSA asymmetric key generator.";
            log.error(message, e);
            throw new CertificateException(message, e);
        }
    }

}
