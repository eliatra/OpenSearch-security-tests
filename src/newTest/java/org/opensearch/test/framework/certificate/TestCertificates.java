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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static org.opensearch.test.framework.certificate.ExtendedPrivateKeyUsage.ID_KP_CLIENTAUTH;
import static org.opensearch.test.framework.certificate.ExtendedPrivateKeyUsage.ID_KP_SERVERAUTH;
import static org.opensearch.test.framework.certificate.PrivateKeyUsage.*;

/**
 * Provides TLS certificates required in test cases.
 * WIP At the moment the certificates are hard coded. 
 * This will be replaced by classes
 * that can generate certificates on the fly.
 */
public class TestCertificates {

    private static final String CA_SUBJECT = "DC=com,DC=example,O=Example Com Inc.,OU=Example Com Inc. Root CA,CN=Example Com Inc. Root CA";
    private static final String ADMIN_DN = "CN=kirk,OU=client,O=client,L=test,C=de";
    private static final int CERTIFICATE_VALIDITY_DAYS = 365;
    private static final String CERTIFICATE_FILE_EXTENSION = ".cert";
    private static final String KEY_FILE_EXTENSION = ".key";
    private final CertificateData caCertificate;

    private final CertificateData adminCertificate;
    private final Map<Integer, CertificateData> nodeCertificates;

    public TestCertificates() {
        this.nodeCertificates = Collections.synchronizedMap(new HashMap<>());
        Set<PrivateKeyUsage> keyUsage = EnumSet.of(DIGITAL_SIGNATURE, KEY_CERT_SIGN, CRL_SIGN);
        this.caCertificate = createCaCertificate(keyUsage);
        this.adminCertificate = createAdminCertificate();
    }

    private CertificateData createCaCertificate(Set<PrivateKeyUsage> keyUsage) {
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(CA_SUBJECT, CERTIFICATE_VALIDITY_DAYS)
                .withKeyUsage(true, keyUsage);
        return CertificatesIssuerFactory
                .rsaBaseCertificateIssuer()
                .issueSelfSignedCertificate(metadata);
    }

    private CertificateData createAdminCertificate() {
        Set<PrivateKeyUsage> keyUsage = EnumSet.of(DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT);
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(ADMIN_DN, CERTIFICATE_VALIDITY_DAYS)
                .withKeyUsage(false, keyUsage, ID_KP_CLIENTAUTH);
        return CertificatesIssuerFactory
                .rsaBaseCertificateIssuer()
                .issueSelfSignedCertificate(metadata);
    }

    public File getRootCertificate() throws IOException {
    	return createTempFile("root", CERTIFICATE_FILE_EXTENSION, caCertificate.certificateInPemFormat());
    }

    public File getNodeCertificate(int node) throws IOException {
        CertificateData certificateData = getOrCreateNodeCertificateData(node);
        return createTempFile("node-" + node, CERTIFICATE_FILE_EXTENSION, certificateData.certificateInPemFormat());
    }

    private CertificateData getOrCreateNodeCertificateData(int node) {
        return nodeCertificates.computeIfAbsent(node, this::createNodeCertificate);
    }

    private CertificateData createNodeCertificate(Integer node) {
        String subject = String.format("DC=de,L=test,O=node,OU=node,CN=node-%d.example.com", node);
        Set<PrivateKeyUsage> keyUsages = EnumSet.of(DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT);
        String domain = String.format("node-%d.example.com", node);
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(subject, CERTIFICATE_VALIDITY_DAYS)
                .withKeyUsage(false, keyUsages, ID_KP_CLIENTAUTH, ID_KP_SERVERAUTH)
                .withSubjectAlternativeName("1.2.3.4.5.5", List.of(domain, "localhost"), "127.0.0.1");
        return CertificatesIssuerFactory
                .rsaBaseCertificateIssuer()
                .issueSignedCertificate(metadata, caCertificate);
    }

    public File getNodeKey(int node, String privateKeyPassword) throws IOException {
        CertificateData certificateData = getOrCreateNodeCertificateData(node);
    	return createTempFile("node-" + node, KEY_FILE_EXTENSION, certificateData.privateKeyInPemFormat(privateKeyPassword));
    }

    public File getAdminCertificate() throws IOException {
    	return createTempFile("admin", CERTIFICATE_FILE_EXTENSION, adminCertificate.certificateInPemFormat());
    }

    public File getAdminKey(String privateKeyPassword) throws IOException {
    	return createTempFile("admin", KEY_FILE_EXTENSION, adminCertificate.privateKeyInPemFormat(privateKeyPassword));
    }

    public String[] getAdminDNs() {
    	return new String[] {ADMIN_DN};
    }

    private File createTempFile(String name, String suffix, String contents) throws IOException {
    	Path path = Files.createTempFile(name, suffix);
    	Files.writeString(path, contents);
    	return path.toFile();
    	
    }
}
