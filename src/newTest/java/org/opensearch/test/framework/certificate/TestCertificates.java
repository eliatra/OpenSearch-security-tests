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
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.opensearch.test.framework.certificate.PublicKeyUsage.CLIENT_AUTH;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.CRL_SIGN;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.DIGITAL_SIGNATURE;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.KEY_CERT_SIGN;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.KEY_ENCIPHERMENT;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.NON_REPUDIATION;
import static org.opensearch.test.framework.certificate.PublicKeyUsage.SERVER_AUTH;

/**
 * It provides TLS certificates required in test cases. The certificates are generated during process of creation objects of the class.
 * The class exposes method which can be used to write certificates and private keys in temporally files.
 */
public class TestCertificates {

    public static final Integer MAX_NUMBER_OF_NODE_CERTIFICATES = 3;

    private static final String CA_SUBJECT = "DC=com,DC=example,O=Example Com Inc.,OU=Example Com Inc. Root CA,CN=Example Com Inc. Root CA";
    private static final String ADMIN_DN = "CN=kirk,OU=client,O=client,L=test,C=de";
    private static final int CERTIFICATE_VALIDITY_DAYS = 365;
    private static final String CERTIFICATE_FILE_EXTENSION = ".cert";
    private static final String KEY_FILE_EXTENSION = ".key";
    private final CertificateData caCertificate;

    private final CertificateData adminCertificate;
    private final List<CertificateData> nodeCertificates;

    public TestCertificates() {
        this.caCertificate = createCaCertificate();
        this.nodeCertificates = IntStream.range(0, MAX_NUMBER_OF_NODE_CERTIFICATES)
            .mapToObj(this::createNodeCertificate)
            .collect(Collectors.toList());
        this.adminCertificate = createAdminCertificate();
    }


    private CertificateData createCaCertificate() {
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(CA_SUBJECT, CERTIFICATE_VALIDITY_DAYS)
                .withKeyUsage(true, DIGITAL_SIGNATURE, KEY_CERT_SIGN, CRL_SIGN);
        return CertificatesIssuerFactory
                .rsaBaseCertificateIssuer()
                .issueSelfSignedCertificate(metadata);
    }

    private CertificateData createAdminCertificate() {
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(ADMIN_DN, CERTIFICATE_VALIDITY_DAYS)
                .withKeyUsage(false, DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, CLIENT_AUTH);
        return CertificatesIssuerFactory
                .rsaBaseCertificateIssuer()
                .issueSelfSignedCertificate(metadata);
    }

    /**
     * It returns the most trusted certificate. Certificates for nodes and users are derived from this certificate.
     * @return file which contains certificate in PEM format, defined by <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>
     * @throws IOException
     */
    public File getRootCertificate() throws IOException {
    	return createTempFile("root", CERTIFICATE_FILE_EXTENSION, caCertificate.certificateInPemFormat());
    }

    /**
     * Certificate for Open Search node. The certificate is derived from root certificate, returned by method {@link #getRootCertificate()}
     * @param node is a node index. It has to be less than {@link #MAX_NUMBER_OF_NODE_CERTIFICATES}
     * @return file which contains certificate in PEM format, defined by <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>
     * @throws IOException
     */
    public File getNodeCertificate(int node) throws IOException {
        isCorrectNodeNumber(node);
        CertificateData certificateData = nodeCertificates.get(node);
        return createTempFile("node-" + node, CERTIFICATE_FILE_EXTENSION, certificateData.certificateInPemFormat());
    }

    private void isCorrectNodeNumber(int node) {
        if (node >= MAX_NUMBER_OF_NODE_CERTIFICATES) {
            String message = String.format("Cannot get certificate for node %d, number of created certificates for nodes is %d", node,
                    MAX_NUMBER_OF_NODE_CERTIFICATES);
            throw new RuntimeException(message);
        }
    }

    private CertificateData createNodeCertificate(Integer node) {
        String subject = String.format("DC=de,L=test,O=node,OU=node,CN=node-%d.example.com", node);
        String domain = String.format("node-%d.example.com", node);
        CertificateMetadata metadata = CertificateMetadata.basicMetadata(subject, CERTIFICATE_VALIDITY_DAYS)
                .withKeyUsage(false, DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, CLIENT_AUTH, SERVER_AUTH)
                .withSubjectAlternativeName("1.2.3.4.5.5", List.of(domain, "localhost"), "127.0.0.1");
        return CertificatesIssuerFactory
                .rsaBaseCertificateIssuer()
                .issueSignedCertificate(metadata, caCertificate);
    }

    /**
     * It returns private key associated with node certificate returned by method {@link #getNodeCertificate(int)}
     *
     * @param node is a node index. It has to be less than {@link #MAX_NUMBER_OF_NODE_CERTIFICATES}
     * @param privateKeyPassword is a password used to encode private key, can be <code>null</code> to retrieve unencrypted key.
     * @return file which contains private key encoded in PEM format, defined
     * by <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>
     * @throws IOException
     */
    public File getNodeKey(int node, String privateKeyPassword) throws IOException {
        CertificateData certificateData = nodeCertificates.get(node);
    	return createTempFile("node-" + node, KEY_FILE_EXTENSION, certificateData.privateKeyInPemFormat(privateKeyPassword));
    }

    /**
     * Certificate which proofs admin user identity. Certificate is derived from root certificate returned by
     * method {@link #getRootCertificate()}
     * @return file which contains certificate in PEM format, defined by <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>
     * @throws IOException
     */
    public File getAdminCertificate() throws IOException {
    	return createTempFile("admin", CERTIFICATE_FILE_EXTENSION, adminCertificate.certificateInPemFormat());
    }

    /**
     * It returns private key associated with admin certificate returned by {@link #getAdminCertificate()}.
     *
     * @param privateKeyPassword is a password used to encode private key, can be <code>null</code> to retrieve unencrypted key.
     * @return file which contains private key encoded in PEM format, defined
     * by <a href="https://www.rfc-editor.org/rfc/rfc1421.txt">RFC 1421</a>
     * @throws IOException
     */
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
