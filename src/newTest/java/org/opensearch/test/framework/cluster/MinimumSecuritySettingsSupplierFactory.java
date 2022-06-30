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

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.test.framework.cluster;

import java.io.IOException;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.framework.certificate.TestCertificates;

public class MinimumSecuritySettingsSupplierFactory {

	private TestCertificates testCertificates;

	public MinimumSecuritySettingsSupplierFactory(TestCertificates testCertificates) {
		if (testCertificates == null) {
			throw new IllegalArgumentException("certificates must not be null");
		}
		this.testCertificates = testCertificates;

	}

	public NodeSettingsSupplier minimumOpenSearchSettings(Settings other) {
		return i -> minimumOpenSearchSettingsBuilder(i, false).put(other).build();
	}

	public NodeSettingsSupplier minimumOpenSearchSettingsSslOnly(Settings other) {
		return i -> minimumOpenSearchSettingsBuilder(i, true).put(other).build();
	}

	private Settings.Builder minimumOpenSearchSettingsBuilder(int node, boolean sslOnly) {

		Settings.Builder builder = Settings.builder();
		
		
		try {
			builder.put("plugins.security.ssl.transport.pemtrustedcas_filepath", testCertificates.getRootCertificate().getAbsolutePath());			
			builder.put("plugins.security.ssl.transport.pemcert_filepath", testCertificates.getNodeCertificate(node).getAbsolutePath());
			builder.put("plugins.security.ssl.transport.pemkey_filepath", testCertificates.getNodeKey(node).getAbsolutePath());
						
			builder.put("plugins.security.ssl.http.pemtrustedcas_filepath", testCertificates.getRootCertificate().getAbsolutePath());
			builder.put("plugins.security.ssl.http.pemcert_filepath", testCertificates.getNodeCertificate(node).getAbsolutePath());
			builder.put("plugins.security.ssl.http.pemkey_filepath", testCertificates.getNodeKey(node).getAbsolutePath());
			
		} catch (IOException e) {
			throw new IllegalArgumentException("Invalid test certificates provided on local cluster start");
		}
//
//            if (certificateWithKeyPairAndPrivateKeyPassword.getCertificateType() == CertificateType.node_transport) {
//                builder.put("searchguard.ssl.transport.pemcert_filepath",
//                                certificateWithKeyPairAndPrivateKeyPassword.getCertificateFile().getAbsolutePath())
//                        .put("searchguard.ssl.transport.pemkey_filepath",
//                                certificateWithKeyPairAndPrivateKeyPassword.getPrivateKeyFile().getAbsolutePath());
//                Optional.ofNullable(certificateWithKeyPairAndPrivateKeyPassword.getPrivateKeyPassword())
//                        .ifPresent(privateKeyPassword -> builder.put("searchguard.ssl.transport.pemkey_password", privateKeyPassword));
//            } else if (certificateWithKeyPairAndPrivateKeyPassword.getCertificateType() == CertificateType.node_rest) {
//                builder.put("searchguard.ssl.http.pemcert_filepath",
//                                certificateWithKeyPairAndPrivateKeyPassword.getCertificateFile().getAbsolutePath())
//                        .put("searchguard.ssl.http.pemkey_filepath",
//                                certificateWithKeyPairAndPrivateKeyPassword.getPrivateKeyFile().getAbsolutePath());
//                Optional.ofNullable(certificateWithKeyPairAndPrivateKeyPassword.getPrivateKeyPassword())
//                        .ifPresent(privateKeyPassword -> builder.put("searchguard.ssl.http.pemkey_password", privateKeyPassword));
//            } else if (certificateWithKeyPairAndPrivateKeyPassword.getCertificateType() == CertificateType.node_transport_rest) {
//                builder.put("searchguard.ssl.transport.pemcert_filepath",
//                                certificateWithKeyPairAndPrivateKeyPassword.getCertificateFile().getAbsolutePath())
//                        .put("searchguard.ssl.transport.pemkey_filepath",
//                                certificateWithKeyPairAndPrivateKeyPassword.getPrivateKeyFile().getAbsolutePath());
//                Optional.ofNullable(certificateWithKeyPairAndPrivateKeyPassword.getPrivateKeyPassword())
//                        .ifPresent(privateKeyPassword -> builder.put("searchguard.ssl.transport.pemkey_password", privateKeyPassword));
//
//                builder.put("searchguard.ssl.http.pemcert_filepath",
//                                certificateWithKeyPairAndPrivateKeyPassword.getCertificateFile().getAbsolutePath())
//                        .put("searchguard.ssl.http.pemkey_filepath",
//                                certificateWithKeyPairAndPrivateKeyPassword.getPrivateKeyFile().getAbsolutePath());
//                Optional.ofNullable(certificateWithKeyPairAndPrivateKeyPassword.getPrivateKeyPassword())
//                        .ifPresent(privateKeyPassword -> builder.put("searchguard.ssl.http.pemkey_password", privateKeyPassword));
//            }
//
//            builder.put("searchguard.ssl.transport.enforce_hostname_verification", false);
//
//                String adminClientDn = certificatesContext.getAdminCertificate().getCertificate().getSubject().toString();
//                builder.putList("searchguard.authcz.admin_dn", adminClientDn);
//                builder.put("searchguard.background_init_if_sgindex_not_exist", false);
//                builder.put("searchguard.ssl_only", false);

		return builder;

	}
}
