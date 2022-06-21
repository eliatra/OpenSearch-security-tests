/*
 * Copyright 2020 floragunn GmbH
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

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.rest.TestRestClient;


public interface OpenSearchClientProvider {

    String getClusterName();

    TestCertificates getTestCertificates();

    InetSocketAddress getHttpAddress();

    InetSocketAddress getTransportAddress();

    default URI getHttpAddressAsURI() {
        InetSocketAddress address = getHttpAddress();
        return URI.create("https://" + address.getHostString() + ":" + address.getPort());
    }

//    default SSLContextProvider getAdminClientSslContextProvider() {
//        return new TestCertificateBasedSSLContextProvider(getTestCertificates().getCaCertificate(), getTestCertificates().getAdminCertificate());
//    }
//
//    default SSLContextProvider getAnyClientSslContextProvider() {
//        return new TestCertificateBasedSSLContextProvider(getTestCertificates().getCaCertificate(), getTestCertificates().getAnyClientCertificate());
//    }

    default TestRestClient getRestClient(UserCredentialsHolder user, Header... headers) {
        return getRestClient(user.getName(), user.getPassword(), headers);
    }

    default TestRestClient getRestClient(String user, String password, String tenant) {
        return getRestClient(user, password, new BasicHeader("sgtenant", tenant));
    }

    default TestRestClient getRestClient(String user, String password, Header... headers) {
        BasicHeader basicAuthHeader = getBasicAuthHeader(user, password);
        if (headers != null && headers.length > 0) {
            List<Header> concatenatedHeaders = Stream.concat(Stream.of(basicAuthHeader), Stream.of(headers)).collect(Collectors.toList());
            return getRestClient(concatenatedHeaders);
        }
        return getRestClient(basicAuthHeader);
    }

    default TestRestClient getRestClient(Header... headers) {
        return getRestClient(Arrays.asList(headers));
    }

    default TestRestClient getRestClient(List<Header> headers) {
        return createGenericClientRestClient(headers);
    }

    default TestRestClient getAdminCertRestClient() {
        return createGenericAdminRestClient(Collections.emptyList());
    }

    default TestRestClient createGenericClientRestClient(List<Header> headers) {
    	// TODO: SSL
    	// return new ITRestClient(getHttpAddress(), headers, getAnyClientSslContextProvider().getSslContext(false));
    	return new TestRestClient(getHttpAddress(), headers, "");
    }

    default TestRestClient createGenericAdminRestClient(List<Header> headers) {
        //a client authentication is needed for admin because admin needs to authenticate itself (dn matching in config file)
    	// TODO: SSL
//        return new ITRestClient(getHttpAddress(), headers, getAdminClientSslContextProvider().getSslContext(true));
    	return new TestRestClient(getHttpAddress(), headers, "");
    }

    default BasicHeader getBasicAuthHeader(String user, String password) {
        return new BasicHeader("Authorization",
                "Basic " + Base64.getEncoder().encodeToString((user + ":" + Objects.requireNonNull(password)).getBytes(StandardCharsets.UTF_8)));
    }

    public interface UserCredentialsHolder {
        String getName();

        String getPassword();
    }

}
