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

package org.opensearch.test;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.rest.TestRestClient;
import org.opensearch.test.framework.rest.TestRestClient.HttpResponse;

public class GenericIntegrationTest {

    private final static TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin")
            .roles(new Role("allaccess").indexPermissions("*").on("*").clusterPermissions("*"));
    
    private final static TestSecurityConfig.AuthcDomain authc = new TestSecurityConfig.AuthcDomain("basic", 0).httpAuthenticator("basic").backend("internal");
    
    private final static TestSecurityConfig sgConfig = new TestSecurityConfig().authc(authc);
            
    
    
    
    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().sgConfig(sgConfig).user(ADMIN_USER).build();

    @Test
    public void basicTest() throws Exception {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            HttpResponse response = client.get("_opendistro/_security/authinfo?pretty");
            Assert.assertEquals(response.getStatusCode(), HttpStatus.SC_OK);
        }
    }
}
