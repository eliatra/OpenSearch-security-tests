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
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.rest.TestRestClient;
import org.opensearch.test.framework.rest.TestRestClient.HttpResponse;

/**
 * WIP
 * Generic test class that demonstrates how to use the test framework to 
 * set up a test cluster with users, roles, indices and data, and how to
 * implement tests. One main goal here is to make tests self-contained.
 */
public class GenericIntegrationTest {
	
	// define what authc/authz this test uses
    private final static TestSecurityConfig.AuthcDomain authc = new TestSecurityConfig.AuthcDomain("basic", 0).httpAuthenticator("basic").backend("internal");
    
    // define users and roles used in this test
    private final static TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin")
            .roles(new Role("allaccess").indexPermissions("*").on("*").clusterPermissions("*"));
    
    // define indices used in this test
    private final static TestIndex index = TestIndex.name("indexa").build();
    
    // define test data used in this test
    // TODO 

    // build our test cluster as a ClassRule
    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().authc(authc).user(ADMIN_USER).indices(index).build();

    @Test
    public void basicTest() throws Exception {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            HttpResponse response = client.get("_opendistro/_security/authinfo?pretty");
            Assert.assertEquals(response.getStatusCode(), HttpStatus.SC_OK);
        }
    }
}
