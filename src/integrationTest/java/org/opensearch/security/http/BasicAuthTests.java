/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security.http;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.message.BasicHeader;
import org.hamcrest.Matchers;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.apache.hc.core5.http.HttpStatus.SC_FORBIDDEN;
import static org.apache.hc.core5.http.HttpStatus.SC_OK;
import static org.apache.hc.core5.http.HttpStatus.SC_UNAUTHORIZED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsStringIgnoringCase;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.rest.RestStatus.FORBIDDEN;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.statusException;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsContainDocumentWithId;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class BasicAuthTests {

	private static final String CUSTOM_ATTRIBUTE_NAME = "superhero";
	private static final String NOT_EXISTING_USER = "not-existing-user";
	private static final String INVALID_PASSWORD = "secret-password";
	private static final String HEADER_NAME_IMPERSONATE = "opendistro_security_impersonate_as";

	private static final String POINTER_ROLES = "/roles";
	private static final String POINTER_ERROR_REASON = "/error/reason";
	private static final String POINTER_USER_NAME = "/user_name";

	private static final String ID_1 = "doc/001/";
	private static final String ID_2 = "doc/002/";
	private static final String ID_ADMIN = "doc/admin/";

	private static final String INDEX_1 = "index-1";
	private static final String INDEX_2 = "index-2";
	private static final String INDEX_3 = "index-3";
	private static final String INDEX_ADMIN = "index-admin";

	private static final String PERMISSION_SEARCH = "indices:data/read/search";

	private static final Role ROLE_1 = new Role("role-1").indexPermissions(PERMISSION_SEARCH).on(INDEX_1);
	private static final Role ROLE_2 = new Role("role-2").indexPermissions(PERMISSION_SEARCH).on(INDEX_2);
	private static final Role ROLE_3 = new Role("role-3").indexPermissions(PERMISSION_SEARCH).on(INDEX_3);
	private static final Role ROLE_ADMIN = new Role("role-admin").indexPermissions(PERMISSION_SEARCH).on(INDEX_ADMIN);

	private static final User USER_1 = new User("simple_user_1").roles(ROLE_1);
	private static final User USER_2 = new User("simple_user_2").roles(ROLE_2);
	private static final User USER_3 = new User("simple_user_3").roles(ROLE_3);
	private static final User USER_ADMIN = new User("admin-user").roles(ROLE_ADMIN).attr(CUSTOM_ATTRIBUTE_NAME, true);

	private static final AuthcDomain AUTHC_DOMAIN = new AuthcDomain("basic", 0)
		.httpAuthenticatorWithChallenge("basic").backend("internal");

	private static final Map<String, Object> USER_IMPERSONATION_CONFIGURATION = Map.of(
		"plugins.security.authcz.rest_impersonation_user." + USER_ADMIN.getName(), List.of(USER_1.getName(), USER_2.getName())
	);

	@ClassRule
	public static final LocalCluster cluster = new LocalCluster.Builder()
		.nodeSettings(USER_IMPERSONATION_CONFIGURATION)
		.clusterManager(ClusterManager.SINGLENODE).anonymousAuth(false)
		.authc(AUTHC_DOMAIN).users(USER_1, USER_ADMIN, USER_2, USER_3).build();

	@BeforeClass
	public static void createTestData() {
		try(Client client = cluster.getInternalNodeClient()){
			client.prepareIndex(INDEX_1).setId(ID_1).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0]).get();
			client.prepareIndex(INDEX_2).setId(ID_2).setRefreshPolicy(IMMEDIATE).setSource(SONGS[1]).get();
			client.prepareIndex(INDEX_ADMIN).setId(ID_ADMIN).setRefreshPolicy(IMMEDIATE).setSource(SONGS[2]).get();
		}
	}

	@Test
	public void shouldRespondWith401WhenUserDoesNotExist() {
		try (TestRestClient client = cluster.getRestClient(NOT_EXISTING_USER, INVALID_PASSWORD)) {
			HttpResponse response = client.getAuthInfo();

			assertThat(response, is(notNullValue()));
			response.assertStatusCode(SC_UNAUTHORIZED);
		}
	}

	@Test
	public void shouldRespondWith401WhenUserNameIsIncorrect() {
		try (TestRestClient client = cluster.getRestClient(NOT_EXISTING_USER, USER_1.getPassword())) {
			HttpResponse response = client.getAuthInfo();

			assertThat(response, is(notNullValue()));
			response.assertStatusCode(SC_UNAUTHORIZED);
		}
	}

	@Test
	public void shouldRespondWith401WhenPasswordIsIncorrect() {
		try (TestRestClient client = cluster.getRestClient(USER_1.getName(), INVALID_PASSWORD)) {
			HttpResponse response = client.getAuthInfo();

			assertThat(response, is(notNullValue()));
			response.assertStatusCode(SC_UNAUTHORIZED);
		}
	}

	@Test
	public void shouldRespondWith200WhenCredentialsAreCorrect() {
		try (TestRestClient client = cluster.getRestClient(USER_1)) {

			HttpResponse response = client.getAuthInfo();

			assertThat(response, is(notNullValue()));
			response.assertStatusCode(SC_OK);
		}
	}

	@Test
	public void testBrowserShouldRequestForCredentials() {
		try (TestRestClient client = cluster.getRestClient()) {

			HttpResponse response = client.getAuthInfo();

			assertThat(response, is(notNullValue()));
			response.assertStatusCode(SC_UNAUTHORIZED);
			assertThatBrowserAskUserForCredentials(response);
		}
	}

	@Test
	public void testUserShouldNotHaveAssignedCustomAttributes() {
		try (TestRestClient client = cluster.getRestClient(USER_1)) {

			HttpResponse response = client.getAuthInfo();

			assertThat(response, is(notNullValue()));
			response.assertStatusCode(SC_OK);
			AuthInfo authInfo = response.getBodyAs(AuthInfo.class);
			assertThat(authInfo, is(notNullValue()));
			assertThat(authInfo.getCustomAttributeNames(), is(notNullValue()));
			assertThat(authInfo.getCustomAttributeNames(), hasSize(0));
		}
	}

	@Test
	public void testUserShouldHaveAssignedCustomAttributes() {
		try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {

			HttpResponse response = client.getAuthInfo();

			assertThat(response, is(notNullValue()));
			response.assertStatusCode(SC_OK);
			AuthInfo authInfo = response.getBodyAs(AuthInfo.class);
			assertThat(authInfo, is(notNullValue()));
			List<String> customAttributeNames = authInfo.getCustomAttributeNames();
			assertThat(customAttributeNames, is(notNullValue()));
			assertThat(customAttributeNames, hasSize(1));
			assertThat(customAttributeNames.get(0), Matchers.equalTo("attr.internal." + CUSTOM_ATTRIBUTE_NAME));
		}
	}

	private void assertThatBrowserAskUserForCredentials(HttpResponse response) {
		String reason = "Browser does not ask user for credentials";
		assertThat(reason, response.containHeader(HttpHeaders.WWW_AUTHENTICATE), equalTo(true));
		assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE).getValue(), containsStringIgnoringCase("basic"));
	}

	@Test
	public void shouldHaveAssignedRole_positiveUser1() {
		try(TestRestClient client = cluster.getRestClient(USER_1)) {

			HttpResponse response = client.getAuthInfo();

			response.assertStatusCode(SC_OK);
			List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
			assertThat(roles, contains(USER_1.getRoleNameInUserScope(ROLE_1)));
		}
	}

	@Test
	public void shouldHaveAssignedRole_positiveUser2() {
		try(TestRestClient client = cluster.getRestClient(USER_2)) {

			HttpResponse response = client.getAuthInfo();

			response.assertStatusCode(SC_OK);
			List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
			assertThat(roles, contains(USER_2.getRoleNameInUserScope(ROLE_2)));
		}
	}

	@Test
	public void shouldHaveAssignedRole_positiveUser3() {
		try(TestRestClient client = cluster.getRestClient(USER_3)) {

			HttpResponse response = client.getAuthInfo();

			response.assertStatusCode(SC_OK);
			List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
			assertThat(roles, contains(USER_3.getRoleNameInUserScope(ROLE_3)));
		}
	}

	@Test
	public void shouldHaveAssignedRole_positiveUserAdmin() {
		try(TestRestClient client = cluster.getRestClient(USER_ADMIN)) {

			HttpResponse response = client.getAuthInfo();

			response.assertStatusCode(SC_OK);
			List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
			assertThat(roles, contains(USER_ADMIN.getRoleNameInUserScope(ROLE_ADMIN)));
		}
	}

	@Test
	public void shouldImpersonateUser_positiveUser1() {
		try(TestRestClient client = cluster.getRestClient(USER_ADMIN)) {

			HttpResponse response = client.getAuthInfo(new BasicHeader(HEADER_NAME_IMPERSONATE, USER_1.getName()));

			response.assertStatusCode(SC_OK);
			assertThat(response.getTextFromJsonBody(POINTER_USER_NAME), equalTo(USER_1.getName()));
			List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
			assertThat(roles, hasSize(1));
			assertThat(roles, contains(USER_1.getRoleNameInUserScope(ROLE_1)));
		}
	}

	@Test
	public void shouldImpersonateUser_positiveUser2() {
		try(TestRestClient client = cluster.getRestClient(USER_ADMIN)) {

			HttpResponse response = client.getAuthInfo(new BasicHeader(HEADER_NAME_IMPERSONATE, USER_2.getName()));

			response.assertStatusCode(SC_OK);
			assertThat(response.getTextFromJsonBody(POINTER_USER_NAME), equalTo(USER_2.getName()));
			List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
			assertThat(roles, hasSize(1));
			assertThat(roles, contains(USER_2.getRoleNameInUserScope(ROLE_2)));
		}
	}

	@Test
	public void shouldImpersonateUser_negativeUser3() {
		try(TestRestClient client = cluster.getRestClient(USER_ADMIN)) {

			HttpResponse response = client.getAuthInfo(new BasicHeader(HEADER_NAME_IMPERSONATE, USER_3.getName()));

			response.assertStatusCode(SC_FORBIDDEN);
			String reason = response.getTextFromJsonBody(POINTER_ERROR_REASON);
			String expectedMessage = String.format("'%s' is not allowed to impersonate as 'simple_user_3'",
				USER_ADMIN.getName(), USER_3.getName());
			assertThat(reason, equalTo(expectedMessage));
		}
	}

	@Test
	public void shouldImpersonateUser_negativeUserAdmin() {
		try(TestRestClient client = cluster.getRestClient(USER_1)) {

			HttpResponse response = client.getAuthInfo(new BasicHeader(HEADER_NAME_IMPERSONATE, USER_ADMIN.getName()));

			response.assertStatusCode(SC_FORBIDDEN);
			String reason = response.getTextFromJsonBody(POINTER_ERROR_REASON);
			String expectedMessage = String.format("'%s' is not allowed to impersonate as '%s'", USER_1.getName(), USER_ADMIN.getName());
			assertThat(reason, equalTo(expectedMessage));
		}
	}

	@Test
	public void shouldAccessImpersonateUserData_positive() throws IOException {
		List<BasicHeader> headers = List.of(new BasicHeader(HEADER_NAME_IMPERSONATE, USER_1.getName()));
		try(RestHighLevelClient client = cluster.getRestHighLevelClient(USER_ADMIN, headers)) {

			SearchResponse response = client.search(queryStringQueryRequest(INDEX_1, "*"), DEFAULT);

			assertThat(response, isSuccessfulSearchResponse());
			assertThat(response, numberOfTotalHitsIsEqualTo(1));
			assertThat(response, searchHitsContainDocumentWithId(0, INDEX_1, ID_1));
		}
	}

	@Test
	public void shouldAccessImpersonateUserData_negativeOwnIndexAccess() throws IOException {
		List<BasicHeader> headers = List.of(new BasicHeader(HEADER_NAME_IMPERSONATE, USER_1.getName()));
		try(RestHighLevelClient client = cluster.getRestHighLevelClient(USER_ADMIN, headers)) {
			SearchRequest searchRequest = queryStringQueryRequest(INDEX_ADMIN, "*");

			assertThatThrownBy(() -> client.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}

	@Test
	public void shouldAccessImpersonateUserData_negativeAnotherUserIndexAccess() throws IOException {
		List<BasicHeader> headers = List.of(new BasicHeader(HEADER_NAME_IMPERSONATE, USER_1.getName()));
		try(RestHighLevelClient client = cluster.getRestHighLevelClient(USER_ADMIN, headers)) {
			SearchRequest searchRequest = queryStringQueryRequest(INDEX_2, "*");

			assertThatThrownBy(() -> client.search(searchRequest, DEFAULT), statusException(FORBIDDEN));
		}
	}
}
