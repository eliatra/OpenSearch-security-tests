package org.opensearch.security.http;

import java.util.List;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.LdapAuthenticationConfigBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AuthenticationBackend;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.HttpAuthenticator;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.ldap.EmbeddedLDAPServer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.http.DirectoryInformationTrees.COMMON_NAME_OPEN_SEARCH;
import static org.opensearch.security.http.DirectoryInformationTrees.LDIF_DATA;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_KIRK;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_OPEN_SEARCH;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_SPOCK;
import static org.opensearch.security.http.DirectoryInformationTrees.USERNAME_ATTRIBUTE;
import static org.opensearch.security.http.DirectoryInformationTrees.USERS_ROOT;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_KIRK;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_SEARCH;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_SPOCK;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class LdapTlsAuthenticationTest {

	private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

	private static final TestCertificates TEST_CERTIFICATES = new TestCertificates();

	public static final String POINTER_USERNAME = "/user_name";

	public static final EmbeddedLDAPServer embeddedLDAPServer = new EmbeddedLDAPServer(TEST_CERTIFICATES.getRootCertificateData(),
		TEST_CERTIFICATES.getLdapCertificateData(), LDIF_DATA);

	public static LocalCluster cluster = new LocalCluster.Builder()
		.testCertificates(TEST_CERTIFICATES)
		.clusterManager(ClusterManager.SINGLENODE).anonymousAuth(false)
		.authc(new AuthcDomain("ldap", 2, true)
			.httpAuthenticator(new HttpAuthenticator("basic").challenge(false))
			.backend(new AuthenticationBackend("ldap")
				.config(() -> new LdapAuthenticationConfigBuilder()
					// this port is available when embeddedLDAPServer is already started, therefore Supplier interface is used
					.hosts(List.of("localhost:" + embeddedLDAPServer.getLdapsPort()))
					.enableSsl(true)
					.bindDn(COMMON_NAME_OPEN_SEARCH)
					.password(PASSWORD_OPEN_SEARCH)
					.userBase(USERS_ROOT)
					.userSearch(USER_SEARCH)
					.usernameAttribute(USERNAME_ATTRIBUTE)
					.penTrustedCasFilePath(TEST_CERTIFICATES.getRootCertificate().getAbsolutePath())
					.build())))
		.authc(AUTHC_HTTPBASIC_INTERNAL)
		.users(ADMIN_USER)
		.build();

	@ClassRule
	public static RuleChain ruleChain = RuleChain.outerRule(embeddedLDAPServer).around(cluster);


	@Test
	public void shouldAuthenticateUserWithLdap_positiveSpockUser() {
		try (TestRestClient client = cluster.getRestClient(USER_SPOCK, PASSWORD_SPOCK)) {
			TestRestClient.HttpResponse response = client.getAuthInfo();

			response.assertStatusCode(200);
			String username = response.getTextFromJsonBody(POINTER_USERNAME);
			assertThat(username, equalTo(USER_SPOCK));
		}
	}

	@Test
	public void shouldAuthenticateUserWithLdap_positiveKirkUser() {
		try (TestRestClient client = cluster.getRestClient(USER_KIRK, PASSWORD_KIRK)) {
			TestRestClient.HttpResponse response = client.getAuthInfo();

			response.assertStatusCode(200);
			String username = response.getTextFromJsonBody(POINTER_USERNAME);
			assertThat(username, equalTo(USER_KIRK));
		}
	}

	@Test
	public void shouldAuthenticateUserWithLdap_negativeWhenIncorrectPassword() {
		try (TestRestClient client = cluster.getRestClient(USER_SPOCK, "incorrect password")) {
			TestRestClient.HttpResponse response = client.getAuthInfo();

			response.assertStatusCode(401);
		}
	}

	@Test
	public void shouldAuthenticateUserWithLdap_negativeWhenIncorrectUsername() {
		try (TestRestClient client = cluster.getRestClient("invalid-user-name", PASSWORD_SPOCK)) {
			TestRestClient.HttpResponse response = client.getAuthInfo();

			response.assertStatusCode(401);
		}
	}

	@Test
	public void shouldAuthenticateUserWithLdap_negativeWhenUserDoesNotExist() {
		try (TestRestClient client = cluster.getRestClient("doesNotExist", "password")) {
			TestRestClient.HttpResponse response = client.getAuthInfo();

			response.assertStatusCode(401);
		}
	}
}
