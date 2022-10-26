package org.opensearch.security.http;

import org.opensearch.test.framework.ldap.LdifBuilder;
import org.opensearch.test.framework.ldap.LdifData;

class DirectoryInformationTrees {

	public static final String USER_KIRK = "kirk";
	public static final String PASSWORD_KIRK = "kirk-secret";

	public static final String USER_SPOCK = "spock";
	public static final String PASSWORD_SPOCK = "spocksecret";

	public static final String COMMON_NAME_OPEN_SEARCH = "cn=Open Search,ou=people,o=TEST";
	public static final String PASSWORD_OPEN_SEARCH = "open_search-secret";
	public static final String USER_OPENS = "opens";
	public static final String USERS_ROOT = "ou=people,o=TEST";

	public static final String USER_SEARCH = "(uid={0})";
	public static final String USERNAME_ATTRIBUTE = "uid";
	static final LdifData LDIF_DATA = new LdifBuilder()
		.root("o=TEST")
			.dc("TEST")
			.classes("top", "domain")
			.newRecord(USERS_ROOT)
			.ou("people")
			.classes("organizationalUnit", "top")
		.newRecord(COMMON_NAME_OPEN_SEARCH)
			.classes("inetOrgPerson")
			.cn("Open Search")
			.sn("Search")
			.uid(USER_OPENS)
			.userPassword(PASSWORD_OPEN_SEARCH)
			.mail("open.search@example.com")
			.ou("Human Resources")
		.newRecord("cn=Captain Spock,ou=people,o=TEST")
			.classes("inetOrgPerson")
			.cn("Captain Spock")
			.sn(USER_SPOCK)
			.uid(USER_SPOCK)
			.userPassword(PASSWORD_SPOCK)
			.mail("spock@example.com")
			.ou("Human Resources")
		.newRecord("cn=Kirk,ou=people,o=TEST")
			.classes("inetOrgPerson")
			.cn("Kirk")
			.sn("Kirk")
			.uid(USER_KIRK)
			.userPassword(PASSWORD_KIRK)
			.mail("spock@example.com")
			.ou("Human Resources")
		.buildRecord()
		.buildLdif();
}
