package org.opensearch.test.framework;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LdapAuthenticationConfigBuilder {
	private boolean enableSsl = false;
	private boolean enableStartTls = false;
	private boolean enableSslClientAuth = false;
	private boolean verifyHostnames = false;
	private List<String> hosts;
	private String bindDn;
	private String password;
	private String userBase;
	private String userSearch;
	private String usernameAttribute;

	private String penTrustedCasFilePath;

	public LdapAuthenticationConfigBuilder enableSsl(boolean enableSsl) {
		this.enableSsl = enableSsl;
		return this;
	}

	public LdapAuthenticationConfigBuilder enableStartTls(boolean enableStartTls) {
		this.enableStartTls = enableStartTls;
		return this;
	}

	public LdapAuthenticationConfigBuilder enableSslClientAuth(boolean enableSslClientAuth) {
		this.enableSslClientAuth = enableSslClientAuth;
		return this;
	}

	public LdapAuthenticationConfigBuilder verifyHostnames(boolean verifyHostnames) {
		this.verifyHostnames = verifyHostnames;
		return this;
	}

	public LdapAuthenticationConfigBuilder hosts(List<String> hosts) {
		this.hosts = hosts;
		return this;
	}

	public LdapAuthenticationConfigBuilder bindDn(String bindDn) {
		this.bindDn = bindDn;
		return this;
	}

	public LdapAuthenticationConfigBuilder password(String password) {
		this.password = password;
		return this;
	}

	public LdapAuthenticationConfigBuilder userBase(String userBase) {
		this.userBase = userBase;
		return this;
	}

	public LdapAuthenticationConfigBuilder userSearch(String userSearch) {
		this.userSearch = userSearch;
		return this;
	}

	public LdapAuthenticationConfigBuilder usernameAttribute(String usernameAttribute) {
		this.usernameAttribute = usernameAttribute;
		return this;
	}

	public LdapAuthenticationConfigBuilder penTrustedCasFilePath(String penTrustedCasFilePath) {
		this.penTrustedCasFilePath = penTrustedCasFilePath;
		return this;
	}

	public Map<String, Object> build() {
		HashMap<String, Object> config = new HashMap<>();
		config.put("enable_ssl", enableSsl);
		config.put("enable_start_tls", enableStartTls);
		config.put("enable_ssl_client_auth", enableSslClientAuth);
		config.put("verify_hostnames", verifyHostnames);
		config.put("hosts", hosts);
		config.put("bind_dn", bindDn);
		config.put("password", password);
		config.put("userbase", userBase);
		config.put("usersearch", userSearch);
		config.put("username_attribute", usernameAttribute);
		config.put("pemtrustedcas_filepath", penTrustedCasFilePath);
		return config;
	}
}
