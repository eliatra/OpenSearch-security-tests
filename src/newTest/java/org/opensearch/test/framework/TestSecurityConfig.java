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

package org.opensearch.test.framework;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.Strings;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.test.framework.cluster.NestedValueMap;
import org.opensearch.test.framework.cluster.NestedValueMap.Path;
import org.opensearch.test.framework.cluster.OpenSearchClientProvider.UserCredentialsHolder;

public class TestSecurityConfig {

	private static final Logger log = LogManager.getLogger(TestSecurityConfig.class);

	private String resourceFolder = null;
	private NestedValueMap overrideSecurityConfigSettings;
	private NestedValueMap overrideUserSettings;
	private NestedValueMap overrideRoleSettings;
	private NestedValueMap overrideRoleMappingSettings;
	private AuthcDomain authc;
	private DlsFls dlsFls;
//	private Privileges privileges;
	private String indexName = ".opendistro_security";
	private Map<String, Supplier<Object>> variableSuppliers = new HashMap<>();

	public TestSecurityConfig() {

	}

	public TestSecurityConfig configIndexName(String configIndexName) {
		this.indexName = configIndexName;
		return this;
	}

	public TestSecurityConfig resources(String resourceFolder) {
		this.resourceFolder = resourceFolder;
		return this;
	}

	public TestSecurityConfig var(String name, Supplier<Object> variableSupplier) {
		this.variableSuppliers.put(name, variableSupplier);
		return this;
	}

	public TestSecurityConfig securityConfigSettings(String keyPath, Object value, Object... more) {
		if (overrideSecurityConfigSettings == null) {
			overrideSecurityConfigSettings = new NestedValueMap();
		}

		overrideSecurityConfigSettings.put(NestedValueMap.Path.parse(keyPath), value);

		for (int i = 0; i < more.length - 1; i += 2) {
			overrideSecurityConfigSettings.put(NestedValueMap.Path.parse(String.valueOf(more[i])), more[i + 1]);
		}

		return this;
	}

	public TestSecurityConfig xff(String proxies) {
		if (overrideSecurityConfigSettings == null) {
			overrideSecurityConfigSettings = new NestedValueMap();
		}

		overrideSecurityConfigSettings.put(new NestedValueMap.Path("config", "dynamic", "http", "xff"),
				NestedValueMap.of("enabled", true, "internalProxies", proxies));

		return this;
	}

    public TestSecurityConfig authc(AuthcDomain authcDomain) {
        if (overrideSecurityConfigSettings == null) {
            overrideSecurityConfigSettings = new NestedValueMap();
        }

        overrideSecurityConfigSettings.put(new NestedValueMap.Path("config", "dynamic", "authc"), authcDomain.toMap());

        return this;
    }


	public TestSecurityConfig dlsFls(DlsFls dlsFls) {
		this.dlsFls = dlsFls;
		return this;
	}

	public TestSecurityConfig user(User user) {
		if (user.roleNames != null) {
			return this.user(user.name, user.password, user.attributes, user.roleNames);
		} else {
			return this.user(user.name, user.password, user.attributes, user.roles);
		}
	}

	public TestSecurityConfig user(String name, String password, String... sgRoles) {
		return user(name, password, null, sgRoles);
	}

	public TestSecurityConfig user(String name, String password, Map<String, Object> attributes, String... sgRoles) {
		if (overrideUserSettings == null) {
			overrideUserSettings = new NestedValueMap();
		}

		overrideUserSettings.put(new NestedValueMap.Path(name, "hash"), hash(password.toCharArray()));

		if (sgRoles != null && sgRoles.length > 0) {
			overrideUserSettings.put(new NestedValueMap.Path(name, "search_guard_roles"), sgRoles);
		}

		if (attributes != null && attributes.size() != 0) {
			for (Map.Entry<String, Object> attr : attributes.entrySet()) {
				overrideUserSettings.put(new NestedValueMap.Path(name, "attributes", attr.getKey()), attr.getValue());
			}
		}

		return this;
	}

	public TestSecurityConfig user(String name, String password, Role... sgRoles) {
		return user(name, password, null, sgRoles);
	}

	public TestSecurityConfig user(String name, String password, Map<String, Object> attributes, Role... sgRoles) {
		if (overrideUserSettings == null) {
			overrideUserSettings = new NestedValueMap();
		}

		overrideUserSettings.put(new NestedValueMap.Path(name, "hash"), hash(password.toCharArray()));

		if (sgRoles != null && sgRoles.length > 0) {
			String roleNamePrefix = "user_" + name + "__";

			overrideUserSettings.put(new NestedValueMap.Path(name, "opendistro_security_roles"),
					Arrays.asList(sgRoles).stream().map((r) -> roleNamePrefix + r.name).collect(Collectors.toList()));
			roles(roleNamePrefix, sgRoles);
		}

		if (attributes != null && attributes.size() != 0) {
			for (Map.Entry<String, Object> attr : attributes.entrySet()) {
				overrideUserSettings.put(new NestedValueMap.Path(name, "attributes", attr.getKey()), attr.getValue());
			}
		}

		return this;
	}

	public TestSecurityConfig roles(Role... roles) {
		return roles("", roles);
	}

	public TestSecurityConfig roles(String roleNamePrefix, Role... roles) {
		if (overrideRoleSettings == null) {
			overrideRoleSettings = new NestedValueMap();
		}

		for (Role role : roles) {

			String name = roleNamePrefix + role.name;

			if (role.clusterPermissions.size() > 0) {
				overrideRoleSettings.put(new NestedValueMap.Path(name, "cluster_permissions"), role.clusterPermissions);
			}

			if (role.indexPermissions.size() > 0) {
				overrideRoleSettings.put(new NestedValueMap.Path(name, "index_permissions"),
						role.indexPermissions.stream().map((p) -> p.toJsonMap()).collect(Collectors.toList()));
			}
		}

		return this;
	}

	public TestSecurityConfig roleMapping(RoleMapping... roleMappings) {
		if (overrideRoleMappingSettings == null) {
			overrideRoleMappingSettings = new NestedValueMap();
		}

		for (RoleMapping roleMapping : roleMappings) {

			String name = roleMapping.name;

			if (roleMapping.backendRoles.size() > 0) {
				overrideRoleMappingSettings.put(new NestedValueMap.Path(name, "backend_roles"),
						roleMapping.backendRoles);
			}

			if (roleMapping.users.size() > 0) {
				overrideRoleMappingSettings.put(new NestedValueMap.Path(name, "users"), roleMapping.users);
			}
		}

		return this;
	}

	public TestSecurityConfig roleToRoleMapping(Role role, String... backendRoles) {
		return this.roleMapping(new RoleMapping(role.name).backendRoles(backendRoles));
	}
	
	
	// -----------

	public static class User implements UserCredentialsHolder {
		private String name;
		private String password;
		private Role[] roles;
		private String[] roleNames;
		private Map<String, Object> attributes = new HashMap<>();

		public User(String name) {
			this.name = name;
			this.password = "secret";
		}

		public User password(String password) {
			this.password = password;
			return this;
		}

		public User roles(Role... roles) {
			this.roles = roles;
			return this;
		}

		public User roles(String... roles) {
			this.roleNames = roles;
			return this;
		}

		public User attr(String key, Object value) {
			this.attributes.put(key, value);
			return this;
		}

		public String getName() {
			return name;
		}

		public String getPassword() {
			return password;
		}

		public Set<String> getRoleNames() {
			Set<String> result = new HashSet<String>();

			if (roleNames != null) {
				result.addAll(Arrays.asList(roleNames));
			}

			if (roles != null) {
				result.addAll(Arrays.asList(roles).stream().map(Role::getName).collect(Collectors.toSet()));
			}

			return result;
		}

	}

	public static class Role {
		public static Role ALL_ACCESS = new Role("all_access").clusterPermissions("*").indexPermissions("*").on("*");

		private String name;
		private List<String> clusterPermissions = new ArrayList<>();

		private List<IndexPermission> indexPermissions = new ArrayList<>();

		public Role(String name) {
			this.name = name;
		}

		public Role clusterPermissions(String... clusterPermissions) {
			this.clusterPermissions.addAll(Arrays.asList(clusterPermissions));
			return this;
		}

		public IndexPermission indexPermissions(String... indexPermissions) {
			return new IndexPermission(this, indexPermissions);
		}

		public String getName() {
			return name;
		}
	}

	public static class RoleMapping {
		private String name;
		private List<String> backendRoles = new ArrayList<>();
		private List<String> users = new ArrayList<>();

		public RoleMapping(String name) {
			this.name = name;
		}

		public RoleMapping backendRoles(String... backendRoles) {
			this.backendRoles.addAll(Arrays.asList(backendRoles));
			return this;
		}

		public RoleMapping users(String... users) {
			this.users.addAll(Arrays.asList(users));
			return this;
		}

	}

	public static class IndexPermission {
		private List<String> allowedActions;
		private List<String> indexPatterns;
		private Role role;
		private String dlsQuery;
		private List<String> fls;
		private List<String> maskedFields;

		IndexPermission(Role role, String... allowedActions) {
			this.allowedActions = Arrays.asList(allowedActions);
			this.role = role;
		}

		public IndexPermission dls(String dlsQuery) {
			this.dlsQuery = dlsQuery;
			return this;
		}

		public IndexPermission fls(String... fls) {
			this.fls = Arrays.asList(fls);
			return this;
		}

		public IndexPermission maskedFields(String... maskedFields) {
			this.maskedFields = Arrays.asList(maskedFields);
			return this;
		}

		public Role on(String... indexPatterns) {
			this.indexPatterns = Arrays.asList(indexPatterns);
			this.role.indexPermissions.add(this);
			return this.role;
		}

		public NestedValueMap toJsonMap() {
			NestedValueMap result = new NestedValueMap();

			result.put("index_patterns", indexPatterns);
			result.put("allowed_actions", allowedActions);

			if (dlsQuery != null) {
				result.put("dls", dlsQuery);
			}

			if (fls != null) {
				result.put("fls", fls);
			}

			if (maskedFields != null) {
				result.put("masked_fields", maskedFields);
			}

			return result;
		}

	}

    public static class AuthcDomain {

        private final String id;
        private boolean enabled = true;
        private boolean transportEnabled = true;
        private int order;
        private List<String> skipUsers = new ArrayList<>();
        private List<String> enabledOnlyForIps = null;
        private HttpAuthenticator httpAuthenticator;
        private AuthenticationBackend authenticationBackend;

        public AuthcDomain(String id, int order) {
            this.id = id;
            this.order = order;
        }

        public AuthcDomain httpAuthenticator(String type) {
            this.httpAuthenticator = new HttpAuthenticator(type);
            return this;
        }

        public AuthcDomain challengingAuthenticator(String type) {
            this.httpAuthenticator = new HttpAuthenticator(type).challenge(true);
            return this;
        }

        public AuthcDomain httpAuthenticator(HttpAuthenticator httpAuthenticator) {
            this.httpAuthenticator = httpAuthenticator;
            return this;
        }

        public AuthcDomain backend(String type) {
            this.authenticationBackend = new AuthenticationBackend(type);
            return this;
        }

        public AuthcDomain backend(AuthenticationBackend authenticationBackend) {
            this.authenticationBackend = authenticationBackend;
            return this;
        }

        public AuthcDomain skipUsers(String... users) {
            this.skipUsers.addAll(Arrays.asList(users));
            return this;
        }

        public AuthcDomain enabledOnlyForIps(String... ips) {
            if (enabledOnlyForIps == null) {
                enabledOnlyForIps = new ArrayList<>();
            }

            enabledOnlyForIps.addAll(Arrays.asList(ips));
            return this;
        }

        NestedValueMap toMap() {
            NestedValueMap result = new NestedValueMap();
            result.put(new NestedValueMap.Path(id, "http_enabled"), enabled);
            result.put(new NestedValueMap.Path(id, "transport_enabled"), transportEnabled);
            result.put(new NestedValueMap.Path(id, "order"), order);

            if (httpAuthenticator != null) {
                result.put(new NestedValueMap.Path(id, "http_authenticator"), httpAuthenticator.toMap());
            }

            if (authenticationBackend != null) {
                result.put(new NestedValueMap.Path(id, "authentication_backend"), authenticationBackend.toMap());
            }


            if (skipUsers != null && skipUsers.size() > 0) {
                result.put(new NestedValueMap.Path(id, "skip_users"), skipUsers);
            }

            return result;
        }


        public static class HttpAuthenticator {
            private final String type;
            private boolean challenge;
            private NestedValueMap config = new NestedValueMap();

            public HttpAuthenticator(String type) {
                this.type = type;
            }

            public HttpAuthenticator challenge(boolean challenge) {
                this.challenge = challenge;
                return this;
            }

            public HttpAuthenticator config(Map<String, Object> config) {
                this.config.putAllFromAnyMap(config);
                return this;
            }

            public HttpAuthenticator config(String key, Object value) {
                this.config.put(Path.parse(key), value);
                return this;
            }

            NestedValueMap toMap() {
                NestedValueMap result = new NestedValueMap();
                result.put("type", type);
                result.put("challenge", challenge);
                result.put("config", config);
                return result;
            }
        }

        public static class AuthenticationBackend {
            private final String type;
            private NestedValueMap config = new NestedValueMap();

            public AuthenticationBackend(String type) {
                this.type = type;
            }

            public AuthenticationBackend config(Map<String, Object> config) {
                this.config.putAllFromAnyMap(config);
                return this;
            }

            public AuthenticationBackend config(String key, Object value) {
                this.config.put(Path.parse(key), value);
                return this;
            }

            NestedValueMap toMap() {
                NestedValueMap result = new NestedValueMap();
                result.put("type", type);
                result.put("config", config);
                return result;
            }
        }
    }

	
	
	
	
	
	
	
	
	
	
	public static class DlsFls {

		private Boolean debug;
		private String metrics;
		private String useImpl;
		private Boolean dlsAllowNow;

		public DlsFls() {
		}

		public DlsFls useImpl(String impl) {
			this.useImpl = impl;
			return this;
		}

//		// @Override
//		public Object toBasicObject() {
//			return ImmutableMap.of("default", ImmutableMap.ofNonNull("debug", debug, "metrics", metrics, "use_impl",
//					useImpl, "dls", ImmutableMap.ofNonNull("allow_now", dlsAllowNow)));
//		}
	}

//	public static class Privileges {
//		private boolean ignoreUnauthorizedIndices = true;
//
//		public Privileges() {
//
//		}
//
//		public boolean isIgnoreUnauthorizedIndices() {
//			return ignoreUnauthorizedIndices;
//		}
//
//		public Privileges ignoreUnauthorizedIndices(boolean ignoreUnauthorizedIndices) {
//			this.ignoreUnauthorizedIndices = ignoreUnauthorizedIndices;
//			return this;
//		}
//
//		// @Override
//		public Object toBasicObject() {
//			return ImmutableMap.of("default",
//					ImmutableMap.of("ignore_unauthorized_indices.enabled", ignoreUnauthorizedIndices));
//		}
//	}


    public TestSecurityConfig clone() {
        TestSecurityConfig result = new TestSecurityConfig();

        result.resourceFolder = resourceFolder;
        result.indexName = indexName;
        result.overrideRoleSettings = overrideRoleSettings != null ? overrideRoleSettings.clone() : null;
        result.overrideSecurityConfigSettings = overrideSecurityConfigSettings != null ? overrideSecurityConfigSettings.clone() : null;
        result.overrideUserSettings = overrideUserSettings != null ? overrideUserSettings.clone() : null;

        return result;
    }

	public void initIndex(Client client) {
		Map<String, Object> settings = new HashMap<>();
		if (indexName.startsWith(".")) {
			settings.put("index.hidden", true);
		}
		client.admin().indices().create(new CreateIndexRequest(indexName).settings(settings)).actionGet();

        writeConfigToIndex(client, CType.CONFIG, "config.yml", overrideSecurityConfigSettings);
        writeConfigToIndex(client, CType.ROLES, "roles.yml", overrideRoleSettings);
		writeConfigToIndex(client, CType.INTERNALUSERS, "internal_users.yml", overrideUserSettings);
        writeConfigToIndex(client, CType.ROLESMAPPING, "roles_mapping.yml", overrideRoleMappingSettings);
        writeConfigToIndex(client, CType.ACTIONGROUPS, "action_groups.yml");
        writeConfigToIndex(client, CType.TENANTS, "tenants.yml");
        
		ConfigUpdateResponse configUpdateResponse = client.execute(ConfigUpdateAction.INSTANCE,
				new ConfigUpdateRequest(CType.lcStringValues().toArray(new String[0]))).actionGet();

		if (configUpdateResponse.hasFailures()) {
			throw new RuntimeException("ConfigUpdateResponse produced failures: " + configUpdateResponse.failures());
		}
	}

//	private void writeOptionalConfigToIndex(Client client, CType configType, String file, NestedValueMap overrides) {
//
//		NestedValueMap map = new NestedValueMap();
//		NestedValueMap typeVersion = new NestedValueMap();
//		
//		typeVersion.put("type", configType.toLCString());
//		typeVersion.put("config_version", 2);
//		
//		map.put("_meta", typeVersion);
//		
//		if (overrides != null) {
//			map.putAllFromAnyMap(overrides);			
//		}
//		
//		XContentBuilder builder;
//		String json;
//
//		// todo merge maps. Or, just use overrides?
//
//		try {
//			builder = XContentFactory.jsonBuilder(); //.startObject();
//			builder.map(map);
//			json = Strings.toString(builder);
//			log.info("Writing " + configType + ":\n" + json);
//
//			client.index(new IndexRequest(indexName).id(configType.toLCString())
//					.setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(configType.toLCString(),
//							BytesReference.fromByteBuffer(ByteBuffer.wrap(json.getBytes("utf-8")))))
//					.actionGet();
//		} catch (Exception e) {
//			throw new RuntimeException("Error while initializing config for " + indexName, e);
//		}
//
		// try {
//      DocNode config = null;
//
//      if (resourceFolder != null) {
//          try {
//              config = DocNode.parse(Format.YAML).from(openFile(file));
//          } catch (FileNotFoundException e) {
//              // ignore
//          }
//      }
//
//      if (config == null) {
//          config = DocNode.of("_sg_meta.type", configType.toLCString(), "_sg_meta.config_version", 2);
//      }
//
//      if (overrides != null) {
//          config = new MergePatch(DocNode.wrap(overrides)).apply(config);
//      }
//
//      log.info("Writing " + configType + ":\n" + config.toYamlString());
//
//      client.index(new IndexRequest(indexName).id(configType.toLCString()).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
//              .source(configType.toLCString(), BytesReference.fromByteBuffer(ByteBuffer.wrap(config.toJsonString().getBytes("utf-8")))))
//              .actionGet();
//  } catch (Exception e) {
//      throw new RuntimeException("Error while initializing config for " + indexName, e);
//  }
//	}

	private static String hash(final char[] clearTextPassword) {
		final byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);
		final String hash = OpenBSDBCrypt.generate((Objects.requireNonNull(clearTextPassword)), salt, 12);
		Arrays.fill(salt, (byte) 0);
		Arrays.fill(clearTextPassword, '\0');
		return hash;
	}


    private void writeConfigToIndex(Client client, CType configType, String file) {
        writeConfigToIndex(client, configType, file, (NestedValueMap) null);
    }

	private void writeConfigToIndex(Client client, CType configType, String file, NestedValueMap overrides) {
		try {

			NestedValueMap  config = NestedValueMap.of(new NestedValueMap.Path("_meta", "type"), configType.toLCString(),
					new NestedValueMap.Path("_meta", "config_version"), 2);

			if (overrides != null) {
				config.overrideLeafs(overrides);
			}

			XContentBuilder builder = XContentFactory.jsonBuilder().map(config);
			String json = Strings.toString(builder);
			
			log.info("Writing " + configType + ":\n" + json);

			client.index(new IndexRequest(indexName).id(configType.toLCString())
					.setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(configType.toLCString(),
							BytesReference.fromByteBuffer(ByteBuffer.wrap(json.getBytes("utf-8")))))
					.actionGet();
		} catch (Exception e) {
			throw new RuntimeException("Error while initializing config for " + indexName, e);
		}
	}
}

////

////
////    private void writeOptionalConfigToIndex(Client client, String configType, String file, NestedValueMap overrides) {
////        try {
////            NestedValueMap config = null;
////
////            if (resourceFolder != null) {
////                try {
////                    config = NestedValueMap.fromYaml(openFile(file));
////                } catch (FileNotFoundException e) {
////                    // ingore
////                }
////            }
////
////            if (config == null) {
////                config = NestedValueMap.of(new NestedValueMap.Path("meta", "type"), configType,
////                        new NestedValueMap.Path("meta", "config_version"), 2);
////            }
////
////            if (overrides != null) {
////                config.overrideLeafs(overrides);
////            }
////
////            log.info("Writing " + configType + ":\n" + config.toYamlString());
////
////            client.index(new IndexRequest(indexName).id(configType).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(configType,
////                    BytesReference.fromByteBuffer(ByteBuffer.wrap(config.toJsonString().getBytes("utf-8"))))).actionGet();
////        } catch (Exception e) {
////            throw new RuntimeException("Error while initializing config for " + indexName, e);
////        }
////    }
////
////    private void writeConfigToIndex(Client client, CType<?> configType, Document<?> document) {
////        try {
////            log.info("Writing " + configType + ":\n" + document.toYamlString());
////
////            client.index(new IndexRequest(indexName).id(configType.toLCString()).setRefreshPolicy(RefreshPolicy.IMMEDIATE)
////                    .source(configType.toLCString(), BytesReference.fromByteBuffer(ByteBuffer.wrap(document.toJsonString().getBytes("utf-8")))))
////                    .actionGet();
////        } catch (Exception e) {
////            throw new RuntimeException("Error while initializing config for " + indexName, e);
////        }
////    }
////
////    private void writeConfigToIndex(Client client, String configType, Document<?> document) {
////        try {
////            log.info("Writing " + configType + ":\n" + document.toYamlString());
////
////            client.index(new IndexRequest(indexName).id(configType).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(configType,
////                    BytesReference.fromByteBuffer(ByteBuffer.wrap(document.toJsonString().getBytes("utf-8"))))).actionGet();
////        } catch (Exception e) {
////            throw new RuntimeException("Error while initializing config for " + indexName, e);
////        }
////    }
//

//    public static class Authc {
//
//        private List<Domain> domains;
//        private List<String> trustedProxies;
//
//        public Authc(Domain... domains) {
//            this.domains = ImmutableList.ofArray(domains);
//        }
//
//        public Authc trustedProxies(String... trustedProxies) {
//            this.trustedProxies = Arrays.asList(trustedProxies);
//            return this;
//        }
//
//        public static class Domain {
//
//            private final String type;
//            private String id;
//            private String description;
//            private List<String> acceptIps = null;
//            private List<String> skipIps = null;
//            private List<String> acceptUsers = null;
//            private List<String> skipUsers = null;
//            private List<AdditionalUserInformation> additionalUserInformation = null;
//            private UserMapping userMapping;
//            private DocNode backendConfig;
//            private DocNode frontendConfig;
//
//            public Domain(String type) {
//                this.type = type;
//            }
//
//            public Domain id(String id) {
//                this.id = id;
//                return this;
//            }
//
//            public Domain description(String description) {
//                this.description = description;
//                return this;
//            }
//
//            public Domain frontend(DocNode frontendConfig) {
//                this.frontendConfig = frontendConfig;
//                return this;
//            }
//
//            public Domain backend(DocNode backendConfig) {
//                this.backendConfig = backendConfig;
//                return this;
//            }
//
//            public Domain userMapping(UserMapping userMapping) {
//                this.userMapping = userMapping;
//                return this;
//            }
//
//            public Domain additionalUserInformation(AdditionalUserInformation... additionalUserInformation) {
//                if (this.additionalUserInformation == null) {
//                    this.additionalUserInformation = new ArrayList<>(Arrays.asList(additionalUserInformation));
//                } else {
//                    this.additionalUserInformation.addAll(Arrays.asList(additionalUserInformation));
//                }
//                return this;
//            }
//
//            public Domain acceptIps(String... ips) {
//                if (acceptIps == null) {
//                    acceptIps = new ArrayList<>(Arrays.asList(ips));
//                } else {
//                    acceptIps.addAll(Arrays.asList(ips));
//                }
//                return this;
//            }
//
//            public Domain skipIps(String... ips) {
//                if (skipIps == null) {
//                    skipIps = new ArrayList<>(Arrays.asList(ips));
//                } else {
//                    skipIps.addAll(Arrays.asList(ips));
//                }
//                return this;
//            }
//
//            public Domain skipUsers(String... users) {
//                skipUsers = Arrays.asList(users);
//                return this;
//            }
//
//            public Domain acceptUsers(String... users) {
//                acceptUsers = Arrays.asList(users);
//                return this;
//            }
//
//            @Override
//            public Object toBasicObject() {
//                Map<String, Object> result = new LinkedHashMap<>();
//
//                result.put("type", type);
//
//                if (id != null) {
//                    result.put("id", id);
//                }
//
//                if (description != null) {
//                    result.put("description", description);
//                }
//
//                if (frontendConfig != null) {
//                    int slash = type.indexOf('/');
//                    result.put(type.substring(0, slash != -1 ? slash : type.length()), frontendConfig);
//                }
//
//                if (backendConfig != null) {
//                    result.put(type.substring(type.indexOf('/') + 1), backendConfig);
//                }
//
//                if (acceptIps != null || acceptUsers != null) {
//                    result.put("accept", ImmutableMap.ofNonNull("ips", acceptIps, "users", acceptUsers));
//                }
//
//                if (skipIps != null || skipUsers != null) {
//                    result.put("skip", ImmutableMap.ofNonNull("ips", skipIps, "users", skipUsers));
//                }
//
//                if (additionalUserInformation != null) {
//                    result.put("additional_user_information", additionalUserInformation);
//                }
//
//                if (userMapping != null) {
//                    result.put("user_mapping", userMapping.toBasicObject());
//                }
//
//                return result;
//            }
//
////            public static class AdditionalUserInformation implements Document<AdditionalUserInformation> {
////                private String type;
////                private DocNode config;
////
////                public AdditionalUserInformation(String type) {
////                    this.type = type;
////                    this.config = null;
////                }
////
////                public AdditionalUserInformation(String type, DocNode config) {
////                    this.type = type;
////                    this.config = config;
////                }
////
////                @Override
////                public Object toBasicObject() {
////                    return ImmutableMap.ofNonNull("type", type, type, config);
////                }
////
////            }
////
////            public static class UserMapping implements Document<UserMapping> {
////                private List<DocNode> userNameFrom = new ArrayList<>();
////                private List<String> userNameStatic = new ArrayList<>();
////                private List<DocNode> userNameFromBackend = new ArrayList<>();
////                private List<DocNode> rolesFrom = new ArrayList<>();
////                private List<DocNode> rolesFromCommaSeparatedString = new ArrayList<>();
////                private List<String> rolesStatic = new ArrayList<>();
////                private Map<String, String> attrsFrom = new HashMap<>();
////                private Map<String, String> attrsStatic = new HashMap<>();
////
////                public UserMapping userNameFrom(String sourcePath) {
////                    userNameFrom.add(DocNode.wrap(sourcePath));
////                    return this;
////                }
////
////                public UserMapping userNameFrom(DocNode docNode) {
////                    userNameFrom.add(docNode);
////                    return this;
////                }
////
////                public UserMapping userNameStatic(String userName) {
////                    userNameStatic.add(userName);
////                    return this;
////                }
////
////                public UserMapping userNameFromBackend(String sourcePath) {
////                    userNameFromBackend.add(DocNode.wrap(sourcePath));
////                    return this;
////                }
////
////                public UserMapping userNameFromBackend(DocNode docNode) {
////                    userNameFromBackend.add(docNode);
////                    return this;
////                }
////
////                public UserMapping rolesFrom(String sourcePath) {
////                    rolesFrom.add(DocNode.wrap(sourcePath));
////                    return this;
////                }
////
////                public UserMapping rolesFromCommaSeparatedString(String sourcePath) {
////                    rolesFromCommaSeparatedString.add(DocNode.wrap(sourcePath));
////                    return this;
////                }
////
////                public UserMapping rolesFrom(DocNode docNode) {
////                    rolesFrom.add(docNode);
////                    return this;
////                }
////
////                public UserMapping rolesStatic(String... roles) {
////                    rolesStatic.addAll(Arrays.asList(roles));
////                    return this;
////                }
////
////                public UserMapping attrsFrom(String target, String sourcePath) {
////                    this.attrsFrom.put(target, sourcePath);
////                    return this;
////                }
////
////                public UserMapping attrsStatic(String target, String value) {
////                    this.attrsStatic.put(target, value);
////                    return this;
////                }
////
////                @Override
////                public Object toBasicObject() {
////                    Map<String, Object> result = new LinkedHashMap<>();
////
////                    if (userNameFrom.size() != 0 || userNameStatic.size() != 0 || userNameFromBackend.size() != 0) {
////                        Map<String, Object> userName = new LinkedHashMap<>();
////
////                        if (userNameFrom.size() == 1) {
////                            userName.put("from", userNameFrom.get(0));
////                        } else if (userNameFrom.size() > 1) {
////                            userName.put("from", userNameFrom);
////                        }
////
////                        if (userNameStatic.size() == 1) {
////                            userName.put("static", userNameStatic.get(0));
////                        } else if (userNameStatic.size() > 1) {
////                            userName.put("static", userNameStatic);
////                        }
////
////                        if (userNameFromBackend.size() == 1) {
////                            userName.put("from_backend", userNameFromBackend.get(0));
////                        } else if (userNameFromBackend.size() > 1) {
////                            userName.put("from_backend", userNameFromBackend);
////                        }
////
////                        result.put("user_name", userName);
////                    }
////
////                    if (rolesFrom.size() != 0 || rolesStatic.size() != 0 || rolesFromCommaSeparatedString.size() != 0) {
////                        Map<String, Object> roles = new LinkedHashMap<>();
////
////                        if (rolesFrom.size() == 1) {
////                            roles.put("from", rolesFrom.get(0));
////                        } else if (rolesFrom.size() > 1) {
////                            roles.put("from", rolesFrom);
////                        }
////
////                        if (rolesFromCommaSeparatedString.size() == 1) {
////                            roles.put("from_comma_separated_string", rolesFromCommaSeparatedString.get(0));
////                        } else if (rolesFromCommaSeparatedString.size() > 1) {
////                            roles.put("from_comma_separated_string", rolesFromCommaSeparatedString);
////                        }
////
////                        if (rolesStatic.size() == 1) {
////                            roles.put("static", rolesStatic.get(0));
////                        } else if (rolesStatic.size() > 1) {
////                            roles.put("static", rolesStatic);
////                        }
////
////                        result.put("roles", roles);
////                    }
////
////                    if (attrsFrom.size() != 0 || attrsStatic.size() != 0) {
////                        Map<String, Object> attrs = new LinkedHashMap<>();
////
////                        if (attrsFrom.size() != 0) {
////                            attrs.put("from", attrsFrom);
////                        }
////
////                        if (attrsStatic.size() != 0) {
////                            attrs.put("static", attrsStatic);
////                        }
////
////                        result.put("attrs", attrs);
////                    }
////
////                    return result;
////                }
////
////            }
////
////        }
////
////        @Override
////        public Object toBasicObject() {
////            Map<String, Object> result = new LinkedHashMap<>();
////
////            result.put("auth_domains", domains);
////
////            if (trustedProxies != null) {
////                result.put("network", ImmutableMap.of("trusted_proxies", trustedProxies));
////            }
////
////            return ImmutableMap.of("default", result);
////        }
////    }
//

//
//}
//}
//}