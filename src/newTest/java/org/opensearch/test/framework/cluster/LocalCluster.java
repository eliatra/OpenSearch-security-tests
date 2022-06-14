/*
 * Copyright 2015-2021 floragunn GmbH
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

import java.io.File;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.rules.ExternalResource;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.RoleMapping;
import org.opensearch.test.framework.certificate.TestCertificates;



public class LocalCluster extends ExternalResource implements AutoCloseable, OpenSearchClientProvider {

    private static final Logger log = LogManager.getLogger(LocalCluster.class);

    static {
        System.setProperty("security.default_init.dir", new File("./securityconfig").getAbsolutePath());
    }

    protected static final AtomicLong num = new AtomicLong();

    protected final String resourceFolder;
    private final List<Class<? extends Plugin>> plugins;
    private final ClusterConfiguration clusterConfiguration;
    private final TestSecurityConfig testSgConfig;
    private Settings nodeOverride;
    private final String clusterName;
    private final MinimumSecuritySettingsSupplierFactory minimumOpenSearchSettingsSupplierFactory;
    private final TestCertificates testCertificates;
    private final List<LocalCluster> clusterDependencies;
    private final Map<String, LocalCluster> remotes;
    private volatile LocalOpenSearchCluster localOpenSearchCluster;

    private LocalCluster(String clusterName, String resourceFolder, TestSecurityConfig testSgConfig, Settings nodeOverride,
            ClusterConfiguration clusterConfiguration, List<Class<? extends Plugin>> plugins, TestCertificates testCertificates,
            List<LocalCluster> clusterDependencies, Map<String, LocalCluster> remotes) {
        this.resourceFolder = resourceFolder;
        this.plugins = plugins;
        this.clusterConfiguration = clusterConfiguration;
        this.testSgConfig = testSgConfig;
        this.nodeOverride = nodeOverride;
        this.clusterName = clusterName;
        this.minimumOpenSearchSettingsSupplierFactory = new MinimumSecuritySettingsSupplierFactory(resourceFolder);
        this.testCertificates = testCertificates;
        this.remotes = remotes;
        this.clusterDependencies = clusterDependencies;
    }

    @Override
    public void before() throws Throwable {
        if (localOpenSearchCluster == null) {
            for (LocalCluster dependency : clusterDependencies) {
                if (!dependency.isStarted()) {
                    dependency.before();
                }
            }

            for (Map.Entry<String, LocalCluster> entry : remotes.entrySet()) {
                @SuppressWarnings("resource")
                InetSocketAddress transportAddress = entry.getValue().localOpenSearchCluster.masterNode().getTransportAddress();
                nodeOverride = Settings.builder().put(nodeOverride)
                        .putList("cluster.remote." + entry.getKey() + ".seeds", transportAddress.getHostString() + ":" + transportAddress.getPort())
                        .build();
            }

            start();
        }
    }

    @Override
    protected void after() {
        if (localOpenSearchCluster != null && localOpenSearchCluster.isStarted()) {
            try {
                Thread.sleep(1234);
                localOpenSearchCluster.destroy();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                localOpenSearchCluster = null;
            }
        }
    }

    @Override
    public void close() {
        if (localOpenSearchCluster != null && localOpenSearchCluster.isStarted()) {
            try {
                Thread.sleep(100);
                localOpenSearchCluster.destroy();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                localOpenSearchCluster = null;
            }
        }
    }

    @Override
    public String getClusterName() {
        return clusterName;
    }

    @Override
    public InetSocketAddress getHttpAddress() {
        return localOpenSearchCluster.clientNode().getHttpAddress();
    }

    @Override
    public InetSocketAddress getTransportAddress() {
        return localOpenSearchCluster.clientNode().getTransportAddress();
    }

    public Client getInternalNodeClient() {
        return localOpenSearchCluster.clientNode().getInternalNodeClient();
    }

    public Client getPrivilegedInternalNodeClient() {
    	// TODO Implement
    	throw new UnsupportedOperationException();
        // return PrivilegedConfigClient.adapt(getInternalNodeClient());
    }

    public <X> X getInjectable(Class<X> clazz) {
        return this.localOpenSearchCluster.masterNode().getInjectable(clazz);
    }

    public PluginAwareNode node() {
        return this.localOpenSearchCluster.masterNode().esNode();
    }

    public List<LocalOpenSearchCluster.Node> nodes() {
        return this.localOpenSearchCluster.getAllNodes();
    }

    public LocalOpenSearchCluster.Node getNodeByName(String name) {
        return this.localOpenSearchCluster.getNodeByName(name);
    }

    public LocalOpenSearchCluster.Node getRandomClientNode() {
        return this.localOpenSearchCluster.randomClientNode();
    }

//    public void updateSgConfig(CType<?> configType, String key, Map<String, Object> value) {
//        try (Client client = PrivilegedConfigClient.adapt(this.getInternalNodeClient())) {
//            log.info("Updating config {}.{}:{}", configType, key, value);
//            ConfigurationRepository configRepository = getInjectable(ConfigurationRepository.class);
//            String OpenSearchIndex = configRepository.getEffectiveSecurityIndex();
//
//            GetResponse getResponse = client.get(new GetRequest(OpenSearchIndex, configType.toLCString())).actionGet();
//            String jsonDoc = new String(Base64.getDecoder().decode(String.valueOf(getResponse.getSource().get(configType.toLCString()))));
//            NestedValueMap config = NestedValueMap.fromJsonString(jsonDoc);
//
//            config.put(key, value);
//
//            if (log.isTraceEnabled()) {
//                log.trace("Updated config: " + config);
//            }
//
//            IndexResponse response = client
//                    .index(new IndexRequest(OpenSearchIndex).id(configType.toLCString()).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
//                            .source(configType.toLCString(), BytesReference.fromByteBuffer(ByteBuffer.wrap(config.toJsonString().getBytes("utf-8")))))
//                    .actionGet();
//
//            if (response.getResult() != DocWriteResponse.Result.UPDATED) {
//                throw new RuntimeException("Updated failed " + response);
//            }
//
//            ConfigUpdateResponse configUpdateResponse = client
//                    .execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(CType.lcStringValues().toArray(new String[0]))).actionGet();
//
//            if (configUpdateResponse.hasFailures()) {
//                throw new RuntimeException("ConfigUpdateResponse produced failures: " + configUpdateResponse.failures());
//            }
//
//        } catch (IOException | DocumentParseException | UnexpectedDocumentStructureException e) {
//            throw new RuntimeException(e);
//        }
//    }

    public boolean isStarted() {
        return localOpenSearchCluster != null;
    }

    public Random getRandom() {
        return localOpenSearchCluster.getRandom();
    }

    private void start() {
        try {
        	// TODO: adapt constructor
//            localEsCluster = new LocalOpenSearchCluster(clusterName, clusterConfiguration,
//                    minimumOpenSearchSettingsSupplierFactory.minimumOpenSearchSettings(nodeOverride), plugins, testCertificates);
            
            localOpenSearchCluster = new LocalOpenSearchCluster(clusterName, clusterConfiguration, null, plugins, testCertificates);

            localOpenSearchCluster.start();

        } catch (Exception e) {
            log.error("Local ES cluster start failed", e);
            throw new RuntimeException(e);
        }

        if (testSgConfig != null) {
        	// TODO: Initialize security config
            // initSecurityIndex(testSgConfig);
        }
    }

    public String getResourceFolder() {
        return resourceFolder;
    }

    public static class Builder {

        private final Settings.Builder nodeOverrideSettingsBuilder = Settings.builder();
        private final List<Class<? extends Plugin>> plugins = new ArrayList<>();
        private Map<String, LocalCluster> remoteClusters = new HashMap<>();
        private List<LocalCluster> clusterDependencies = new ArrayList<>();
        private boolean sslEnabled;
        private String resourceFolder;
        private ClusterConfiguration clusterConfiguration = ClusterConfiguration.DEFAULT;
        private TestSecurityConfig testSgConfig = new TestSecurityConfig().resources("/");
        private String clusterName = "local_cluster";
        private TestCertificates testCertificates;
        private boolean enterpriseModulesEnabled;

        public Builder sslEnabled() {
        	// TODO enable SSL
//            sslEnabled(TestCertificates.builder().ca("CN=root.ca.example.com,OU=OpenSearch,O=OpenSearch")
//                    .addNodes("CN=node-0.example.com,OU=OpenSearch,O=OpenSearch").addClients("CN=client-0.example.com,OU=OpenSearch,O=OpenSearch")
//                    .addAdminClients("CN=admin-0.example.com,OU=OpenSearch,O=OpenSearch").build());
            return this;
        }

        public Builder sslEnabled(TestCertificates certificatesContext) {
            this.testCertificates = certificatesContext;
            this.sslEnabled = true;
            return this;
        }

        public Builder dependsOn(Object object) {
            // We just want to make sure that the object is already done
            if (object == null) {
                throw new IllegalStateException("Dependency not fulfilled");
            }
            return this;
        }

        public Builder resources(String resourceFolder) {
            this.resourceFolder = resourceFolder;
            testSgConfig.resources(resourceFolder);
            return this;
        }

        public Builder clusterConfiguration(ClusterConfiguration clusterConfiguration) {
            this.clusterConfiguration = clusterConfiguration;
            return this;
        }

        public Builder singleNode() {
            this.clusterConfiguration = ClusterConfiguration.SINGLENODE;
            return this;
        }

        public Builder sgConfig(TestSecurityConfig testSgConfig) {
            this.testSgConfig = testSgConfig;
            return this;
        }

        public Builder nodeSettings(Object... settings) {
            for (int i = 0; i < settings.length - 1; i += 2) {
                String key = String.valueOf(settings[i]);
                Object value = settings[i + 1];

                if (value instanceof List) {
                    List<String> values = ((List<?>) value).stream().map(String::valueOf).collect(Collectors.toList());
                    nodeOverrideSettingsBuilder.putList(key, values);
                } else {
                    nodeOverrideSettingsBuilder.put(key, String.valueOf(value));
                }
            }

            return this;
        }

        public Builder plugin(Class<? extends Plugin> plugin) {
            this.plugins.add(plugin);

            return this;
        }

        public Builder remote(String name, LocalCluster anotherCluster) {
            remoteClusters.put(name, anotherCluster);

            clusterDependencies.add(anotherCluster);

            return this;
        }

//        public Builder indices(TestIndex... indices) {
//            this.testIndices.addAll(Arrays.asList(indices));
//            return this;
//        }
//
//        public Builder aliases(TestAlias... aliases) {
//            this.testAliases.addAll(Arrays.asList(aliases));
//            return this;
//        }

        public Builder users(TestSecurityConfig.User... users) {
            for (TestSecurityConfig.User user : users) {
                testSgConfig.user(user);
            }
            return this;
        }

        public Builder user(TestSecurityConfig.User user) {
            testSgConfig.user(user);
            return this;
        }

        public Builder user(String name, String password, String... sgRoles) {
            testSgConfig.user(name, password, sgRoles);
            return this;
        }

        public Builder user(String name, String password, Role... sgRoles) {
            testSgConfig.user(name, password, sgRoles);
            return this;
        }

        public Builder roles(Role... roles) {
            testSgConfig.roles(roles);
            return this;
        }

        public Builder roleMapping(RoleMapping... mappings) {
            testSgConfig.roleMapping(mappings);
            return this;
        }

        public Builder roleToRoleMapping(Role role, String... backendRoles) {
            testSgConfig.roleToRoleMapping(role, backendRoles);
            return this;
        }

        public Builder authc(TestSecurityConfig.Authc authc) {
            testSgConfig.authc(authc);
            return this;
        }

        public Builder dlsFls(TestSecurityConfig.DlsFls dlsfls) {
            testSgConfig.dlsFls(dlsfls);
            return this;
        }

        public Builder var(String name, Supplier<Object> value) {
            testSgConfig.var(name, value);
            return this;
        }

        public Builder clusterName(String clusterName) {
            this.clusterName = clusterName;
            return this;
        }

        public Builder configIndexName(String configIndexName) {
            testSgConfig.configIndexName(configIndexName);
            return this;
        }

        public LocalCluster build() {
            try {
//                if (sslEnabled) {
//                    nodeOverrideSettingsBuilder.put("OpenSearch.ssl.http.enabled", true)
//                            .put("OpenSearch.ssl.transport.pemtrustedcas_filepath", testCertificates.getCaCertFile().getPath())
//                            .put("OpenSearch.ssl.http.pemtrustedcas_filepath", testCertificates.getCaCertFile().getPath());
//
//                }

                clusterName += "_" + num.incrementAndGet();

                return new LocalCluster(clusterName, resourceFolder, testSgConfig, nodeOverrideSettingsBuilder.build(), clusterConfiguration, plugins,
                        testCertificates, clusterDependencies, remoteClusters);
            } catch (Exception e) {
                log.error("Failed to build LocalCluster", e);
                throw new RuntimeException(e);
            }
        }

        public LocalCluster start() {
            LocalCluster localCluster = build();

            localCluster.start();

            return localCluster;
        }
    }

	@Override
	public TestCertificates getTestCertificates() {
		// TODO Implement
		throw new UnsupportedOperationException();		
	}

}
