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
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import java.util.SortedSet;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.google.common.net.InetAddresses;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.Strings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.http.BindHttpException;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager.NodeSettings;
import org.opensearch.transport.BindTransportException;

import static java.util.Objects.requireNonNull;
import static org.junit.Assert.assertEquals;
import static org.opensearch.test.framework.cluster.NodeType.CLIENT;
import static org.opensearch.test.framework.cluster.NodeType.DATA;
import static org.opensearch.test.framework.cluster.NodeType.MASTER;

public class LocalOpenSearchCluster {

    static {
        System.setProperty("opensearch.enforce.bootstrap.checks", "true");
    }

    private static final Logger log = LogManager.getLogger(LocalOpenSearchCluster.class);

    private final String clusterName;
    private final ClusterManager clusterConfiguration;
    private final NodeSettingsSupplier nodeSettingsSupplier;
    private final List<Class<? extends Plugin>> additionalPlugins;
    private final List<Node> nodes = new ArrayList<>();
    private final TestCertificates testCertificates;

    private File clusterHomeDir;
    private List<String> seedHosts;
    private List<String> initialMasterHosts;
    private int retry = 0;
    private boolean started;
    private Random random = new Random();

    public LocalOpenSearchCluster(String clusterName, ClusterManager clusterConfiguration, NodeSettingsSupplier nodeSettingsSupplier,
                          List<Class<? extends Plugin>> additionalPlugins, TestCertificates testCertificates) {
        this.clusterName = clusterName;
        this.clusterConfiguration = clusterConfiguration;
        this.nodeSettingsSupplier = nodeSettingsSupplier;
        this.additionalPlugins = additionalPlugins;
        this.testCertificates = testCertificates;
        try {
			this.clusterHomeDir = Files.createTempDirectory("local_cluster_" + clusterName).toFile();
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}        
    }

    private List<Node> getNodesByType(NodeType nodeType) {
        return nodes.stream()
            .filter(currentNode -> currentNode.hasAssignedType(nodeType))
            .collect(Collectors.toList());
    }

    private long countNodesByType(NodeType nodeType) {
        return getNodesByType(nodeType).stream().count();
    }

    public void start() throws Exception {
        log.info("Starting {}", clusterName);

        int forkNumber = getUnitTestForkNumber();
        int masterNodeCount = clusterConfiguration.getMasterNodes();
        int nonMasterNodeCount = clusterConfiguration.getDataNodes() + clusterConfiguration.getClientNodes();

        SortedSet<Integer> masterNodeTransportPorts = PortAllocator.TCP.allocate(clusterName, Math.max(masterNodeCount, 4), 5000 + forkNumber * 1000 + 300);
        SortedSet<Integer> masterNodeHttpPorts = PortAllocator.TCP.allocate(clusterName, masterNodeCount, 5000 + forkNumber * 1000 + 200);

        this.seedHosts = toHostList(masterNodeTransportPorts);
        this.initialMasterHosts = toHostList(masterNodeTransportPorts.stream().limit(masterNodeCount).collect(Collectors.toSet()));

        started = true;

        CompletableFuture<Void> masterNodeFuture = startNodes(clusterConfiguration.getMasterNodeSettings(), masterNodeTransportPorts,
                masterNodeHttpPorts);

        SortedSet<Integer> nonMasterNodeTransportPorts = PortAllocator.TCP.allocate(clusterName, nonMasterNodeCount, 5000 + forkNumber * 1000 + 310);
        SortedSet<Integer> nonMasterNodeHttpPorts = PortAllocator.TCP.allocate(clusterName, nonMasterNodeCount, 5000 + forkNumber * 1000 + 210);

        CompletableFuture<Void> nonMasterNodeFuture = startNodes(clusterConfiguration.getNonMasterNodeSettings(), nonMasterNodeTransportPorts,
                nonMasterNodeHttpPorts);

        CompletableFuture.allOf(masterNodeFuture, nonMasterNodeFuture).join();

        if (isNodeFailedWithPortCollision()) {
            log.info("Detected port collision for master node. Retrying.");

            retry();
            return;
        }

        log.info("Startup finished. Waiting for GREEN");

        waitForCluster(ClusterHealthStatus.GREEN, TimeValue.timeValueSeconds(10), nodes.size());

        log.info("Started: {}", this);

    }

    public String getClusterName() {
        return clusterName;
    }

    public boolean isStarted() {
        return started;
    }

    public void stop() {
        for (Node node : getNodesByType(CLIENT)) {
            node.stop();
        }

        for (Node node : getNodesByType(DATA)) {
            node.stop();
        }

        for (Node node : getNodesByType(MASTER)) {
            node.stop();
        }
    }

    public void destroy() {
        stop();
        nodes.clear();

        try {
            FileUtils.deleteDirectory(clusterHomeDir);
        } catch (IOException e) {
            log.warn("Error while deleting " + clusterHomeDir, e);
        }
    }

    public Node clientNode() {
        return findRunningNode(getNodesByType(CLIENT), getNodesByType(DATA), getNodesByType(MASTER));
    }

    public Node masterNode() {
        return findRunningNode(getNodesByType(MASTER));
    }

    public List<Node> getNodes() {
        return Collections.unmodifiableList(nodes);
    }

    public Node getNodeByName(String name) {
        return nodes.stream().filter(node -> node.getNodeName().equals(name)).findAny().orElseThrow(() -> new RuntimeException(
                "No such node with name: " + name + "; available: " + nodes.stream().map(Node::getNodeName).collect(Collectors.toList())));
    }
    
    private boolean isNodeFailedWithPortCollision() {
        return nodes.stream().anyMatch(Node::isPortCollision);
    }

    private void retry() throws Exception {
        retry++;

        if (retry > 10) {
            throw new RuntimeException("Detected port collisions for master node. Giving up.");
        }

        stop();

        this.nodes.clear();
        this.seedHosts = null;
        this.initialMasterHosts = null;
        this.clusterHomeDir = Files.createTempDirectory("local_cluster_" + clusterName + "_retry_" + retry).toFile();

        start();
    }

    @SafeVarargs
    private final Node findRunningNode(List<Node> nodes, List<Node>... moreNodes) {
        for (Node node : nodes) {
            if (node.isRunning()) {
                return node;
            }
        }

        if (moreNodes != null && moreNodes.length > 0) {
            for (List<Node> nodesList : moreNodes) {
                for (Node node : nodesList) {
                    if (node.isRunning()) {
                        return node;
                    }
                }
            }
        }

        return null;
    }

    private CompletableFuture<Void> startNodes(List<NodeSettings> nodeSettingList, SortedSet<Integer> transportPorts, SortedSet<Integer> httpPorts) {
        Iterator<Integer> transportPortIterator = transportPorts.iterator();
        Iterator<Integer> httpPortIterator = httpPorts.iterator();
        List<CompletableFuture<String>> futures = new ArrayList<>();

        for (NodeSettings nodeSettings : nodeSettingList) {
            Node node = new Node(nodeSettings, transportPortIterator.next(), httpPortIterator.next());
            futures.add(node.start());
        }

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    }

    public void waitForCluster(ClusterHealthStatus status, TimeValue timeout, int expectedNodeCount) throws IOException {
        Client client = clientNode().getInternalNodeClient();

        
            log.debug("waiting for cluster state {} and {} nodes", status.name(), expectedNodeCount);
            AdminClient adminClient = client.admin();

            final ClusterHealthResponse healthResponse = adminClient.cluster().prepareHealth().setWaitForStatus(status).setTimeout(timeout)
                    .setMasterNodeTimeout(timeout).setWaitForNodes("" + expectedNodeCount).execute().actionGet();

            if (log.isDebugEnabled()) {
                log.debug("Current ClusterState:\n{}", Strings.toString(healthResponse));
            }

            if (healthResponse.isTimedOut()) {
                throw new IOException(
                        "cluster state is " + healthResponse.getStatus().name() + " with " + healthResponse.getNumberOfNodes() + " nodes");
            } else {
                log.debug("... cluster state ok {} with {} nodes", healthResponse.getStatus().name(), healthResponse.getNumberOfNodes());
            }

            assertEquals(expectedNodeCount, healthResponse.getNumberOfNodes());
       
    }

    @Override
    public String toString() {
        String masterNodes = nodeByTypeToString(MASTER);
        String dataNodes = nodeByTypeToString(DATA);
        String clientNodes = nodeByTypeToString(CLIENT);
        return "\nES Cluster " + clusterName + "\nmaster nodes: " + masterNodes + "\n  data nodes: " + dataNodes + "\nclient nodes: " + clientNodes
                + "\n";
    }

    private String nodeByTypeToString(NodeType type) {
        return getNodesByType(type).stream().map(Objects::toString).collect(Collectors.joining(", "));
    }

    private static List<String> toHostList(Collection<Integer> ports) {
        return ports.stream().map(port -> "127.0.0.1:" + port).collect(Collectors.toList());
    }

    private String createNextNodeName(NodeSettings nodeSettings) {
        NodeType type = nodeSettings.recognizeNodeType();
        long nodeTypeCount = countNodesByType(type);
        String nodeType = type.name().toLowerCase(Locale.ROOT);
        return nodeType + "_" + nodeTypeCount;
    }

    public class Node implements OpenSearchClientProvider {
        private final NodeType nodeType;
        private final String nodeName;
        private final NodeSettings nodeSettings;
        private final File nodeHomeDir;
        private final File dataDir;
        private final File logsDir;
        private final int transportPort;
        private final int httpPort;
        private final InetSocketAddress httpAddress;
        private final InetSocketAddress transportAddress;
        private PluginAwareNode node;
        private boolean running = false;
        private boolean portCollision = false;

        Node(NodeSettings nodeSettings, int transportPort, int httpPort) {
            this.nodeName = createNextNodeName(requireNonNull(nodeSettings, "Node settings are required."));
            this.nodeSettings = nodeSettings;
            this.nodeHomeDir = new File(clusterHomeDir, nodeName);
            this.dataDir = new File(this.nodeHomeDir, "data");
            this.logsDir = new File(this.nodeHomeDir, "logs");
            this.transportPort = transportPort;
            this.httpPort = httpPort;
            InetAddress hostAddress = InetAddresses.forString("127.0.0.1");
            this.httpAddress = new InetSocketAddress(hostAddress, httpPort);
            this.transportAddress = new InetSocketAddress(hostAddress, transportPort);

            this.nodeType = nodeSettings.recognizeNodeType();
            nodes.add(this);
        }

        boolean hasAssignedType(NodeType type) {
            return requireNonNull(type, "Node type is required.").equals(this.nodeType);
        }

        CompletableFuture<String> start() {
            CompletableFuture<String> completableFuture = new CompletableFuture<>();
            Class<? extends Plugin>[] mergedPlugins = nodeSettings.pluginsWithAddition(additionalPlugins);
            this.node = new PluginAwareNode(nodeSettings.masterNode, getOpenSearchSettings(), mergedPlugins);

            new Thread(new Runnable() {

                @Override
                public void run() {
                    try {
                        node.start();
                        running = true;
                        completableFuture.complete("initialized");
                    } catch (BindTransportException | BindHttpException e) {
                        log.warn("Port collision detected for {}", this, e);
                        portCollision = true;
                        try {
                            node.close();
                        } catch (IOException e1) {
                            log.error(e1);
                        }

                        node = null;
                        PortAllocator.TCP.reserve(transportPort, httpPort);

                        completableFuture.complete("retry");

                    } catch (Throwable e) {
                        log.error("Unable to start {}", this, e);
                        node = null;
                        completableFuture.completeExceptionally(e);
                    }
                }
            }).start();

            return completableFuture;
        }

        public Client getInternalNodeClient() {
            return node.client();
        }

        public PluginAwareNode esNode() {
            return node;
        }

        public boolean isRunning() {
            return running;
        }

        public <X> X getInjectable(Class<X> clazz) {
            return node.injector().getInstance(clazz);
        }

        public void stop() {
            try {
                log.info("Stopping {}", this);

                running = false;

                if (node != null) {
                    node.close();
                    node = null;
                    Thread.sleep(10);
                }

            } catch (Throwable e) {
                log.warn("Error while stopping " + this, e);
            }
        }

        @Override
        public String toString() {
            String state = running ? "RUNNING" : node != null ? "INITIALIZING" : "STOPPED";

            return nodeName + " " + state + " [" + transportPort + ", " + httpPort + "]";
        }

        public boolean isPortCollision() {
            return portCollision;
        }

        public String getNodeName() {
            return nodeName;
        }

        @Override
        public InetSocketAddress getHttpAddress() {
            return httpAddress;
        }

        @Override
        public InetSocketAddress getTransportAddress() {
            return transportAddress;
        }

        private Settings getOpenSearchSettings() {
            Settings settings = getMinimalOpenSearchSettings();

            if (nodeSettingsSupplier != null) {
                // TODO node number
                return Settings.builder().put(settings).put(nodeSettingsSupplier.get(0)).build();
            }

            return settings;
        }

        private Settings getMinimalOpenSearchSettings() {
            return Settings.builder().put("node.name", nodeName).put("node.data", nodeSettings.dataNode).put("node.master", nodeSettings.masterNode)
                    .put("cluster.name", clusterName).put("path.home", nodeHomeDir.toPath()).put("path.data", dataDir.toPath())
                    .put("path.logs", logsDir.toPath()).putList("cluster.initial_master_nodes", initialMasterHosts)
                    .put("discovery.initial_state_timeout", "8s").putList("discovery.seed_hosts", seedHosts).put("transport.tcp.port", transportPort)
                    .put("http.port", httpPort).put("cluster.routing.allocation.disk.threshold_enabled", false)
                    .put("discovery.probe.connect_timeout", "10s").put("discovery.probe.handshake_timeout", "10s").put("http.cors.enabled", true)
                    .build();
        }

        @Override
        public String getClusterName() {
            return clusterName;
        }

        @Override
        public TestCertificates getTestCertificates() {
            return testCertificates;
        }
    }
    
    private static int getUnitTestForkNumber() {
        String forkno = System.getProperty("forkno");

        if (forkno != null && forkno.length() > 0) {
            return Integer.parseInt(forkno.split("_")[1]);
        } else {
            return 42;
        }
    }

    public Random getRandom() {
        return random;
    }

}
