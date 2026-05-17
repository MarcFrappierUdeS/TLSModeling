package application.system_under_test.tls_attacker;

import application.system_under_test.SystemUnderTest;
import application.system_under_test.tls_attacker.utils.ByteUtils;
import application.system_under_test.tls_attacker.utils.TlsMessageBuilder;
import application.system_under_test.tls_attacker.utils.TlsYamlParser;
// import application.information_handler.InformationConvertertoAbstract;

import java.util.LinkedHashMap;
import java.util.Map;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * TLS-Attacker client implementation that extends SystemUnderTest.
 * This class handles TLS client operations including sending ClientHello messages
 * and processing ServerHello responses.
 */
public class TLSAttackerFakeClient extends SystemUnderTest {

    /** The hostname for the TLS connection */
    private static final String HOST = "localhost";

    /** The port number for the TLS connection */
    private static final int PORT = 8443;

    /** The path to the ClientHello YAML file to use (default: hardcoded model) */
    private String clientHelloYamlPath = "src/main/resources/data/ModelClientHello.yaml";

    private State state;
    private TransportHandler transportHandler;
    private Config config;

    /**
     * Sets the path to the ClientHello YAML file to use.
     * This allows using dynamically generated ClientHello instead of the hardcoded one.
     * 
     * @param yamlPath the path to the ClientHello YAML file
     */
    public void setClientHelloYamlPath(String yamlPath) {
        this.clientHelloYamlPath = yamlPath;
        System.out.println("ClientHello YAML path set to: " + yamlPath);
    }

    /**
     * Gets the current ClientHello YAML path.
     * 
     * @return the path to the ClientHello YAML file
     */
    public String getClientHelloYamlPath() {
        return this.clientHelloYamlPath;
    }

    /**
     * Initializes the TLS connection and layers.
     * This follows a reactive/manual pattern using TransportHandler directly instead of 
     * a pre-defined WorkflowExecutor. This approach provides maximum flexibility 
     * for Model-Based Testing, allowing us to send/receive messages on-demand 
     * based on the model's instructions.
     */
    private void initializeConnections() throws Exception {
        System.out.println("[Client] Configuring and initializing network layers...");
        
        config = Config.createConfig();
        OutboundConnection connection = new OutboundConnection(HOST, PORT);
        connection.setAlias("client");
        connection.setTransportHandlerType(TransportHandlerType.TCP);
        connection.setConnectionTimeout(5000);
        config.setDefaultClientConnection(connection);

        // Default protocol version configuration
        config.setHighestProtocolVersion(de.rub.nds.tlsattacker.core.constants.ProtocolVersion.TLS13);
        config.setSupportedVersions(de.rub.nds.tlsattacker.core.constants.ProtocolVersion.TLS13);

        // Enable standard extensions required for a typical TLS 1.3 handshake
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);

        WorkflowTrace trace = new WorkflowTrace();
        state = new State(config, trace); 
        
        // Manual layer preparation - essential when not using DefaultWorkflowExecutor
        state.getContext().prepareWithLayers(StackConfiguration.TLS);

        transportHandler = TransportHandlerFactory.createTransportHandler(state.getContext().getConnection());
        state.getContext().setTransportHandler(transportHandler);
        transportHandler.initialize();
    }

    /**
     * Closes the active TLS connection and releases network resources.
     */
    public void close() {
        if (transportHandler != null) {
            try {
                transportHandler.closeConnection();
                System.out.println("[Client] Connection closed.");
            } catch (Exception e) {
                // Ignore closing errors
            }
        }
    }

    /**
     * Implementation of the SUT execution cycle.
     * Unlike standard TLS-Attacker usage, this method implements a reactive control loop:
     * 1. Load instructions from ProB (YAML)
     * 2. Translate abstract parameters into a concrete TLS message
     * 3. Send the message and capture ALL server responses using GenericReceiveAction
     * 4. Parse responses back to YAML for model validation
     */
    @Override
    public void createSUT() {
        try {
            // Initialize the low-level connection
            initializeConnections();

            boolean isRunning = true;
            List<ProtocolMessage> lastReceivedMessages = new ArrayList<>();

            System.out.println("\n=== STARTING REACTIVE CONTROL LOOP ===");

            while (isRunning) {
                // STEP 1: Retrieve data from .yaml (Input)
                // We read the "abstract" message generated by the ProB formal model
                Map<String, Object> yamlRoot = TlsYamlParser.readYamlAsObject(clientHelloYamlPath);
                
                @SuppressWarnings("unchecked")
                Map<String, String> clientHelloMap = (Map<String, String>) yamlRoot.get("clientHelloInformation");
                
                if (clientHelloMap == null) {
                    throw new RuntimeException("clientHelloInformation section not found in YAML");
                }

                // STEP 2: Prepare the message (Translation)
                System.out.println("[Client] Preparing ClientHello from YAML instructions...");
                
                // IMPORTANT: Configure cipher suites and groups in the Config object BEFORE message creation
                // TLS-Attacker uses the config as a template for new messages
                TlsMessageBuilder.configureFromYaml(clientHelloMap, config);

                ClientHelloMessage clientHello = new ClientHelloMessage(config);
                
                /*
                 * TECHNICAL NOTE ON MODIFIABLE VARIABLES:
                 * TLS-Attacker uses a "ModifiableVariable" system to allow fine-grained protocol manipulation.
                 * To bypass the standard config and inject specific/invalid values for testing, use:
                 * clientHello.setSessionId(Modifiable.explicit(new byte[]{0x01, 0x02}));
                 * This is the key for fuzzing or negative testing.
                 */

                // Add extensions manually via the Builder to ensure they match the YAML exactly
                TlsMessageBuilder.addExtensionsToClientHello(clientHelloMap, clientHello);

                // EXECUTION: Manual send action
                System.out.println("[Client] Sending ClientHello...");
                SendAction sendAction = new SendAction("client", clientHello);
                sendAction.execute(state);
                state.getWorkflowTrace().addTlsAction(sendAction);

                // EXECUTION: Generic reception (Step 3)
                // We use GenericReceiveAction because in TLS 1.3, a single ClientHello 
                // triggers a burst of server messages (ServerHello, EncryptedExtensions, Cert, etc.)
                System.out.println("[Client] Listening for server responses...");
                GenericReceiveAction receiveAction = new GenericReceiveAction("client");
                receiveAction.execute(state);
                state.getWorkflowTrace().addTlsAction(receiveAction);

                if (receiveAction.getReceivedMessages() != null && !receiveAction.getReceivedMessages().isEmpty()) {
                    System.out.println("[Client] Captured messages:");
                    for (ProtocolMessage msg : receiveAction.getReceivedMessages()) {
                        System.out.println("  -> " + msg.toCompactString());
                        
                        // If it's a ServerHello, perform basic extraction (Step 4)
                        if (msg instanceof ServerHelloMessage) {
                            handleServerHello((ServerHelloMessage) msg);
                        }
                    }
                    lastReceivedMessages.addAll(receiveAction.getReceivedMessages());
                } else {
                    System.out.println("[Client] No messages received (timeout or connection reset).");
                }

                // Currently stops after one handshake flight (can be looped based on ProB state later)
                isRunning = false;
            }

        } catch (Exception e) {
            System.err.println("Error during FakeClient execution: " + e.getMessage());
            e.printStackTrace();
        } finally {
            close();
            System.out.println("=== END OF CONTROL LOOP ===");
        }
    }

    /**
     * Temporary handler for ServerHello data extraction for ProB validation.
     * Choice: This logic will eventually be moved to a dedicated 'TlsMessageParser' utility class
     * to keep the FakeClient lean and focused on workflow orchestration.
     */
    private void handleServerHello(ServerHelloMessage response) {
        Map<String, String> parsed = new LinkedHashMap<>();
        parsed.put("random", ByteUtils.bytesToHex(response.getRandom().getValue()));
        parsed.put("pre_shared_key", "{}");
        
        // Format mapping to match the B-Model expected syntax (e.g., prefixing hex with 'x')
        if (response.getSessionId() != null && response.getSessionId().getValue() != null && response.getSessionId().getValue().length > 0) {
            parsed.put("legacy_session_id_echo", "x" + ByteUtils.bytesToHex(response.getSessionId().getValue()));
        } else {
            parsed.put("legacy_session_id_echo", "x");
        }
        
        parsed.put("legacy_version", "x" + ByteUtils.bytesToHex(response.getProtocolVersion().getValue()));
        parsed.put("supported_versions", "{TLS_1_3}");
        parsed.put("legacy_compression_methods", "0");
        parsed.put("key_share", "{}");
        
        CipherSuite selectedCipherSuite = CipherSuite.getCipherSuite(response.getSelectedCipherSuite().getValue());
        if (selectedCipherSuite != null) {
            parsed.put("cipher_suites", selectedCipherSuite.name());
        } else {
            parsed.put("cipher_suites", "UNKNOWN");
        }

        Map<String, Object> wrapped = Map.of("serverHelloInformation", parsed);
        TlsYamlParser.writeYaml(wrapped, "src/main/resources/data/SUTServerHello.yaml");
        System.out.println("[Parser] ServerHello saved to YAML for ProB validation.");
    }

    /**
     * Starts the System Under Test.
     * Not required for this implementation.
     */
    @Override
    public void startSUT() {
        // Not needed for this implementation
    }

    /**
     * Executes operations on the System Under Test.
     * Not required for this implementation.
     */
    @Override
    public void executeSUTOperation() {
        // Not needed for this implementation
    }
}
