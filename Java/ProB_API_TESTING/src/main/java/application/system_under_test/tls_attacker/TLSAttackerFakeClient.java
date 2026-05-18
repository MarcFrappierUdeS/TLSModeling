package application.system_under_test.tls_attacker;

import application.system_under_test.SystemUnderTest;
import application.system_under_test.tls_attacker.utils.ByteUtils;
import application.system_under_test.tls_attacker.utils.TlsMessageBuilder;
import application.system_under_test.tls_attacker.utils.TlsMessageParser;
import application.system_under_test.tls_attacker.utils.TlsYamlParser;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
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
     * This setup is intended to be called once at the start of a test session.
     */
    public void connect() throws Exception {
        if (transportHandler != null && transportHandler.isInitialized()) {
            return; // Already connected
        }

        System.out.println("[Client] Initializing network layers...");
        
        config = Config.createConfig();
        OutboundConnection connection = new OutboundConnection(HOST, PORT);
        connection.setAlias("client");
        connection.setTransportHandlerType(TransportHandlerType.TCP);
        connection.setConnectionTimeout(5000);
        config.setDefaultClientConnection(connection);

        // Standard TLS 1.3 configuration
        config.setHighestProtocolVersion(de.rub.nds.tlsattacker.core.constants.ProtocolVersion.TLS13);
        config.setSupportedVersions(de.rub.nds.tlsattacker.core.constants.ProtocolVersion.TLS13);
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);

        WorkflowTrace trace = new WorkflowTrace();
        state = new State(config, trace); 
        state.getContext().prepareWithLayers(StackConfiguration.TLS);

        transportHandler = TransportHandlerFactory.createTransportHandler(state.getContext().getConnection());
        state.getContext().setTransportHandler(transportHandler);
        transportHandler.initialize();
        System.out.println("[Client] Connected to " + HOST + ":" + PORT);
    }

    /**
     * Executes exactly ONE MBT cycle:
     * 1. Read abstract instruction from ProB (YAML)
     * 2. Send the concrete TLS message
     * 3. Capture and parse the response(s) back to YAML
     * 
     * This method no longer contains a loop; orchestration is handled externally.
     */
    public void executeCycle() throws Exception {
        // Ensure we are connected
        connect();

        // STEP 1: Retrieve data from .yaml (Input)
        Map<String, Object> yamlRoot = TlsYamlParser.readYamlAsObject(clientHelloYamlPath);
        @SuppressWarnings("unchecked")
        Map<String, String> clientHelloMap = (Map<String, String>) yamlRoot.get("clientHelloInformation");
        
        if (clientHelloMap == null) {
            throw new RuntimeException("clientHelloInformation section not found in YAML");
        }

        // STEP 2: Prepare and Send message
        System.out.println("[Client] Sending message defined in YAML...");
        TlsMessageBuilder.configureFromYaml(clientHelloMap, config);
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        TlsMessageBuilder.addExtensionsToClientHello(clientHelloMap, clientHello);

        SendAction sendAction = new SendAction("client", clientHello);
        sendAction.execute(state);
        state.getWorkflowTrace().addTlsAction(sendAction);

        // STEP 3: Receive and Parse responses
        // We use the guided approach to ensure decryption of the TLS 1.3 flight
        receiveAndProcessResponses();
    }

    /**
     * Internal helper to handle the reception flight logic.
     * In TLS 1.3, the server sends a burst flight. This method ensures that
     * even if messages are received before keys are updated, they are processed correctly.
     */
    private void receiveAndProcessResponses() {
        System.out.println("[Client] Receiving server response flight...");
        
        // Guided reception of the standard TLS 1.3 server flight
        ReceiveAction receiveHandshake = new ReceiveAction("client",
            new ServerHelloMessage(), 
            new EncryptedExtensionsMessage(),
            new CertificateMessage(),
            new CertificateVerifyMessage(),
            new FinishedMessage()
        );
        receiveHandshake.execute(state);
        state.getWorkflowTrace().addTlsAction(receiveHandshake);

        if (receiveHandshake.getReceivedMessages() != null && !receiveHandshake.getReceivedMessages().isEmpty()) {
            System.out.println("[Client] Captured " + receiveHandshake.getReceivedMessages().size() + " messages.");
            
            for (ProtocolMessage msg : receiveHandshake.getReceivedMessages()) {
                System.out.println("  -> " + msg.toCompactString());
                
                // Process each message. 
                // Note: If some were decrypted on-the-fly by the guided action, 
                // they will already be of the correct type (not APPLICATION).
                processReceivedMessage(msg);
            }
        } else {
            System.out.println("[Client] No handshake messages received (check for Alert).");
        }
    }

    /**
     * Legacy entry point for backward compatibility with current TestExaminer.
     * Performs a full one-shot handshake cycle.
     */
    @Override
    public void createSUT() {
        try {
            System.out.println("\n=== EXECUTING SUT CYCLE (Legacy Wrapper) ===");
            executeCycle();
        } catch (Exception e) {
            System.err.println("Error during FakeClient execution: " + e.getMessage());
            e.printStackTrace();
        } finally {
            terminate();
            System.out.println("=== SUT CYCLE FINISHED ===");
        }
    }

    /**
     * Closes the active TLS connection and releases network resources.
     */
    public void terminate() {
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
     * Identifies the message type, extracts abstract data using TlsMessageParser,
     * and saves it to a corresponding YAML file.
     * 
     * @param msg The received TLS message
     */
    private void processReceivedMessage(ProtocolMessage msg) {
        Map<String, String> abstractData = null;
        String fileName = null;
        String rootKey = null;

        if (msg instanceof ServerHelloMessage) {
            abstractData = TlsMessageParser.parseServerHello((ServerHelloMessage) msg);
            fileName = "src/main/resources/data/SUTServerHello.yaml";
            rootKey = "serverHelloInformation";
        } else if (msg instanceof EncryptedExtensionsMessage) {
            abstractData = TlsMessageParser.parseEncryptedExtensions((EncryptedExtensionsMessage) msg);
            fileName = "src/main/resources/data/SUTEncryptedExtensions.yaml";
            rootKey = "encryptedExtensionsInformation";
        } else if (msg instanceof CertificateMessage) {
            abstractData = TlsMessageParser.parseCertificate((CertificateMessage) msg);
            fileName = "src/main/resources/data/SUTCertificate.yaml";
            rootKey = "certificateInformation";
        } else if (msg instanceof CertificateVerifyMessage) {
            // Model doesn't seem to have a dedicated SendCertificateVerify operation separate from Certificate?
            abstractData = Map.of("signature", "valid"); // Simplified for now
            fileName = "src/main/resources/data/SUTCertificateVerify.yaml";
            rootKey = "certificateVerifyInformation";
        } else if (msg instanceof FinishedMessage) {
            abstractData = TlsMessageParser.parseFinished((FinishedMessage) msg);
            fileName = "src/main/resources/data/SUTFinished.yaml";
            rootKey = "finishedInformation";
        } else if (msg instanceof AlertMessage) {
            abstractData = TlsMessageParser.parseAlert((AlertMessage) msg);
            fileName = "src/main/resources/data/SUTAlert.yaml";
            rootKey = "alertInformation";
        }

        if (abstractData != null && fileName != null && rootKey != null) {
            Map<String, Object> wrapped = Map.of(rootKey, abstractData);
            TlsYamlParser.writeYaml(wrapped, fileName);
            System.out.println("[Parser] " + msg.getClass().getSimpleName() + " saved to " + fileName);
        }
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
