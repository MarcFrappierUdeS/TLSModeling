package application.system_under_test.tls_attacker;

import application.system_under_test.SystemUnderTest;
import application.system_under_test.tls_attacker.utils.ByteUtils;
import application.system_under_test.tls_attacker.utils.TlsMessageBuilder;
import application.system_under_test.tls_attacker.utils.TlsMessageParser;
import application.system_under_test.tls_attacker.utils.TlsYamlParser;
import application.system_under_test.tls_attacker.utils.ProbCommand;
import application.system_under_test.tls_attacker.utils.TlsEventResult;

import java.io.File;
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
     * * @param yamlPath the path to the ClientHello YAML file
     */
    public void setClientHelloYamlPath(String yamlPath) {
        this.clientHelloYamlPath = yamlPath;
        System.out.println("ClientHello YAML path set to: " + yamlPath);
    }

    /**
     * Gets the current ClientHello YAML path.
     * * @return the path to the ClientHello YAML file
     */
    public String getClientHelloYamlPath() {
        return this.clientHelloYamlPath;
    }

    /**
     * Watches for prob_command.yaml and executes commands in a loop.
     */
    public void startCommandWatcher() {
        System.out.println("[Client] Starting command watcher on prob_command.yaml...");
        String commandFile = "prob_command.yaml";
        File file = new File(commandFile);
        
        while (true) {
            if (file.exists()) {
                try {
                    System.out.println("[Client] Command file detected. Reading...");
                    ProbCommand cmd = TlsYamlParser.parseProbCommand(commandFile);
                    
                    // Delete the command file so we don't process it twice
                    file.delete();
                    
                    executeCommand(cmd);
                } catch (Exception e) {
                    System.err.println("[Client] Error executing command: " + e.getMessage());
                    e.printStackTrace();
                    
                    // Write error event
                    TlsEventResult errorEvent = new TlsEventResult("FAILURE", "ERROR", Map.of("error", e.getMessage()));
                    TlsYamlParser.writeTlsEvent(errorEvent, "tls_event.yaml");
                }
            }
            
            try {
                Thread.sleep(500); // Poll every 500ms
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /**
     * Dispatches the command to send or listen.
     */
    public void executeCommand(ProbCommand cmd) throws Exception {
        System.out.println("[Client] Executing " + cmd.getAction() + " for " + cmd.getMessageType());
        if ("SEND".equalsIgnoreCase(cmd.getAction())) {
            executeSend(cmd);
        } else if ("LISTEN".equalsIgnoreCase(cmd.getAction())) {
            executeListen(cmd);
        } else {
            throw new IllegalArgumentException("Unknown action: " + cmd.getAction());
        }
    }

    /**
     * Executes a SEND action.
     */
    private void executeSend(ProbCommand cmd) throws Exception {
        connect();
        
        System.out.println("[Client] 📤 Preparing to send: " + cmd.getMessageType());
        ProtocolMessage msg = null;
        if ("ClientHello".equalsIgnoreCase(cmd.getMessageType())) {
            // Convert Map<String, Object> to Map<String, String> for TlsMessageBuilder
            Map<String, String> stringParams = new LinkedHashMap<>();
            cmd.getParameters().forEach((k, v) -> {
                String val = String.valueOf(v);
                stringParams.put(k, val);
            });
            
            System.out.println("[Client] ⚙️ Configuring message with parameters: " + stringParams);
            TlsMessageBuilder.configureFromYaml(stringParams, config);
            ClientHelloMessage ch = new ClientHelloMessage(config);
            TlsMessageBuilder.addExtensionsToClientHello(stringParams, ch);
            msg = ch;
        } else {
            // TODO: Add other message types
            throw new UnsupportedOperationException("Send not implemented for: " + cmd.getMessageType());
        }

        if (msg != null) {
            System.out.println("[Client] 🚀 Sending " + msg.getClass().getSimpleName() + "...");
            SendAction sendAction = new SendAction("client", msg);
            sendAction.execute(state);
            state.getWorkflowTrace().addTlsAction(sendAction);
            
            TlsEventResult result = new TlsEventResult("SENT_OK", cmd.getMessageType(), Map.of());
            TlsYamlParser.writeTlsEvent(result, "tls_event.yaml");
            System.out.println("[Client] ✅ Message sent successfully.");
        }
    }

    // On garde un buffer de messages décodés au niveau de la classe
    private java.util.Queue<ProtocolMessage> flightBuffer = new java.util.LinkedList<>();

    /**
     * Executes a LISTEN action, managing TLS 1.3 Flights automatically.
     */
    private void executeListen(ProbCommand cmd) throws Exception {
        connect();
        String expectedType = cmd.getMessageType();
        System.out.println("[Client] 📡 Listening for network messages (Expected: " + expectedType + ")...");

        // Si notre buffer est vide, on doit lire le réseau
        if (flightBuffer.isEmpty()) {
            System.out.println("[Client] 🌐 Reading from socket (Full TLS 1.3 Flight)...");

            // 🌟 LA CORRECTION EST ICI 🌟
            // On ordonne à TLS-Attacker de s'attendre à la volée complète. 
            // C'est indispensable pour qu'il active le déchiffrement des messages 
            // qui suivent le ServerHello dans le même paquet TCP !
            ReceiveAction receiveAction = new ReceiveAction("client",
                new ServerHelloMessage(),
                new EncryptedExtensionsMessage(),
                new CertificateMessage(),
                new CertificateVerifyMessage(),
                new FinishedMessage()
            );

            receiveAction.execute(state);
            state.getWorkflowTrace().addTlsAction(receiveAction);

            List<ProtocolMessage> received = receiveAction.getReceivedMessages();

            if (received != null && !received.isEmpty()) {
                System.out.println("[Client] 📥 Received " + received.size() + " message(s) from flight.");
                flightBuffer.addAll(received);
            }
        }

        // On consomme le buffer (Un par un, pour nourrir l'Orchestrateur)
        if (!flightBuffer.isEmpty()) {
            ProtocolMessage msg = flightBuffer.poll();
            System.out.println("[Client] 📦 Extracting from buffer: " + msg.getClass().getSimpleName() + " (" + flightBuffer.size() + " left)");
            
            // 1. Sauvegarde pour la comparaison finale (Legacy)
            processReceivedMessage(msg);
            
            // 2. Formatage pour l'orchestrateur
            String typeStr = msg.getClass().getSimpleName().replace("Message", "");
            
            Map<String, String> abstractData = null;
            if (msg instanceof ServerHelloMessage) abstractData = TlsMessageParser.parseServerHello((ServerHelloMessage) msg);
            else if (msg instanceof EncryptedExtensionsMessage) abstractData = TlsMessageParser.parseEncryptedExtensions((EncryptedExtensionsMessage) msg);
            else if (msg instanceof CertificateMessage) abstractData = TlsMessageParser.parseCertificate((CertificateMessage) msg);
            else if (msg instanceof FinishedMessage) abstractData = TlsMessageParser.parseFinished((FinishedMessage) msg);
            else if (msg instanceof AlertMessage) abstractData = TlsMessageParser.parseAlert((AlertMessage) msg);

            // On envoie le message consommé à l'orchestrateur
            TlsEventResult result = new TlsEventResult("RECEIVED", typeStr, abstractData != null ? abstractData : Map.of());
            TlsYamlParser.writeTlsEvent(result, "tls_event.yaml");
            System.out.println("[Client] 💾 Event saved for orchestrator: " + typeStr);
            
        } else {
            System.out.println("[Client] ⏳ No message received (Timeout or empty flight).");
            TlsEventResult result = new TlsEventResult("TIMEOUT", "NONE", Map.of());
            TlsYamlParser.writeTlsEvent(result, "tls_event.yaml");
        }
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
        receiveAndProcessResponses();
    }

    /**
     * Internal helper to handle the reception flight logic.
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
                processReceivedMessage(msg);
            }
        } else {
            System.out.println("[Client] No handshake messages received (check for Alert).");
        }
    }

    /**
     * Legacy entry point for backward compatibility with current TestExaminer.
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
     * * @param msg The received TLS message
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
            abstractData = Map.of("signature", "valid"); 
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

    @Override
    public void startSUT() {
        // Not needed for this implementation
    }

    @Override
    public void executeSUTOperation() {
        // Not needed for this implementation
    }
}
