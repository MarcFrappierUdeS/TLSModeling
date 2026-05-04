package com.tlsclient;

import java.util.ArrayList;
import java.util.List;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

public class ClientServerHelloTests {

    // ==========================================
    // 1. LE MODÈLE (Simule l'API ProB)
    // ==========================================
    public static class FakeProB {
        private String internalState = "INIT";
        private boolean isHrrDetected = false;

        public void reset() {
            internalState = "INIT";
            isHrrDetected = false;
        }

        public void notifyHrrReceived() {
            this.isHrrDetected = true;
        }

        public String determineNextAction(List<ProtocolMessage> lastReceivedMessages) {
            System.out.println("[ProB] Évaluation de l'état (Actuel: " + internalState + ")");

            switch (internalState) {
                case "INIT":
                    internalState = "WAITING_FOR_SERVER_FLIGHT";
                    return "ORDER_SEND_CLIENT_HELLO";

                case "WAITING_FOR_SERVER_FLIGHT":
                    if (lastReceivedMessages != null && !lastReceivedMessages.isEmpty()) {
                        if (isHrrDetected) {
                            System.out.println("[ProB] HelloRetryRequest détecté. Pour ce test de parsing, on s'arrête ici.");
                            internalState = "FINISHED";
                            return "ORDER_TERMINATE";
                        } else {
                            System.out.println("[ProB] Volée du serveur reçue. On termine le handshake...");
                            internalState = "FINISHED";
                            return "ORDER_SEND_FIN";
                        }
                    }
                    return "ORDER_RECEIVE";

                case "FINISHED":
                default:
                    return "ORDER_TERMINATE";
            }
        }
        
        public void configureClientHello(ClientHelloMessage ch, String scenario) {
             System.out.println("[ProB] Injection des paramètres dans le ClientHello...");
             
             if ("TLS_1_3_NORMAL".equals(scenario) || "TLS_1_3_HRR".equals(scenario)) {
                 System.out.println("[ProB] ---> Modification à la volée : Injection d'un SessionID falsifié (DEADBEEF)");
                 ch.setSessionId(Modifiable.explicit(new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF}));
             }
        }
    }

    // ==========================================
    // 2. LE CLIENT (TLS-Attacker réactif)
    // ==========================================
    public static class ReactiveFakeClient {
        private String host;
        private int port;
        private State state;
        private TransportHandler transportHandler;
        private Config config;
        private String currentScenario;

        public ReactiveFakeClient(String host, int port) {
            this.host = host;
            this.port = port;
        }

        public void initializeConnections(String scenario) throws Exception {
            this.currentScenario = scenario;
            printSection("Initialisation du Client - Scénario : " + scenario);
            
            config = Config.createConfig();
            
            if (scenario.equals("TLS_1_3_NORMAL")) {
                config.setHighestProtocolVersion(ProtocolVersion.TLS13);
                config.setSupportedVersions(ProtocolVersion.TLS13);
                config.setAddKeyShareExtension(true);
                config.setDefaultClientSupportedCipherSuites(CipherSuite.TLS_AES_128_GCM_SHA256);
                
            } else if (scenario.equals("TLS_1_3_HRR")) {
                config.setHighestProtocolVersion(ProtocolVersion.TLS13);
                config.setSupportedVersions(ProtocolVersion.TLS13);
                config.setAddKeyShareExtension(true); 
                
                // 1. On annonce les courbes que l'on supporte
                config.setDefaultClientNamedGroups(
                    de.rub.nds.tlsattacker.core.constants.NamedGroup.SECP256R1,
                    de.rub.nds.tlsattacker.core.constants.NamedGroup.SECP384R1
                );
                
                // 2. On passe une liste VIDE pour les clés pré-calculées.
                // TLS-Attacker va générer une extension KeyShare vide.
                // OpenSSL sera obligé de répondre par un HRR pour réclamer une clé.
                config.setDefaultClientKeyShareNamedGroups(new java.util.ArrayList<>());
                
                config.setDefaultClientSupportedCipherSuites(CipherSuite.TLS_AES_128_GCM_SHA256);

            } else if (scenario.equals("TLS_1_2")) {
                config.setHighestProtocolVersion(ProtocolVersion.TLS12);
                config.setSupportedVersions(ProtocolVersion.TLS12);
                config.setAddKeyShareExtension(false);
                // CipherSuite standard pour TLS 1.2
                config.setDefaultClientSupportedCipherSuites(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
            }

            config.setAddSupportedVersionsExtension(true);
            config.setAddEllipticCurveExtension(true); 
            
            OutboundConnection connection = new OutboundConnection(host, port);
            connection.setAlias("client");
            connection.setTransportHandlerType(TransportHandlerType.TCP);
            connection.setConnectionTimeout(5000);
            config.setDefaultClientConnection(connection);

            WorkflowTrace trace = new WorkflowTrace();
            state = new State(config, trace); 
            
            state.getContext().prepareWithLayers(StackConfiguration.TLS);

            transportHandler = TransportHandlerFactory.createTransportHandler(state.getContext().getConnection());
            state.getContext().setTransportHandler(transportHandler);
            transportHandler.initialize();
        }

        public void runControlledLoop(FakeProB probModel) throws Exception {
            boolean isRunning = true;
            List<ProtocolMessage> lastReceivedMessages = new ArrayList<>();

            printSection("Début de la boucle de contrôle (" + currentScenario + ")");

            while (isRunning) {
                String order = probModel.determineNextAction(lastReceivedMessages);
                lastReceivedMessages.clear(); 

                switch (order) {
                    case "ORDER_SEND_CLIENT_HELLO":
                        printSection("Envoi du ClientHello");
                        
                        ClientHelloMessage ch = new ClientHelloMessage(config);
                        probModel.configureClientHello(ch, currentScenario); 
                        
                        SendAction sendAction = new SendAction("client", ch);
                        sendAction.execute(state);
                        state.getWorkflowTrace().addTlsAction(sendAction); 

                        System.out.println("[Client] Action d'envoi exécutée.");
                        break;

                    case "ORDER_SEND_FIN":
                        printSection("Envoi du Finished");
                        
                        FinishedMessage fin = new FinishedMessage();
                        ChangeCipherSpecMessage ccs = new ChangeCipherSpecMessage();
                        
                        SendAction sendFinAction = new SendAction("client", ccs, fin);
                        sendFinAction.execute(state);
                        state.getWorkflowTrace().addTlsAction(sendFinAction);
                        
                        System.out.println("[Client] Handshake terminé côté client.");
                        break;

                    case "ORDER_RECEIVE":
                        printSection("Réception des réponses Serveur");
                        
                        GenericReceiveAction receiveAction = new GenericReceiveAction("client");
                        receiveAction.execute(state);
                        state.getWorkflowTrace().addTlsAction(receiveAction); 
                        
                        if (receiveAction.getReceivedMessages() != null && !receiveAction.getReceivedMessages().isEmpty()) {
                            System.out.println("[Client] Action de réception terminée. Messages capturés :");
                            
                            for(ProtocolMessage msg : receiveAction.getReceivedMessages()) {
                                System.out.println(" -> " + msg.toCompactString());
                                
                                if (msg instanceof ServerHelloMessage) {
                                    ServerHelloMessage sh = (ServerHelloMessage) msg;
                                    
                                    System.out.println("\n--- [Analyse détaillée du ServerHello] ---");
                                    System.out.println("Version TLS lue  : " + ArrayConverter.bytesToHexString(sh.getProtocolVersion().getValue()));
                                    
                                    byte[] randomValue = sh.getRandom().getValue();
                                    System.out.println("Valeur du Random : " + ArrayConverter.bytesToHexString(randomValue));
                                    
                                    // La constante magique du HelloRetryRequest selon le RFC 8446
                                    String hrrMagic = "CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C";
                                    hrrMagic = hrrMagic.replaceAll("\\s+", "").toUpperCase();

                                    String currentRandomStr = ArrayConverter.bytesToHexString(randomValue);
                                    currentRandomStr = currentRandomStr.replaceAll("\\s+", "").toUpperCase();

                                    if (currentRandomStr.equals(hrrMagic)) {
                                        System.out.println("=> TYPE DETECTÉ : HelloRetryRequest (HRR) !");
                                        probModel.notifyHrrReceived(); 
                                    } else {
                                        System.out.println("=> TYPE DETECTÉ : ServerHello standard.");
                                    }
                                    System.out.println("------------------------------------------\n");
                                }
                            }
                            lastReceivedMessages.addAll(receiveAction.getReceivedMessages());
                        } else {
                            System.out.println("[Client] Aucun message reçu (Timeout).");
                        }
                        break;

                    case "ORDER_TERMINATE":
                        printSection("Terminaison et Bilan");
                        if (state.getTlsContext().getSelectedProtocolVersion() != null) {
                            System.out.println("Version TLS Négociée : " + state.getTlsContext().getSelectedProtocolVersion().name());
                        }
                        if (state.getTlsContext().getSelectedCipherSuite() != null) {
                            System.out.println("Cipher Suite Choisie : " + state.getTlsContext().getSelectedCipherSuite().name());
                        }
                        isRunning = false;
                        break;
                }
            }
        }

        public void close() {
            if (transportHandler != null) {
                try {
                    transportHandler.closeConnection();
                } catch (Exception e) { }
            }
        }

        private static void printSection(String title) {
            System.out.println("\n==================================================");
            System.out.println("  " + title.toUpperCase());
            System.out.println("==================================================");
        }
    }

    // ==========================================
    // MAIN 
    // ==========================================
    public static void main(String[] args) {
        FakeProB prob = new FakeProB();
        ReactiveFakeClient client = new ReactiveFakeClient("127.0.0.1", 4433);
        Process serverProcess = null;

        try {
            System.out.println("=== Démarrage de l'environnement ===");
            generateCertificate();
            serverProcess = startOpenSSLServer(4433);
            Thread.sleep(1000); 

            // SCÉNARIO 1 : TLS 1.3 Normal
            prob.reset();
            client.initializeConnections("TLS_1_3_NORMAL");
            client.runControlledLoop(prob);
            client.close();
            
            System.out.println("\n\n--------------------------------------\n\n");

            // SCÉNARIO 2 : TLS 1.3 avec HelloRetryRequest
            prob.reset();
            client.initializeConnections("TLS_1_3_HRR");
            client.runControlledLoop(prob);
            client.close();

            System.out.println("\n\n--------------------------------------\n\n");
            
            // SCÉNARIO 3 : TLS 1.2
            prob.reset();
            client.initializeConnections("TLS_1_2");
            client.runControlledLoop(prob);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            client.close();
            stopOpenSSLServer(serverProcess);
            cleanupFiles();
            System.out.println("=== Tous les tests sont terminés ===");
        }
    }

    private static void generateCertificate() throws Exception {
        Process genKey = Runtime.getRuntime().exec("openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj /CN=localhost");
        genKey.waitFor();
    }

    private static Process startOpenSSLServer(int port) throws Exception {
        return new ProcessBuilder("openssl", "s_server", "-accept", String.valueOf(port), "-key", "key.pem", "-cert", "cert.pem", "-quiet").start();
    }

    private static void stopOpenSSLServer(Process serverProcess) {
        if (serverProcess != null) { serverProcess.destroy(); }
    }

    private static void cleanupFiles() {
        new java.io.File("key.pem").delete();
        new java.io.File("cert.pem").delete();
    }
}