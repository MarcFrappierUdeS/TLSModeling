package com.tlsclient;

import java.util.ArrayList;
import java.util.List;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

public class TLSMessageLogger {

    // ==========================================
    // 1. LE MODÈLE (Simule l'API ProB)
    // ==========================================
    public static class FakeProB {
        private String internalState = "INIT";

        public String determineNextAction(List<ProtocolMessage> lastReceivedMessages) {
            System.out.println("[ProB] Évaluation de l'état (Actuel: " + internalState + ")");

            switch (internalState) {
                case "INIT":
                    internalState = "WAITING_FOR_SERVER_HELLO";
                    return "ORDER_SEND_CLIENT_HELLO";

                case "WAITING_FOR_SERVER_HELLO":
                    if (lastReceivedMessages != null && !lastReceivedMessages.isEmpty()) {
                        System.out.println("[ProB] Analyse des paramètres reçus en mémoire...");
                        internalState = "FINISHED";
                        return "ORDER_TERMINATE";
                    }
                    return "ORDER_RECEIVE";

                case "FINISHED":
                default:
                    return "ORDER_TERMINATE";
            }
        }
        
        public void configureClientHello(ClientHelloMessage ch) {
             System.out.println("[ProB] Injection des extensions et CipherSuites dans le ClientHello...");
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

        public ReactiveFakeClient(String host, int port) {
            this.host = host;
            this.port = port;
        }

        public void initializeConnections() throws Exception {
            printSection("Initialisation du Client");
            System.out.println("[Client] Configuration et initialisation des couches réseau...");
            
            config = Config.createConfig();
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

            printSection("Début de la boucle de contrôle");

            while (isRunning) {
                String order = probModel.determineNextAction(lastReceivedMessages);
                lastReceivedMessages.clear(); 

                switch (order) {
                    case "ORDER_SEND_CLIENT_HELLO":
                        printSection("Envoi du ClientHello");
                        
                        ClientHelloMessage ch = new ClientHelloMessage(config);
                        probModel.configureClientHello(ch); 
                        
                        /*
                         * =========================================================================
                         * COMMENT MODIFIER LE CLIENT HELLO (API ModifiableVariable)
                         * =========================================================================
                         * Dans TLS-Attacker, pour altérer un message à la volée avant son envoi, 
                         * on n'utilise pas de simples "setters" avec des types primitifs. On utilise
                         * la classe abstraite `Modifiable` pour écraser le comportement normal.
                         * 
                         * Exemples de modifications possibles :
                         * 
                         * 1. Modifier le Session ID (Injection d'octets précis)
                         * ch.setSessionId(Modifiable.explicit(new byte[]{(byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF}));
                         * 
                         * 2. Modifier les Cipher Suites proposées (ex: annoncer une suite factice 0x99 0x99)
                         * ch.setCipherSuites(Modifiable.explicit(new byte[]{(byte) 0x99, (byte) 0x99}));
                         * 
                         * 3. Tronquer ou vider un champ (utile pour tester le parsing d'erreurs du serveur)
                         * ch.setCompressions(Modifiable.empty());
                         * 
                         * 4. Modifier la version du protocole annoncée dans le header du ClientHello (ex: TLS 1.4 factice)
                         * ch.setProtocolVersion(Modifiable.explicit(new byte[]{(byte) 0x03, (byte) 0x05}));
                         * 
                         * NB: Ces modifications sont appliquées par le "Config" et le "State" au moment de
                         * l'exécution du SendAction. Elles écrasent les valeurs par défaut générées.
                         * =========================================================================
                         */

                        SendAction sendAction = new SendAction("client", ch);
                        sendAction.execute(state);
                        
                        state.getWorkflowTrace().addTlsAction(sendAction); 

                        System.out.println("[Client] Action d'envoi exécutée. Messages transmis :");
                        System.out.println(sendAction.toString());
                        if (sendAction.getSentMessages() != null) { //IMPORTANT
                            for (ProtocolMessage msg : sendAction.getSentMessages()) {
                                printSeparator();
                                System.out.println(msg.toString()); 
                            }
                            printSeparator();
                        }
                        break;

                    case "ORDER_RECEIVE":
                        printSection("Réception des réponses Serveur");
                        System.out.println("[Client] Écoute du réseau en cours...");
                        
                        GenericReceiveAction receiveAction = new GenericReceiveAction("client");
                        receiveAction.execute(state);
                        
                        state.getWorkflowTrace().addTlsAction(receiveAction); 
                        
                        if (receiveAction.getReceivedMessages() != null && !receiveAction.getReceivedMessages().isEmpty()) {
                            System.out.println("\n[Client] Action de réception terminée. Messages capturés :");
                            //Important
                            for(ProtocolMessage msg : receiveAction.getReceivedMessages()) {
                                System.out.println(" -> " + msg.toCompactString());
                            }
                            for (ProtocolMessage msg : receiveAction.getReceivedMessages()) {
                                printSeparator();
                                System.out.println(msg.toString());

                                /*
                                
                                // 1. Extraction si c'est un SERVER_HELLO
                                if (msg instanceof ServerHelloMessage) {
                                    ServerHelloMessage sh = (ServerHelloMessage) msg;
                                    System.out.println("   [Paramètres ServerHello isolés]");

                                    // Extraction de la Cipher Suite
                                    if (sh.getSelectedCipherSuite() != null) {
                                        byte[] csBytes = sh.getSelectedCipherSuite().getValue();
                                        CipherSuite cs = CipherSuite.getCipherSuite(csBytes);
                                        System.out.println("     * CipherSuite : " + (cs != null ? cs.name() : "Inconnue"));
                                    }

                                    // Extraction du Random (nécessite une conversion en Hexa pour être lisible)
                                    if (sh.getRandom() != null) {
                                        byte[] randomBytes = sh.getRandom().getValue();
                                        System.out.println("     * Random      : " + ArrayConverter.bytesToHexString(randomBytes));
                                    }

                                    // Extraction du Session ID
                                    if (sh.getSessionId() != null && sh.getSessionId().getValue().length > 0) {
                                        System.out.println("     * Session ID  : " + ArrayConverter.bytesToHexString(sh.getSessionId().getValue()));
                                    } else {
                                        System.out.println("     * Session ID  : (Vide)");
                                    }
                                } 
                                
                                // 2. Extraction si c'est un CERTIFICATE
                                else if (msg instanceof CertificateMessage) {
                                    CertificateMessage certMsg = (CertificateMessage) msg;
                                    System.out.println("   [Paramètres Certificate isolés]");
                                    if (certMsg.getCertificatesListLength() != null) {
                                        System.out.println("     * Taille totale de la chaîne : " + certMsg.getCertificatesListLength().getValue() + " octets");
                                    }
                                } 
                                
                                // 3. Extraction si c'est un FINISHED
                                else if (msg instanceof FinishedMessage) {
                                    FinishedMessage finMsg = (FinishedMessage) msg;
                                    System.out.println("   [Paramètres Finished isolés]");
                                    if (finMsg.getVerifyData() != null) {
                                        System.out.println("     * Verify Data : " + ArrayConverter.bytesToHexString(finMsg.getVerifyData().getValue()));
                                    }
                                } 
                                
                                // 4. Autres messages (ex: EncryptedExtensions, ChangeCipherSpec)
                                else {
                                    System.out.println("   (Aucune extraction spécifique codée pour ce type de message)");
                                }

                                */
                            }
                            printSeparator();
                            
                            lastReceivedMessages.addAll(receiveAction.getReceivedMessages());
                        } else {
                            System.out.println("[Client] Aucun message reçu (Timeout ou erreur réseau).");
                        }
                        break;

                    case "ORDER_TERMINATE":
                        printSection("Terminaison et Bilan");
                        System.out.println("[Client] Ordre de terminaison reçu. Fin de la boucle.\n");
                        // Validation de ta tâche : Extraction du contexte cryptographique
                        
                        /* * =========================================================================
                         * CHEAT SHEET : ÉLÉMENTS EXTRACTIBLES DU STATE (state.get...)
                         * Note : Utiliser ArrayConverter.bytesToHexString(...) pour afficher les byte[]
                         * =========================================================================
                         * * --- SECRETS CRYPTOGRAPHIQUES (via getTlsContext()) ---
                         * getMasterSecret() : correspond à la clé secrète principale dérivée des échanges (TLS 1.2).
                         * getPreMasterSecret() : correspond au secret partagé brut avant la dérivation finale.
                         * getClientRandom() / getServerRandom() : correspond aux nombres aléatoires (nonces) de la session.
                         * getClientHandshakeTrafficSecret() : correspond à la clé (TLS 1.3) chiffrant la fin du handshake.
                         * getApplicationTrafficSecret() : correspond à la clé finale chiffrant les données (HTTP, etc.).
                         * * --- PARAMÈTRES NÉGOCIÉS (via getTlsContext()) ---
                         * getSelectedCipherSuite() : correspond à l'algorithme de chiffrement final (ex: TLS_AES_128_GCM_SHA256).
                         * getSelectedProtocolVersion() : correspond à la version TLS finalement retenue par le serveur.
                         * getClientSessionId() / getServerSessionId() : correspond à l'ID de session (pour la reprise).
                         * getSelectedGroup() : correspond à la courbe elliptique choisie pour l'échange de clés.
                         * getSelectedSignatureAndHashAlgorithm() : correspond à l'algorithme de signature du certificat.
                         * * --- ÉTAT RÉSEAU ET COUCHES (via getTlsContext()) ---
                         * getReadSequenceNumber() / getWriteSequenceNumber() : correspond aux compteurs anti-rejeu.
                         * getMessageDigest() : correspond au composant gardant le Hash cumulé de toute la conversation.
                         * * --- HISTORIQUE ET ARCHIVAGE (Directement sur le State) ---
                         * getWorkflowTrace() : correspond au journal de bord complet. Contient la liste ordonnée de toutes les Actions (Send/Receive) exécutées manuellement.
                         * * --- CERTIFICATS ET IDENTITÉS ---
                         * getServerCertificate() : correspond à la chaîne de certificats finale retenue.
                         * * --- EXTENSIONS ET PROTOCOLES ---
                         * getChoosenAlpnProtocol() : correspond au protocole applicatif négocié (ex: h2 pour HTTP/2).
                         * getNegotiatedExtensionTypes() : correspond aux extensions explicitement validées par le serveur.
                         * * --- CRYPTOGRAPHIE ASYMÉTRIQUE ---
                         * getServerEcPublicKey() / getServerRSAModulus() : correspond aux clés publiques pures extraites. 
                        */
                        
                        System.out.println("--- ÉTAT DU CONTEXTE CRYPTOGRAPHIQUE (STATE) ---");
                        if (state.getTlsContext().getSelectedProtocolVersion() != null) {
                            System.out.println("Version TLS Négociée : " + state.getTlsContext().getSelectedProtocolVersion().name());
                        }
                        if (state.getTlsContext().getSelectedCipherSuite() != null) {
                            System.out.println("Cipher Suite Choisie : " + state.getTlsContext().getSelectedCipherSuite().name());
                        }
                        System.out.println("Nombre d'actions dans la trace : " + state.getWorkflowTrace().getTlsActions().size());
                        
                        isRunning = false;
                        break;
                }
            }
        }

        public void close() {
            if (transportHandler != null) {
                try {
                    transportHandler.closeConnection();
                } catch (Exception e) {
                    // Ignore
                }
            }
        }

        // --- Fonctions d'affichage (Utilitaires) ---

        private static void printSeparator() {
            System.out.println("\n--------------------------------------------------");
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
            // 1. Démarrage automatique du serveur cible
            System.out.println("=== Démarrage de l'environnement ===");
            generateCertificate();
            serverProcess = startOpenSSLServer(4433);
            Thread.sleep(1000); // Laisse 1 seconde à OpenSSL pour s'ouvrir

            // 2. Démarrage de notre client
            client.initializeConnections();
            client.runControlledLoop(prob);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 3. Nettoyage complet
            client.close();
            stopOpenSSLServer(serverProcess);
            cleanupFiles();
            System.out.println("=== Test Terminé ===");
        }
    }

    // --- Fonctions utilitaires pour OpenSSL ---

    private static void generateCertificate() throws Exception {
        System.out.println("Generating self-signed certificate for OpenSSL...");
        Process genKey = Runtime.getRuntime().exec("openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj /CN=localhost");
        genKey.waitFor();
    }

    private static Process startOpenSSLServer(int port) throws Exception {
        System.out.println("Starting OpenSSL server on port " + port + "...");
        return new ProcessBuilder("openssl", "s_server", "-accept", String.valueOf(port), "-key", "key.pem", "-cert", "cert.pem", "-quiet").start();
    }

    private static void stopOpenSSLServer(Process serverProcess) {
        if (serverProcess != null) {
            System.out.println("\nStopping OpenSSL server...");
            serverProcess.destroy();
        }
    }

    private static void cleanupFiles() {
        new java.io.File("key.pem").delete();
        new java.io.File("cert.pem").delete();
    }
}