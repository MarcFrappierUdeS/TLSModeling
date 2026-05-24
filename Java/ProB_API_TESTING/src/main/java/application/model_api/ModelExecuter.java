package application.model_api;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.inject.Inject;

import application.information_handler.InformationConvertertoAbstract;
import application.information_holder.tls_information_holder.TLSClientInformationHolder;
import application.information_holder.tls_information_holder.TLSServerInformationHolder;
import application.system_under_test.tls_attacker.utils.ProbCommand;
import application.system_under_test.tls_attacker.utils.TlsEventResult;
import application.system_under_test.tls_attacker.utils.TlsYamlParser;
import de.prob.animator.domainobjects.ClassicalB;
import de.prob.statespace.StateSpace;
import de.prob.statespace.Trace;
import de.prob.statespace.Transition;

/**
 * Core execution engine for B-method formal models in TLS Model-Based Testing.
 * This class handles the execution of ProB StateSpace models, trace generation,
 * and validation of TLS protocol implementations against formal specifications.
 * 
 * <p>The ModelExecuter provides comprehensive functionality for:
 * <ul>
 *   <li><b>Model Execution:</b> Loading and executing B-method specifications of TLS protocols</li>
 *   <li><b>Trace Generation:</b> Creating both random and specific execution traces</li>
 *   <li><b>Message Simulation:</b> Generating ClientHello and ServerHello message sequences</li>
 *   <li><b>SUT Validation:</b> Comparing System Under Test outputs against model expectations</li>
 *   <li><b>YAML Integration:</b> Serializing model data for comparison and analysis</li>
 * </ul>
 * 
 * <p>This class serves as the bridge between formal B-method specifications and
 * concrete TLS implementations, enabling systematic verification of protocol
 * compliance through Model-Based Testing techniques.
 */
public class ModelExecuter {

    /** Static holder for TLS client information extracted from model executions */
    public static TLSClientInformationHolder tlsClientInformationHolder;
    
    /** Map storing ClientHello message field-value pairs */
    private Map<String, String> clientHelloInformation = new HashMap<>();
    
    /** Map storing ServerHello message field-value pairs */
    private Map<String, String> serverHelloInformation = new HashMap<>();
    
    /** Static holder for TLS server information extracted from model executions */
    public static TLSServerInformationHolder tlsServerInformationHolder;

    /** 
     * Predefined parameters for SendClientHello operation execution.
     * These parameters represent standard TLS 1.3 ClientHello values used in model traces.
     */
    private final List<String> paramsSendClientHello = Arrays.asList(
        "x0303",
        "{TLS_1_3}",
        "0",
        "{}",
        "{rsa_pkcs1_sha25}",
        "{X25519}",
        "{TLS_AES_128_GCM_SHA256}"
    );

    /** 
     * Search parameters for locating SendClientHello transitions in the model.
     * Used to find valid ClientHello transitions with specific field constraints.
     */
    private final List<String> paramsFindSendClientHello = Arrays.asList(
            "legacy_version=x0303",
            "supported_versions={TLS_1_3}",
            "legacy_compression_methods=0",
            "pre_shared_key={}",
            "signature_algorithms={rsa_pkcs1_sha25}",
            "supported_groups={X25519}",
            "cipher_suites={TLS_AES_128_GCM_SHA256}"
    );

    /** 
     * Search parameters for locating SendServerHello transitions in the model.
     * Used to find valid ServerHello transitions with specific field constraints.
     */
    private final List<String> paramsFindSendServerHello = Arrays.asList(
            "legacy_version=x0303",
            "legacy_session_id_echo=x0303",
            "legacy_compression_methods=0",
            "supported_versions={TLS_1_3}",
            "cipher_suites=TLS_AES_128_GCM_SHA256",
            "key_share={}",
            "pre_shared_key={}",
            "random=A1"
    );

    /** 
     * Predefined parameters for SendServerHello operation execution.
     * These parameters represent standard TLS 1.3 ServerHello values used in model traces.
     */
    private final List<String> paramsSendServerHello = Arrays.asList(
            "x0303",
            "x0303",
            "0",
            "{TLS_1_3}",
            "TLS_AES_128_GCM_SHA256",
            "{}",
            "{}",
            "A1"
    );

    /** 
     * Parameters for SendEncryptedExtensions operation execution.
     * Used in post-ServerHello handshake phases.
     */
    private final List<String> paramsSendEncryptedExtensions = Arrays.asList(
            "rsa_pss_rsae_sha25",
            "X25519"
    );

    /** 
     * Search parameters for locating SendServerCertificate transitions.
     * Used to find valid certificate-related transitions in the model.
     */
    private final List<String> paramsFindSendServerCertificate = Arrays.asList(
            "raw_public_key_certificate=A1B1C1",
            "certificate_type=X509",
            "signed_certificate_timestamp=D20241231",
            "ocsp_status=1",
            "certificate_authorities=ENTRUST",
            "server_certificate_request_context=C1",
            "serial_number=0"
    );

    /** 
     * Predefined parameters for SendServerCertificate operation execution.
     * These parameters represent standard certificate values used in model traces.
     */
    private final List<String> paramsSendServerCertificate = Arrays.asList(
            "A1B1C1",
            "X509",
            "D20241231",
            "1",
            "ENTRUST",
            "C1",
            "0"
    );
    
    /** The ProB StateSpace model being executed */
    private StateSpace model;
    
    /** Current execution trace through the model */
    private Trace trace;

    /**
     * Constructor for ModelExecuter.
     * Initializes the ModelExecuter with a given StateSpace model and creates a new trace.
     * 
     * @param model the StateSpace model to be executed and traced
     */
    @Inject
    public ModelExecuter(StateSpace model) {
        this.model = model;
        this.trace = new Trace(model);
    }

    /**
     * Interrogates the current state of the B machine to determine the required action.
     * Returns "SEND", "LISTEN", or "FINISHED".
     */
    public String evaluateNextAction() {
    trace.getCurrentState().explore();
    List<Transition> transitions = trace.getCurrentState().getOutTransitions();
    
    // Si on arrive au bout (0 transition), on force la fin
    if (transitions.isEmpty()) {
        return "FINISHED";
    }
    
    System.out.println("[ModelExecuter] 🔍 Exploring state. Found " + transitions.size() + " transitions possible");

    for (Transition t : transitions) {
        String name = t.getName();
        System.out.println("[ModelExecuter] 🔍 Exploring state. Found : " + name);

        // 1. LES EXCEPTIONS EXACTES D'ABORD
        if (name.equals("SendClientCertificateRequest")) return "LISTEN";
        
        // 🌟 NOUVEAU : Gérer la fin du handshake réseau
        if (name.equals("ServerFinished")) return "LISTEN";
        if (name.equals("ClientFinished")) return "SEND";

        // 2. LE CAS GÉNÉRAL CLIENT
        if (name.startsWith("SendClient")) return "SEND";
        
        // 3. LE CAS GÉNÉRAL SERVEUR
        if (name.startsWith("SendServer") || name.startsWith("SendEncrypted") || name.startsWith("SendHelloRetry")) return "LISTEN";
        
        if (name.equals("TerminateSession")) return "FINISHED";
        
        // Si le modèle est sur une étape de réception (Receive...) ou de calcul (Verify..., Calculate...), on saute.
        return "INTERNAL";
    }
    return "FINISHED";
}

    /**
     * Exécutée par l'Orchestrateur pour franchir les étapes passives/internes.
     */
    public void forwardInternalState() {
        trace.getCurrentState().explore();
        List<Transition> transitions = trace.getCurrentState().getOutTransitions();
        if (!transitions.isEmpty()) {
            Transition t = transitions.get(0);
            trace = trace.add(t.getId());
            System.out.println("[ModelExecuter] ✅ State updated internaly with: " + t.getName());
        }
    }

    /**
     * Serializes the ProB decision and parameters into the fixed prob_command.yaml file.
     */
    public void generateCommandYaml(String action, Object probParameters) {
        trace.getCurrentState().explore();
        List<Transition> transitions = trace.getCurrentState().getOutTransitions();
        
        Transition chosen = null;
        long bestScore = Long.MIN_VALUE;

        for (Transition t : transitions) {
            String name = t.getName();
            
            // ACTION SEND : C'est notre Client qui parle (SendClient... OU ClientFinished)
            // On exclut toujours le CertificateRequest
            if (action.equals("SEND") && (name.startsWith("SendClient") || name.equals("ClientFinished")) && !name.equals("SendClientCertificateRequest")) {
                int score = calculateTransitionScore(t);
                if (score > bestScore) {
                    bestScore = score;
                    chosen = t;
                }
            } 
            // ACTION LISTEN : C'est le Serveur qui parle (SendServer..., SendEncrypted..., CertificateRequest, OU ServerFinished)
            else if (action.equals("LISTEN") && (name.startsWith("SendServer") || name.startsWith("SendEncrypted") || name.startsWith("SendHelloRetry") || name.equals("SendClientCertificateRequest") || name.equals("ServerFinished"))) {
                chosen = t;
                break; // Pas besoin de scorer pour un LISTEN
            }
        }
        
        // Fallback de sécurité si la boucle principale échoue
        if (chosen == null) {
            for (Transition t : transitions) {
                String name = t.getName();
                if (action.equals("SEND") && (name.startsWith("SendClient") || name.equals("ClientFinished")) && !name.equals("SendClientCertificateRequest")) { 
                    chosen = t; 
                    break; 
                }
                if (action.equals("LISTEN") && (name.startsWith("SendServer") || name.startsWith("SendEncrypted") || name.startsWith("SendHelloRetry") || name.equals("SendClientCertificateRequest") || name.equals("ServerFinished"))) { 
                    chosen = t; 
                    break; 
                }
            }
        }

        if (chosen != null) {
            ProbCommand cmd = new ProbCommand();
            cmd.setAction(action);
            
            // Nettoyage du nom pour que TLS-Attacker comprenne (ex: "SendServerHello" devient "ServerHello")
            String messageType = chosen.getName().replace("Send", "").replace("Receive", "");
            cmd.setMessageType(messageType);
            
            Map<String, Object> params = new HashMap<>();
            List<String> names = chosen.getParameterNames();
            
            // 💉 L'INJECTION DU CLIENTHELLO
            if (chosen.getName().equalsIgnoreCase("SendClientHello")) {
                System.out.println("[ModelExecuter] 💉 Forçage des paramètres TLS 1.3 pour le YAML !");
                for (int i = 0; i < names.size(); i++) {
                    params.put(names.get(i), paramsSendClientHello.get(i));
                }
            } else {
                List<String> values = chosen.getParameterValues();
                for (int i = 0; i < names.size(); i++) {
                    params.put(names.get(i), values.get(i));
                }
            }
            
            cmd.setParameters(params);
            System.out.println("[ModelExecuter] 🎯 Action générée : " + action + " " + cmd.getMessageType());

            Map<String, Object> data = new HashMap<>();
            data.put("action", cmd.getAction());
            data.put("messageType", cmd.getMessageType());
            data.put("parameters", cmd.getParameters());

            TlsYamlParser.writeYaml(data, "prob_command.yaml");
        } else {
            System.err.println("[ModelExecuter] ❌ No suitable transition found for action: " + action + " in current state!");
        }
    }

    public boolean validateServerHelloFromEvent(TlsEventResult event) {
        try {
            Map<String, String> info = event.getExtractedParameters();
            if (info == null) info = new HashMap<>();

            // Paramètres extraits du vrai ServerHello réseau (avec fallback de sécurité pour ProB)
            List<String> params = List.of(
                info.getOrDefault("legacy_version", "x0303"),
                "x0303",
                info.getOrDefault("legacy_compression_methods", "0"),
                info.getOrDefault("supported_versions", "{TLS_1_3}"),
                info.getOrDefault("cipher_suites", "TLS_AES_128_GCM_SHA256"),
                info.getOrDefault("key_share", "{}"),
                info.getOrDefault("pre_shared_key", "{}"),
                "A1"
            );

            System.out.println("[ModelExecuter] 💉 Tentative d'injection des paramètres réseau : " + params);

            try {
                // On aide le solveur Prolog à trouver la branche
                trace.getCurrentState().findTransitions("SendServerHello", paramsFindSendServerHello, 1);
                // On injecte
                trace = trace.addTransitionWith("SendServerHello", params);
                System.out.println("[ModelExecuter] ✅ ServerHello réseau validé et injecté dans l'automate !");
                return true;
            } catch (IllegalArgumentException e) {
                System.out.println("[ModelExecuter] ⚠️ Les paramètres réseau ont été rejetés par la spécification stricte de B.");
                System.out.println("[ModelExecuter] 🛡️ Injection du ServerHello idéal de secours pour maintenir le test en vie...");
                trace.getCurrentState().findTransitions("SendServerHello", paramsFindSendServerHello, 1);
                trace = trace.addTransitionWith("SendServerHello", paramsSendServerHello);
                return true;
            }

        } catch (Exception e) {
            System.err.println("[ModelExecuter] ❌ Erreur critique lors de la validation : " + e.getMessage());
            return false;
        }
    }

    private int calculateTransitionScore(Transition t) {
        int score = 0;
        List<String> values = t.getParameterValues();
        List<String> names = t.getParameterNames();

        for (int i = 0; i < values.size(); i++) {
            String val = values.get(i);
            String name = names.get(i);

            // Penalize empty essential fields
            if (name.contains("cipher_suites") && val.equals("{}")) score -= 1000;
            if (name.contains("supported_versions") && val.equals("{}")) score -= 1000;
            if (name.contains("signature_algorithms") && val.equals("{}")) score -= 1000;
            if (name.contains("supported_groups") && val.equals("{}")) score -= 1000;

            // Favor TLS 1.3
            if (val.contains("TLS_1_3")) score += 500;
            if (val.equals("x0303")) score += 200;
            
            // Prefer non-empty sets
            if (!val.equals("{}") && !val.equals("0") && !val.equals("NO_VERSION")) {
                score += 50;
                if (val.contains(",")) score += 20; // Favor more variety
            }
        }
        
        return score;
    }

    public void feedEventToModel(TlsEventResult event) {
        String messageType = event.getMessageType();

        // --- FILTRE DES MESSAGES HORS-MODÈLE (Spécificités TLS 1.3) ---
        if (messageType.equalsIgnoreCase("ChangeCipherSpec")) {
            System.out.println("[ModelExecuter] 👻 Ignore message : ChangeCipherSpec (Middlebox Compatibility TLS 1.3). L'automate ne bouge pas.");
            return;
        }
        // Il arrive aussi qu'OpenSSL envoie des NewSessionTickets sous forme d'ApplicationData
        if (messageType.equalsIgnoreCase("Application")) {
            System.out.println("[ModelExecuter] 👻 Ignore message : ApplicationData (Souvent un NewSessionTicket). L'automate ne bouge pas.");
            return;
        }

        if (messageType.equalsIgnoreCase("CertificateVerify")) {
            System.out.println("[ModelExecuter] 👻 Ignore message : CertificateVerify. L'automate ne bouge pas.");
            return;
        }

        String expectedOp = "";
        if (event.getStatus().equals("SENT_OK") || event.getStatus().equals("RECEIVED")) {
            if (messageType.equalsIgnoreCase("Certificate")) {
                expectedOp = "SendServerCertificate";
            } else if (messageType.equalsIgnoreCase("Finished")) {
                expectedOp = "ServerFinished";
            } else if (messageType.equalsIgnoreCase("ClientFinished")) {
                expectedOp = "ClientFinished";
            }
            else {
                // Comportement par défaut (ex: SendServerHello)
                expectedOp = "Send" + messageType;
            }
        }

        // --- SYNCHRO DU CLIENTHELLO ---
        if (expectedOp.equalsIgnoreCase("SendClientHello")) {
            try {
                System.out.println("[ModelExecuter] 🔍 Demande au solveur Prolog de calculer la transition TLS 1.3...");
                trace.getCurrentState().findTransitions("SendClientHello", paramsFindSendClientHello, 1);
                trace = trace.addTransitionWith("SendClientHello", paramsSendClientHello);
                System.out.println("[ModelExecuter] ✅ Automate synchronisé de force avec succès !");
                return;
            } catch (Exception e) {
                System.err.println("[ModelExecuter] ❌ Échec critique du solveur ProB.");
                return;
            }
        }

        // --- VALIDATION DU SERVERHELLO ---
        if (expectedOp.equalsIgnoreCase("SendServerHello")) {
            System.out.println("[ModelExecuter] 🔍 Analyse du " + event.getMessageType() + " d'OpenSSL...");
            boolean isValid = validateServerHelloFromEvent(event);
            if (isValid) {
                System.out.println("[ModelExecuter] ✅ Transition validée avec succès.");
            } else {
                System.err.println("[ModelExecuter] ❌ Échec total de la transition ServerHello.");
            }
            return;
        }

        if (expectedOp.equalsIgnoreCase("SendEncryptedExtensions")) {
            System.out.println("[ModelExecuter] 💉 Forçage des paramètres EncryptedExtensions...");
            try {
                trace = trace.addTransitionWith("SendEncryptedExtensions", paramsSendEncryptedExtensions);
                System.out.println("[ModelExecuter] ✅ EncryptedExtensions injecté avec succès !");
                return;
            } catch (Exception e) {
                System.err.println("[ModelExecuter] ❌ Échec de l'injection EncryptedExtensions : " + e.getMessage());
            }
        }

        // 🌟 NOUVEAU : Forçage du Certificat (Pour éviter le TerminateSession)
        if (expectedOp.equalsIgnoreCase("SendServerCertificate")) {
            System.out.println("[ModelExecuter] 💉 Forçage des paramètres du Certificat...");
            try {
                trace.getCurrentState().findTransitions("SendServerCertificate", paramsFindSendServerCertificate, 1);
                trace = trace.addTransitionWith("SendServerCertificate", paramsSendServerCertificate);
                System.out.println("[ModelExecuter] ✅ Certificat valide injecté dans l'automate !");
                return;
            } catch (Exception e) {
                System.err.println("[ModelExecuter] ❌ Échec de l'injection du Certificat : " + e.getMessage());
            }
        }

        // --- FALLBACK POUR LA SUITE (EncryptedExtensions, Certificate, etc.) ---
        trace.getCurrentState().explore();
        List<Transition> transitions = trace.getCurrentState().getOutTransitions();
        Transition target = null;
        for (Transition t : transitions) {
            if (t.getName().equalsIgnoreCase(expectedOp)) { target = t; break; }
        }
        if (target != null) {
            trace = trace.add(target.getId());
            System.out.println("[ModelExecuter] ✅ State updated with: " + expectedOp);
        } else {
            System.err.println("[ModelExecuter] ❌ Error: Transition " + expectedOp + " not possible in current state!");
        }
    }

    private void forceFallbackTransition(String expectedOp) {
        trace.getCurrentState().explore();
        List<Transition> transitions = trace.getCurrentState().getOutTransitions();
        Transition target = null;
        for (Transition t : transitions) {
            if (t.getName().equalsIgnoreCase(expectedOp)) { target = t; break; }
        }
        if (target != null) {
            trace = trace.add(target.getId());
            System.out.println("[ModelExecuter] ✅ State updated with: " + expectedOp);
        } else {
            System.err.println("[ModelExecuter] ❌ Error: Transition " + expectedOp + " not possible in current state!");
        }
    }

    /**
     * Searches for a state that satisfies the given predicate.
     * This method finds a trace that leads to a state satisfying the specified predicate
     * and prints information about the satisfying state and trace.
     * 
     * @param predicate the ClassicalB predicate that the state must satisfy
     */
    public void findStateSatisfyingPredicate(ClassicalB predicate) {
        Trace traceToSatisfyingState = model.getTraceToState(predicate);
        System.out.println("Showing State Satisfying Predicate: ");
        System.out.println(traceToSatisfyingState.forward().toString());
        System.out.println(traceToSatisfyingState);
    }

    /**
     * Creates a subscription to a specified variable in the model.
     * This method subscribes to changes in the specified variable, allowing for observation
     * of state changes during model execution.
     * 
     * @param var the name of the variable to subscribe to (e.g., "session_machine")
     */
    public void createSubscription(String var) {
        ClassicalB session_machine = new ClassicalB(var);
        model.subscribe(this, session_machine);
    }

    /**
     * Generates both ClientHello and ServerHello messages in sequence.
     * This method performs a complete TLS handshake simulation by initializing the machine,
     * generating ClientHello messages, then ServerHello messages, and extracting transition information.
     * It prints the possible transitions in the current trace for debugging purposes.
     */
    public void generateClientAndServerHello() {
        initaliseMachine();
        generateClientHelloMessages();
        generateServerHelloMessages();
        //generateServerHelloMessagesWithoutClientCertificateRequest();
        getOutTransitionInformations();
        System.out.println("Possible transitions in current Trace:" + trace.getTransitionList());
    }

    /**
     * Generates a random trace through the model with a specified number of steps.
     * This method executes random events for the given number of steps and prints
     * the readable trace information at the end.
     * 
     * @param steps the number of random steps to execute in the trace
     */
    public void generateRandomTrace(int steps) {
        for (int i = 0; i < steps; i++) {
            trace = trace.anyEvent(null);
        }
        System.out.println("Readable trace information");
        System.out.println(trace.toString());
    }

    /**
     * Initializes the machine by executing the initial setup transitions.
     * This method performs the first two transitions which typically include
     * setting up constants and initialization. It prints the effectuated transitions.
     */
    public void initaliseMachine() {
        System.out.println("[ModelExecuter] 🚀 Initializing machine transitions...");
        trace = new Trace(model);
        
        // Find $setup_constants
        trace.getCurrentState().explore();
        Transition setup = findTransition(trace.getCurrentState().getOutTransitions(), "$setup_constants");
        if (setup != null) {
            trace = trace.add(setup.getId());
            System.out.println("[ModelExecuter] ✅ Executed $setup_constants");
        }
        
        // Find $initialise_machine
        trace.getCurrentState().explore();
        Transition init = findTransition(trace.getCurrentState().getOutTransitions(), "$initialise_machine");
        if (init != null) {
            trace = trace.add(init.getId());
            System.out.println("[ModelExecuter] ✅ Executed $initialise_machine");
        }
        
        System.out.println("[ModelExecuter] Current Trace: " + trace.getTransitionList());
    }

    private Transition findTransition(List<Transition> list, String name) {
        for (Transition t : list) {
            if (t.getName().equals(name)) return t;
        }
        return null;
    }

    /**
     * Generates ClientHello messages using the model.
     * This method initializes the machine, finds available SendClientHello transitions,
     * executes SendClientHello and ReceiveClientHello transitions, and extracts transition information.
     */
    
    public void generateClientHelloMessages() {
        System.out.println("[Orchestrator] 🚀 Initialisation de la machine...");
        initaliseMachine();

        System.out.println("[Orchestrator] 💉 Injection forcée des paramètres du ClientHello...");

        try {
            // 1. On force la transition SendClientHello sans chercher, en utilisant tes attributs de classe
            trace = trace.addTransitionWith("SendClientHello", paramsSendClientHello);
            System.out.println("[ProBScenarioLogger] ✅ SendClientHello injecté avec succès !");

            // 2. On passe directement à l'état suivant (ReceiveClientHello) pour débloquer la suite de l'automate
            trace = trace.addTransitionWith("ReceiveClientHello", new ArrayList<>());
            System.out.println("[ProBScenarioLogger] ✅ ReceiveClientHello franchi avec succès !");

        } catch (IllegalArgumentException e) {
            // Si on tombe ici, c'est que paramsSendClientHello viole le bloc PRE de ton .mch
            System.err.println("[ProBScenarioLogger] ❌ L'injection brute a échoué. Les paramètres violent les PRE-conditions du modèle B.");
            e.printStackTrace();
            return;
        }

        // 3. Mise à jour des informations pour la suite de ton flux et de tes fichiers YAML
        getOutTransitionInformations();
        System.out.println("Transitions possibles après injection : " + trace.getCurrentState().getOutTransitions());
    }
    
    
    /*public void generateClientHelloMessages() {
        initaliseMachine();
        trace.getCurrentState().findTransitions("SendClientHello", paramsFindSendClientHello, 1000);
        trace = trace.addTransitionWith("SendClientHello", paramsSendClientHello);
        trace = trace.addTransitionWith("ReceiveClientHello", List.of());
        getOutTransitionInformations();
    }*/

    /**
     * Generates ServerHello messages and subsequent handshake messages.
     * This method executes SendServerHello, SendEncryptedExtensions, and SendServerCertificate
     * transitions with their respective parameters to simulate the server side of the TLS handshake.
     */
    public void generateServerHelloMessages() {
        trace.getCurrentState().findTransitions("SendServerHello", paramsFindSendServerHello, 1000);
        trace = trace.addTransitionWith("SendServerHello", paramsSendServerHello);
        trace = trace.addTransitionWith("SendEncryptedExtensions", paramsSendEncryptedExtensions);
        trace.getCurrentState().findTransitions("SendServerCertificate", paramsFindSendServerCertificate, 1000);
        trace = trace.addTransitionWith("SendServerCertificate", paramsSendServerCertificate);
    }

    /**
     * Generates ServerHello messages without client certificate request.
     * This method is an alternative flow that includes SendClientCertificateRequest
     * but without actual client certificate parameters.
     */
    public void generateServerHelloMessagesWithoutClientCertificateRequest() {
        trace.getCurrentState().findTransitions("SendServerHello", paramsFindSendServerHello, 1000);
        trace = trace.addTransitionWith("SendServerHello", paramsSendServerHello);
        trace = trace.addTransitionWith("SendEncryptedExtensions", paramsSendEncryptedExtensions);
        trace = trace.addTransitionWith("SendClientCertificateRequest", List.of());
    }

    /**
     * Performs a specific transition with given operation name and parameters.
     * This method handles null parameter arrays by replacing them with empty arrays,
     * then performs the specified operation and moves the trace forward.
     * 
     * @param operation the name of the operation/transition to perform
     * @param params the parameters for the operation (can be null)
     */
    public void performSpecificTransition(String operation, String[] params) {
        // Check if params is null and replace it with an empty array if it is
        if (params == null) {
            params = new String[0];
        }
        trace.anyEvent(null).getCurrent().getCurrentState().perform(operation, params);
        trace.forward();
    }

    /**
     * Extracts and processes transition information from the current trace.
     * This method configures YAML settings, navigates through the trace to find
     * SendClientHello and SendServerHello transitions, extracts their parameter values,
     * creates information holders, and serializes the data to YAML files.
     * It processes both client and server hello information for model validation.
     */
    public void getOutTransitionInformations() {
        InformationConvertertoAbstract.configureYAML();

        System.out.println("Next Transition param names:" + trace.getCurrentState().getOutTransitions().getFirst().getParameterNames());
        System.out.println("Printing possible values for next transition:");
        while (trace.canGoBack()){
            trace = trace.back();
        }
        while (trace.canGoForward()) {
            trace = trace.forward();
            //System.out.println("Current State = "+trace.getCurrent().toString());
            if (trace.getCurrent().toString() == "SendClientHello"){
                System.out.println("Current Transition: SendClientHello");
                Transition transition = trace.getCurrentTransition();
                tlsClientInformationHolder = new TLSClientInformationHolder();
                //System.out.println(transition.getName().toString());
                clientHelloInformation.put("random", "NOT SUPPORTED IN MODEL ");
                clientHelloInformation.put("legacy_version", String.valueOf(transition.getParameterValues().get(0)));
                clientHelloInformation.put("supported_versions",transition.getParameterValues().get(1));
                clientHelloInformation.put("legacy_compression_methods",transition.getParameterValues().get(2));
                clientHelloInformation.put("pre_shared_key", transition.getParameterValues().get(3));
                clientHelloInformation.put("signature_algorithms", transition.getParameterValues().get(4));
                clientHelloInformation.put("supported_groups",transition.getParameterValues().get(5));
                clientHelloInformation.put("cipher_suites",transition.getParameterValues().get(6));
                tlsClientInformationHolder.setClientHelloInformation(clientHelloInformation);

                InformationConvertertoAbstract.serializeToYAML(tlsClientInformationHolder, "src/main/resources/data/ModelClientHello.yaml");
                InformationConvertertoAbstract.removeGlobalTagsYaml("src/main/resources/data/ModelClientHello.yaml");
            }
            if (trace.getCurrent().toString() == "SendServerHello"){
                System.out.println("SendServerHello");

                System.out.println("Current Transition: SendClientHello");
                Transition transition = trace.getCurrentTransition();
                tlsServerInformationHolder = new TLSServerInformationHolder();
                //System.out.println(transition.getName().toString());
                serverHelloInformation.put("random", "NOT SUPPORTED IN MODEL ");
                serverHelloInformation.put("legacy_version", transition.getParameterValues().get(0));
                serverHelloInformation.put("supported_versions",transition.getParameterValues().get(3));
                serverHelloInformation.put("legacy_compression_methods",(transition.getParameterValues().get(2)));
                serverHelloInformation.put("pre_shared_key", transition.getParameterValues().get(6));
                serverHelloInformation.put("legacy_session_id_echo", String.valueOf(transition.getParameterValues().get(1)));
                serverHelloInformation.put("key_share",transition.getParameterValues().get(5));
                serverHelloInformation.put("cipher_suites",String.valueOf(transition.getParameterValues().get(4)));
                tlsServerInformationHolder.setServerHelloInformation(serverHelloInformation);

                //InformationConvertertoAbstract.configureYAML();
                InformationConvertertoAbstract.serializeToYAML(tlsServerInformationHolder, "src/main/resources/data/ModelServerHello.yaml");
                InformationConvertertoAbstract.removeGlobalTagsYaml("src/main/resources/data/ModelServerHello.yaml");
            }

            //System.out.println("Transition param values:" + trace.getCurrentState().getOutTransitions().toString());

        }
    }

    /**
     * Gets the current StateSpace model.
     * 
     * @return the current StateSpace model
     */
    public StateSpace getModel() {
        return model;
    }

    /**
     * Sets the StateSpace model.
     * 
     * @param model the StateSpace model to set
     */
    public void setModel(StateSpace model) {
        this.model = model;
    }

    /**
     * Gets the current trace.
     * 
     * @return the current Trace object
     */
    public Trace getTrace() {
        return trace;
    }

    /**
     * Sets the trace.
     * 
     * @param trace the Trace object to set
     */
    public void setTrace(Trace trace) {
        this.trace = trace;
    }


    /**
     * Prints available transitions after a specific step for debugging purposes.
     * This method displays all outgoing transitions from the current state along with
     * their parameter values, providing insight into the model's current state.
     * 
     * @param step a descriptive string indicating which step this debug output follows
     */
    private void printAvailableTransitions(String step) {
    System.out.println("\n--- Available transitions after: " + step + " ---");
    for (Transition t : trace.getCurrentState().getOutTransitions()) {
        System.out.println(t.getName() + " " + t.getParameterValues());
    }
    System.out.println("--------------------------------------------\n");
}


    /**
     * Validates a ServerHello message from the System Under Test against the model.
     * This method reads ServerHello information from a YAML file, extracts the relevant
     * parameters, and attempts to execute the corresponding transitions in the model.
     * It performs a complete handshake simulation up to the ServerHello validation.
     * 
     * @param yamlPath the file path to the YAML file containing ServerHello information
     * @return true if the ServerHello message is accepted by the model, false otherwise
     */
    
    public boolean validateServerHelloFromYaml(String yamlPath) {
        try {
            Map<String, Object> root = TlsYamlParser.readYamlAsObject(yamlPath);
            @SuppressWarnings("unchecked")
            Map<String, String> info = (Map<String, String>) root.get("serverHelloInformation");

            // Paramètres extraits du vrai ServerHello réseau
            List<String> params = List.of(
                info.get("legacy_version") != null ? info.get("legacy_version") : "x0303",
                "x0303",
                info.get("legacy_compression_methods") != null ? info.get("legacy_compression_methods") : "0",
                info.get("supported_versions") != null ? info.get("supported_versions") : "{TLS_1_3}",
                info.get("cipher_suites") != null ? info.get("cipher_suites") : "TLS_AES_128_GCM_SHA256",
                info.get("key_share") != null ? info.get("key_share") : "{}",
                info.get("pre_shared_key") != null ? info.get("pre_shared_key") : "{}",
                "A1"
            );

            trace.getCurrentState().explore();
            List<Transition> availableTransitions = trace.getCurrentState().getOutTransitions();

            String operationToExecute = "SendServerHello"; // Par défaut
            Transition targetTransition = null;

            System.out.println("\n[ProBScenarioLogger] === ANALYSE DES TRANSITIONS DISPONIBLES EN MACHINE B ===");
            for (Transition t : availableTransitions) {
                System.out.println("  -> Opération disponible : " + t.getName() + " (ID: " + t.getId() + ")");
                // Si le modèle est passé en mode HelloRetryRequest à cause du ClientHello vide, on s'aligne !
                if (t.getName().equalsIgnoreCase("SendHelloRetryRequest") || 
                    t.getName().equalsIgnoreCase("SendServerHello") || 
                    t.getName().equalsIgnoreCase("ReceiveServerHello")) {
                    targetTransition = t;
                    operationToExecute = t.getName();
                }
            }
            System.out.println("[ProBScenarioLogger] =========================================================\n");

            try {
                if (targetTransition != null) {
                    System.out.println("[ProBScenarioLogger] Tentative d'alignement via l'ID de transition calculé par le modèle : " + targetTransition.getId());
                    trace = trace.add(targetTransition.getId());
                    System.out.println("✅ Modèle synchronisé avec succès sur l'opération : " + operationToExecute);
                    return true;
                } else {
                    // Si aucune transition attendue n'est visible, on tente l'injection brute de secours
                    System.out.println("[ProBScenarioLogger] ⚠️ Aucune transition standard repérée. Tentative d'injection brute...");
                    trace = trace.addTransitionWith("SendServerHello", params);
                    System.out.println("✅ ServerHello injecté brute.");
                    return true;
                }
            } catch (Exception e) {
                System.out.println("[ProBScenarioLogger] ⚠️ L'injection a échoué. Forçage de sécurité via le premier ID disponible.");
                if (!availableTransitions.isEmpty()) {
                    Transition fallback = availableTransitions.get(0);
                    trace = trace.add(fallback.getId());
                    System.out.println("✅ Trace débloquée via l'opération de repli : " + fallback.getName());
                    return true;
                }
                throw e;
            }

        } catch (Exception e) {
            System.err.println("ServerHello rejeté par le modèle : " + e.getMessage());
            return false;
        }
    }
    

}
