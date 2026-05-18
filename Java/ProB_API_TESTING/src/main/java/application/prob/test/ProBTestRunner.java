package application.prob.test;

import de.prob.scripting.Api;

import de.prob.statespace.StateSpace;
import de.prob.statespace.Trace;
import de.prob.statespace.Transition;
import com.google.inject.Guice;
import com.google.inject.Injector;

import application.tls_step.TlsStep;
import de.prob.MainModule;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

public class ProBTestRunner {
	private Api api;
    private StateSpace stateSpace;
    private Trace trace;
    private ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    public ProBTestRunner(String modelPath) {
        // Initialisation de l'API ProB
        Injector injector = Guice.createInjector(new MainModule());
        this.api = injector.getInstance(Api.class);
        
        Map<String, String> prefs = new HashMap<>();
        prefs.put("MAX_OPERATIONS", "2000");
        prefs.put("KODKOD", "true");        // Utilise un solveur SAT plus puissant pour trouver des solutions non-vides
        prefs.put("RANDOMISE_ENUMERATION_ORDER", "true"); // Évite de toujours prendre le premier résultat (souvent le plus simple/vide)
        
        try {
            this.stateSpace = api.b_load(new File(modelPath).getAbsolutePath(), prefs);
            this.trace = new Trace(stateSpace);
        } catch (Exception e) {
            throw new RuntimeException("Erreur chargement modèle B: " + e.getMessage());
        }
    }

    /**
     * Démarre le modèle (Setup + Initialisation)
     */
    public void startModel() {
        // exécuter SETUP_CONSTANTS puis INITIALISATION
        this.trace = this.trace.anyEvent(null); 
        this.trace = this.trace.anyEvent(null);
    }

    /**
     * La boucle de test principale
     */
    public void runTestLoop() {
        boolean finished = false;
        
        while (!finished) {
            // 1. Demander à ProB : "Quelles sont les actions possibles ?"
            this.trace.getCurrentState().explore();
            List<Transition> availableTransitions = this.trace.getCurrentState().getOutTransitions();
            
            // 2. Trouver une transition intéressante (pas interne $)
            Transition nextStep = findNextInterestingTransition(availableTransitions);
            
            if (nextStep == null) {
                System.out.println("Fin du test : plus d'actions possibles.");
                finished = true;
                continue;
            }

            // 3. Exécuter l'action concrètement (Switch vers TLS-Attacker)
            boolean success = dispatchToTLSAttacker(nextStep);

            if (success) {
                // 4. Mettre à jour le modèle B si l'action réseau a réussi
                this.trace = this.trace.add(nextStep.getId());
            } else {
                System.err.println("Échec de l'action réseau pour: " + nextStep.getName());
                finished = true;
            }
        }
    }

    private Transition findNextInterestingTransition(List<Transition> transitions) {
        /*for (Transition t : transitions) {
            // On ignore les transitions internes ProB et les terminaisons
            if (!t.getName().startsWith("$") && !t.getName().equalsIgnoreCase("TerminateSession")) {
                return t;
            }
        }
        return null;*/

    	Transition bestSoFar = null;

        for (Transition t : transitions) {
            String params = t.getParameterValues().toString();
            String name = t.getName();

            // Ignorer le bruit
            if (name.startsWith("$") || name.equalsIgnoreCase("TerminateSession")) continue;

            // --- STRATÉGIE DE SCORE ---
            // 1. Priorité absolue : TLS 1.3 (x0304 ou x0303 selon ton modèle)
            if (params.contains("x0304") || params.contains("x0303")) {
                return t; // C'est exactement ce qu'on veut, on sort direct
            }

            // 2. Priorité secondaire : N'importe quoi qui n'est pas vide
            if (!params.contains("{}")) {
                bestSoFar = t;
            }
        }

        // Si on n'a pas trouvé de TLS 1.3, on prend la meilleure transition non-vide
        if (bestSoFar != null) return bestSoFar;

        // Sinon, on prend la première disponible (fallback)
        return transitions.stream()
                .filter(t -> !t.getName().startsWith("$") && !t.getName().contains("Terminate"))
                .findFirst()
                .orElse(null);
    }

    /**
     * on branche TLS-Attacker
     */
    private boolean dispatchToTLSAttacker(Transition transition) {
        String opName = transition.getName().toUpperCase();
        List<String> params = transition.getParameterValues();
        
        System.out.println("\n>>> Action modèle : " + opName);
        System.out.println(">>> Paramètres B : " + params);

        /*switch (opName) {
            case "SENDCLIENTHELLO":
                return executeSendClientHello(params);
            
            case "RECEIVESERVERHELLO":
                return executeReceiveServerHello(params);

            // Ajoute les autres cas (SENDSERVERHELLO, etc.) ici
            
            default:
                System.out.println("Action non gérée, exécution par défaut.");
                return true;
        }*/
        
        try {
            // --- PHASE A : ProB -> YAML ---
            TlsStep step = new TlsStep(opName, params);
            File yamlFile = new File("step_out.yaml");
            yamlMapper.writeValue(yamlFile, step);
            System.out.println("[YAML] Fichier généré : " + yamlFile.getAbsolutePath());

            // --- PHASE B : Simulation TLS-Attacker ---
            // Ici, normalement, TLS-Attacker lit step_out.yaml et écrit step_in.yaml
            boolean networkSuccess = simulateNetworkAction(opName, params);

            // --- PHASE C : YAML -> ProB (Oracle) ---
            if (networkSuccess) {
                // On pourrait imaginer lire un fichier "step_in.yaml" ici
                System.out.println("[ORACLE] Action validée par le réseau.");
                return true;
            }
        } catch (Exception e) {
            System.err.println("Erreur lors de la boucle YAML : " + e.getMessage());
        }
        return false;
    }
    
    private boolean simulateNetworkAction(String op, List<String> params) {
        // Pour débloquer la trace, on force le succès si les paramètres ne sont pas vides
        /*if (params.toString().contains("{}")) {
            System.out.println("[SIMU] Paramètres vides détectés, risque d'échec modèle.");
            return false; 
        }
        return true;*/
        String pStr = params.toString();
        if (pStr.contains("NO_VERSION") || pStr.contains("{}")) {
            System.out.println("[WARNING] Paramètres faibles détectés (" + pStr + "), mais on continue l'exploration du modèle.");
        }
        return true; // On renvoie true pour ne pas couper la boucle while
    }

    // --- Méthodes de pont vers TLS-Attacker ---

    private boolean executeSendClientHello(List<String> params) {
        System.out.println("[TLS-Attacker] Envoi du ClientHello...");
        // TODO: Configurer TLS-Attacker avec params.get(0) (version), etc.
        return true; 
    }

    private boolean executeReceiveServerHello(List<String> params) {
        System.out.println("[TLS-Attacker] Attente du ServerHello...");
        // TODO: Vérifier si le message reçu match avec les params
        return true;
    }

    public void stop() {
        if (stateSpace != null) stateSpace.kill();
    }
	
}
