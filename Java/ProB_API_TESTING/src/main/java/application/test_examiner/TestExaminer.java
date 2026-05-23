package application.test_examiner;

import application.config.Config;
import application.information_handler.AbstractInformationComparator;
import application.information_handler.InformationConvertertoAbstract;
import application.model_api.ModelLoader;
import application.system_under_test.SystemUnderTest;
import application.system_under_test.tls_attacker.TLSAttackerFakeClient;
import application.system_under_test.tls_attacker.TLSAttackerSUTServer;
import application.system_under_test.openssl.OpensslLauncher;
import application.system_under_test.tls_attacker.utils.ProbCommand;
import application.system_under_test.tls_attacker.utils.TlsEventResult;
import application.system_under_test.tls_attacker.utils.TlsYamlParser;
import application.model_api.ModelExecuter;
import java.io.File;
import java.io.IOException;
import java.util.Map;

import com.google.inject.Guice;
import com.google.inject.Injector;
import de.prob.MainModule;
import de.prob.scripting.Api;

/**
 * Central coordinator for Model-Based Testing of TLS implementations.
 * This class orchestrates the entire testing process by managing both the formal model
 * execution and the System Under Test (SUT) operations, then comparing their behaviors.
 */
public class TestExaminer {

    private ModelLoader modelLoader;
    private SystemUnderTest systemUnderTest;
    private SystemUnderTest fakeClient;
    private String mode;

    public TestExaminer(String type) {
        Injector injector = Guice.createInjector(new MainModule());
        Api api = injector.getInstance(Api.class);

        switch (type) {
            case "tls":
                this.modelLoader = new ModelLoader(api, Config.TLSMODELFILEPATH);
                this.systemUnderTest = new TLSAttackerSUTServer();
                this.fakeClient = new TLSAttackerFakeClient();
                break;
            case "tlsTesting":
                this.modelLoader = new ModelLoader(api, Config.TLSMODELFORTESTINGFILEPATH);
                break;
            default:
                System.out.println("Invalid Test Examiner Type");
        }
    }

    public void runTest() {
        System.out.println("-- Starting TLS Test --");
        loadModel();
        runTestLoop();
        System.out.println("Shutting down model...");
        this.modelLoader.killModel();
        System.out.println("-- TLS Test Finished --");      
    }

    public void runTestLoop() {
        System.out.println("\n======================================================");
        System.out.println("          STARTING FORMAL TEST LOOP");
        System.out.println("======================================================\n");
        boolean testFinished = false;
        ModelExecuter executer = modelLoader.getModelExecuter();
        
        Process openssl = null;
        try {
            System.out.println("[Orchestrator] 🚀 Starting OpenSSL server SUT...");
            openssl = OpensslLauncher.startOpenSslServer(
                "src/main/resources/session/server.crt", "src/main/resources/session/server.key", 8443
            );
            Thread.sleep(2000); // Wait for server to bind
        } catch (Exception e) {
            System.err.println("[Orchestrator] ❌ Failed to start OpenSSL server: " + e.getMessage());
            return;
        }

        try {
            System.out.println("[Orchestrator] 🟢 Initializing B Model state...");
            executer.initaliseMachine();

            int step = 1;
            while (!testFinished) {
                System.out.println("\n--- STEP " + step + " ---");
                String action = executer.evaluateNextAction();
                System.out.println("[Orchestrator] 📋 Model Decision: " + action);
                
                if ("FINISHED".equals(action)) {
                    System.out.println("[Orchestrator] ✅ Model reached terminal state. Test finished.");
                    testFinished = true;
                    break;
                }

                if ("INTERNAL".equals(action)) {
                    System.out.println("[Orchestrator] ⏩ Internal model transition detected. Advancing model without network I/O...");
                    executer.forwardInternalState();
                    step++;
                    continue; // On passe directement à la step suivante !
                }

                System.out.println("[Orchestrator] 📝 Generating command for SUT...");
                executer.generateCommandYaml(action, null);

                if (fakeClient instanceof TLSAttackerFakeClient) {
                    File cmdFile = new File("prob_command.yaml");
                    if (cmdFile.exists()) {
                        try {
                            ProbCommand cmd = TlsYamlParser.parseProbCommand("prob_command.yaml");
                            cmdFile.delete();
                            System.out.println("[Orchestrator] ⚡ Triggering TLS-Attacker: " + cmd.getAction() + " " + cmd.getMessageType());
                            ((TLSAttackerFakeClient) fakeClient).executeCommand(cmd);
                        } catch (Exception e) {
                            System.err.println("[Orchestrator] ❌ SUT Execution Error: " + e.getMessage());
                            break;
                        }
                    }
                }

                System.out.println("[Orchestrator] ⏳ Waiting for SUT event (tls_event.yaml)...");
                File eventFile = new File("tls_event.yaml");
                int attempts = 0;
                while (!eventFile.exists() && attempts < 30) {
                    try {
                        Thread.sleep(500);
                        attempts++;
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }

                if (eventFile.exists()) {
                    try {
                        Map<String, Object> data = TlsYamlParser.readYamlAsObject("tls_event.yaml");
                        eventFile.delete();
                        
                        TlsEventResult event = new TlsEventResult();
                        event.setStatus((String) data.get("status"));
                        event.setMessageType((String) data.get("messageType"));
                        event.setExtractedParameters((Map<String, String>) data.get("extractedParameters"));
                        
                        System.out.println("[Orchestrator] 📥 Feeding event to Model: " + event.getMessageType() + " [" + event.getStatus() + "]");
                        executer.feedEventToModel(event);
                    } catch (Exception e) {
                        System.err.println("[Orchestrator] ❌ Error processing event: " + e.getMessage());
                        // If we fail to process the event, we should probably stop to avoid infinite loop
                        break;
                    }
                } else {
                    System.err.println("[Orchestrator] ⚠️ Timeout: No event received from SUT within 15s.");
                    break;
                }
                step++;
                if (step > 50) {
                    System.err.println("[Orchestrator] 🛑 Safety break: test loop exceeded 50 steps.");
                    break;
                }
            }
        } finally {
            if (openssl != null) {
                System.out.println("\n[Orchestrator] 🛑 Shutting down OpenSSL server...");
                openssl.destroy();
            }
        }
    }

    public void loadModel() {
        System.out.println("Testing TLS Model...");
        this.modelLoader.loadAndExecuteAPI();
        this.modelLoader.modelInformation();
    }

    public void createSUTForServerHello() {}
    public void executeSUTOperation() {}
    public void testServerHello() {
        this.modelLoader.generateClientAndServerHello();
    }

    public void compareResults() {
        System.out.println("Comparing YAML result");
        boolean match;
        switch (mode) {
            case "client":
                match = AbstractInformationComparator.compareAbstractYaml(
                    InformationConvertertoAbstract.retreiveYamlInformation("src/main/resources/data/SUTServerHello.yaml"),
                    InformationConvertertoAbstract.retreiveYamlInformation("src/main/resources/data/ModelServerHello.yaml"),
                    ""
                );
                break;
            case "server":
                match = AbstractInformationComparator.compareAbstractYaml(
                    InformationConvertertoAbstract.retreiveYamlInformation("src/main/resources/data/SUTClientHello.yaml"),
                    InformationConvertertoAbstract.retreiveYamlInformation("src/main/resources/data/ModelClientHello.yaml"),
                    ""
                );
                break;
            default:
                throw new IllegalArgumentException("Unknown SUT mode: " + mode);
        }
        System.out.println(match ? "Match found!" : "No match found!");
    }
}
