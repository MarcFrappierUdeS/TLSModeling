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

    /**
     * Initializes a new TestExaminer of the specified type.
     * 
     * @param type The type of test to perform (e.g., "tls" or "tlsTesting").
     */
    public TestExaminer(String type) {
        Injector injector = Guice.createInjector(new MainModule());
        Api api = injector.getInstance(Api.class);

        switch (type) {
            case "tls":
                this.modelLoader = new ModelLoader(api, Config.TLSMODELFORTESTINGFILEPATH);
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

    /**
     * Executes the complete testing lifecycle.
     * Loads the model, runs the test loop, and performs cleanup upon completion.
     */
    public void runTest() {
        System.out.println("\n>>> INITIALIZING TLS TEST SUITE <<<");
        loadModel();
        runTestLoop();
        System.out.println("\n[SYSTEM] Shutting down model...");
        this.modelLoader.killModel();
        System.out.println(">>> TLS TEST SUITE FINISHED <<<\n");      
    }

    /**
     * Main execution loop for formal model-based testing.
     * Orchestrates the interaction between the ProB model and the System Under Test.
     * Handles starting the SUT, model initialization, action evaluation, command generation,
     * and processing network events back into the model.
     */
    public void runTestLoop() {
        System.out.println("======================================================");
        System.out.println("          STARTING FORMAL TEST LOOP");
        System.out.println("======================================================");
        boolean testFinished = false;
        ModelExecuter executer = modelLoader.getModelExecuter();
        
        Process openssl = null;
        try {
            System.out.println("[SUT-INIT] Starting OpenSSL server SUT...");
            openssl = OpensslLauncher.startOpenSslServer(
                "src/main/resources/session/server.crt", "src/main/resources/session/server.key", 8443
            );
            Thread.sleep(2000); // Wait for server to bind
        } catch (Exception e) {
            System.err.println("[ERROR] Failed to start OpenSSL server: " + e.getMessage());
            return;
        }

        try {
            System.out.println("[MODEL] Initializing B Model state...");
            executer.initaliseMachine();

            int step = 1;
            while (!testFinished) {
                System.out.println("\n+--- STEP #" + step + " -------------------------------------------");
                String action = executer.evaluateNextAction();
                System.out.println("| [MODEL] Decision: " + action);
                
                if ("FINISHED".equals(action)) {
                    System.out.println("| [STATE] Model reached terminal state. Test successful.");
                    testFinished = true;
                    break;
                }

                if ("INTERNAL".equals(action)) {
                    System.out.println("| [MODEL] Internal transition. Advancing state...");
                    executer.forwardInternalState();
                    step++;
                    continue; 
                }

                System.out.println("| [GEN] Generating YAML command for SUT...");
                executer.generateCommandYaml(action, null);

                if (fakeClient instanceof TLSAttackerFakeClient) {
                    File cmdFile = new File("prob_command.yaml");
                    if (cmdFile.exists()) {
                        try {
                            ProbCommand cmd = TlsYamlParser.parseProbCommand("prob_command.yaml");
                            cmdFile.delete();
                            System.out.println("| [NET] Sending to SUT: " + cmd.getAction() + " " + cmd.getMessageType());
                            ((TLSAttackerFakeClient) fakeClient).executeCommand(cmd);
                        } catch (Exception e) {
                            System.err.println("| [ERROR] SUT Execution Failure: " + e.getMessage());
                            break;
                        }
                    }
                }

                System.out.println("| [NET] Waiting for SUT event (tls_event.yaml)...");
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
                        
                        System.out.println("| [MODEL] Processing event: " + event.getMessageType() + " [" + event.getStatus() + "]");
                        executer.feedEventToModel(event);
                    } catch (Exception e) {
                        System.err.println("| [ERROR] Event processing error: " + e.getMessage());
                        break;
                    }
                } else {
                    System.err.println("| [TIMEOUT] No event received from SUT (15s limit).");
                    break;
                }
                step++;
                if (step > 50) {
                    System.err.println("| [SAFETY] Test loop exceeded maximum step limit (50).");
                    break;
                }
            }
            System.out.println("+------------------------------------------------------\n");
        } finally {
            if (openssl != null) {
                System.out.println("[SUT-EXIT] Shutting down OpenSSL server...");
                openssl.destroy();
            }
        }
    }

    /**
     * Loads the B machine and initializes the ProB API.
     */
    public void loadModel() {
        System.out.println("Testing TLS Model...");
        this.modelLoader.loadAndExecuteAPI();
        this.modelLoader.modelInformation();
    }

    /**
     * Stub for SUT creation.
     */
    public void createSUTForServerHello() {}

    /**
     * Stub for SUT operation execution.
     */
    public void executeSUTOperation() {}

    /**
     * Triggers the generation of Client and Server Hello messages in the model.
     */
    public void testServerHello() {
        this.modelLoader.generateClientAndServerHello();
    }

    /**
     * Compares the YAML outputs between the SUT and the formal model.
     * Uses the AbstractInformationComparator to determine if the behavior matches.
     */
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
