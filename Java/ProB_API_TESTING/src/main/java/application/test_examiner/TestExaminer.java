package application.test_examiner;

import application.config.Config;
import application.information_handler.AbstractInformationComparator;
import application.information_handler.InformationConvertertoAbstract;
import application.model_api.ModelLoader;
import application.system_under_test.SystemUnderTest;
import application.system_under_test.tls_attacker.TLSAttackerFakeClient;
import application.system_under_test.tls_attacker.TLSAttackerSUTServer;
import application.system_under_test.openssl.OpensslLauncher;
// import application.system_under_test.tls_attacker.utils.TlsYamlParser;
// import application.system_under_test.tls_system_under_test.TLSSystemUnderTest;

import java.io.IOException;

// import java.util.Map;

import com.google.inject.Guice;
import com.google.inject.Injector;
import de.prob.MainModule;
import de.prob.scripting.Api;

/**
 * Central coordinator for Model-Based Testing of TLS implementations.
 * This class orchestrates the entire testing process by managing both the formal model
 * execution and the System Under Test (SUT) operations, then comparing their behaviors.
 * 
 * <p>The TestExaminer handles:
 * <ul>
 *   <li>Loading and executing B-method formal models of TLS protocols</li>
 *   <li>Initializing and running TLS implementations as Systems Under Test</li>
 *   <li>Coordinating message exchanges between model and SUT</li>
 *   <li>Validating SUT behavior against model specifications</li>
 * </ul>
 */
public class TestExaminer {

    /* Type of the test examiner */
    private ModelLoader modelLoader;

    /* System Under Test (SUT) */
    private SystemUnderTest systemUnderTest;
    private SystemUnderTest fakeClient;

    private OpensslLauncher opensslLauncher;


    /* Client or server SUT */
    private String mode;

    /**
     * Constructs a TestExaminer with the specified test type.
     * Initializes the ProB API, loads the appropriate formal model, and sets up
     * the corresponding System Under Test implementations based on the test type.
     * 
     * @param type the type of test to perform ("tls" for TLS 1.3 testing, "tlsTesting" for alternative model)
     * @throws IllegalArgumentException if an invalid test type is provided
     */
    public TestExaminer(String type) {

        // Initialize Guice injector to load the ProB API
        Injector injector = Guice.createInjector(new MainModule());
        Api api = injector.getInstance(Api.class);

        switch (type) {
            case "tls":
                this.modelLoader = new ModelLoader(
                    api,
                    Config.TLSMODELFILEPATH
                );

                this.systemUnderTest = new TLSAttackerSUTServer();
                this.fakeClient = new TLSAttackerFakeClient();

                break;
            //Simply to show the flexibility and adaptation of the code
            case "tlsTesting":
                this.modelLoader = new ModelLoader(
                    api,
                    Config.TLSMODELFORTESTINGFILEPATH
                );
                //this.systemUnderTest = new SystemUnderTest();
                break;
            default:
                System.out.println("Invalid Test Examiner Type");
        }
    }

    /**
     * Executes the complete Model-Based Testing workflow.
     * This method orchestrates the entire testing process including model loading,
     * ClientHello generation, SUT initialization, fake client execution, and
     * ServerHello validation against the formal model.
     */
    public void runTest() {
        System.out.println("-- Starting TLS Test --");

        
        // Load model
        loadModel();
        
        // modelLoader.findSendClientHelloParameters();

        //Generate ClientHello
        System.out.println("Generating and testing ClientHello");
        modelLoader.generateClientHello();


        // Launch real SUT (System Under Test)
        Process openssl = null;
        try {
            openssl = OpensslLauncher.startOpenSslServer(
                "src/main/resources/session/server.crt", "src/main/resources/session/server.key", 8443
            );
        } catch (IOException e) {
            e.printStackTrace();
        }

        // DISABLED: Using external OpenSSL server instead of TLS-Attacker server
        // if (systemUnderTest != null) {
        //     System.out.println("Starting SUT ...");
        //     systemUnderTest.createSUT();
        //     systemUnderTest.startSUT();
        // }

        // System.out.println("Using external OpenSSL server on port 8443");
        // System.out.println("Make sure your OpenSSL server is running:");
        // System.out.println("  openssl s_server -cert cert.pem -key key.pem -accept 8443");
        // System.out.println("Waiting 2 seconds for server to be ready...");
        
        // try {
        //     Thread.sleep(2000); // Wait 2 seconds
        // } catch (InterruptedException e) {
        //     Thread.currentThread().interrupt();
        // }

        // Create and execute the fake client with tls attacker as a client
        if (fakeClient != null) {
            System.out.println("Starting client with tls attacker...");
            fakeClient.createSUT();
        }

        openssl.destroy();

        // Results comparison
        // compareResults();

        boolean isValid = modelLoader.validateServerHelloFromSUT("src/main/resources/data/SUTServerHello.yaml");

        if (isValid) {
            System.out.println("ServerHello is valid according to the model.");
        } else {
            System.out.println("ServerHello is invalid according to the model.");
        }

        System.out.println("Shutting down model...");
        this.modelLoader.killModel();
        System.out.println("-- TLS Test Finished --");      
          
    }

    /**
     * Loads and initializes the formal B-method model.
     * This method loads the model specification, executes initial setup,
     * and prints model information for verification.
     */
    public void loadModel() {
        System.out.println("Testing TLS Model...");
        this.modelLoader.loadAndExecuteAPI();
        this.modelLoader.modelInformation();
    }

    // public void createSUT() {
    //     systemUnderTest.startSUT();
    // }

    /**
     * Creates a System Under Test specifically configured for ServerHello testing.
     * This method is reserved for future implementations of specialized SUT configurations.
     */
    public void createSUTForServerHello() {}

    /**
     * Executes a specific operation on the System Under Test.
     * This method is reserved for future implementations of targeted SUT operations.
     */
    public void executeSUTOperation() {}

    //    KEEPING FOR FURTHER IMPLEMENTATIONS
    //    public void executeModelOperation() {
    //        this.modelLoader.executeSpecificTrace();
    //    }

    /**
     * Tests ServerHello message generation and validation.
     * This method generates both ClientHello and ServerHello messages using the model
     * to validate the complete handshake sequence.
     */
    public void testServerHello() {
        this.modelLoader.generateClientAndServerHello();
    }

    /**
     * Compares results between the model and System Under Test.
     * This method performs YAML-based comparison of handshake messages to detect
     * discrepancies between expected model behavior and actual SUT implementation.
     * The comparison mode (client/server) determines which messages are compared.
     * 
     * @throws IllegalArgumentException if an unknown SUT mode is specified
     */
    public void compareResults() {
        System.out.println("Comparing YAML result");
        boolean match;

        switch (mode) {
            case "client":
                match = AbstractInformationComparator.compareAbstractYaml(
                    InformationConvertertoAbstract.retreiveYamlInformation(
                        "src/main/resources/data/SUTServerHello.yaml"
                    ),
                    InformationConvertertoAbstract.retreiveYamlInformation(
                        "src/main/resources/data/ModelServerHello.yaml"
                    ),
                    ""
                );
                break;
            case "server":
                match = AbstractInformationComparator.compareAbstractYaml(
                    InformationConvertertoAbstract.retreiveYamlInformation(
                        "src/main/resources/data/SUTClientHello.yaml"
                    ),
                    InformationConvertertoAbstract.retreiveYamlInformation(
                        "src/main/resources/data/ModelClientHello.yaml"
                    ),
                    ""
                );
                break;
            default:
                throw new IllegalArgumentException("Unknown SUT mode: " + mode);
        }

        System.out.println(match ? "Match found!" : "No match found!");
    }


    



}
