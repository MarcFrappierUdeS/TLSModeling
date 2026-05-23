package application.model_api;

// import application.config.Config;
// import com.google.inject.Guice;
import com.google.inject.Inject;
// import com.google.inject.Injector;
// import com.google.inject.Stage;
import de.prob.scripting.Api;
import de.prob.statespace.StateSpace;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Loader and manager for B-method formal models in TLS Model-Based Testing.
 * Handles loading, initialization, and execution coordination of ProB StateSpace models.
 * 
 * <p>Key responsibilities:
 * <ul>
 *   <li>Loading B-machine specifications from file system</li>
 *   <li>Initializing ProB API and model execution environment</li>
 *   <li>Coordinating model executions and trace generations</li>
 *   <li>Validating SUT outputs against model specifications</li>
 * </ul>
 * 
 */
public class ModelLoader {

    /** Guice injector for ProB 2.0 bindings and dependency injection */
    // private static final Injector INJECTOR = Guice.createInjector(Stage.PRODUCTION, new Config());
    
    /** File path to the B-machine model specification */
    private final String modelFilePath;

    /** ProB API instance for model operations */
    private final Api api;
    
    /** Loaded StateSpace model ready for execution */
    private StateSpace model;
    
    /** Model execution engine for running traces and validations */
    private ModelExecuter modelExecuter;


    /**
     * Constructor for ModelLoader.
     * Initializes the ModelLoader with the ProB API and the path to the model file.
     * 
     * @param api the ProB API instance used for loading and executing models
     * @param modelFilePath the path to the B machine (.mch) file to be loaded
     */
    @Inject
    public ModelLoader(Api api, String modelFilePath) {

        this.api = api;

        this.modelFilePath = modelFilePath;
    }

    /**
     * Loads the B machine (.mch file) and executes it.
     * This method initializes the model and prepares it for execution.
     * It also performs extended static checks on the model.
     * If an error occurs during loading or execution, it prints the stack trace.
     * 
     * @throws Exception if there is an error loading or executing the model
     */
    public void loadAndExecuteAPI() {
        try {
            System.out.println("LOADING B MACHINE (.mch file)");
            Map<String, String> prefs = new HashMap<>();
            prefs.put("MAX_OPERATIONS","1000");
            model = api.b_load(Paths.get(this.modelFilePath).toAbsolutePath().toString(), prefs);
            model.execute();
            model.performExtendedStaticChecks();
            modelExecuter = new ModelExecuter(model);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * Prints information about the loaded model.
     * This includes the names of sets, constants, variables, and operations in the machine.
     * It is useful for understanding the structure and components of the model.
     * 
     */
    public void modelInformation() {
        System.out.println("--------------");
        System.out.println("Machine Set Names: " + model.getLoadedMachine().getSetNames());
        System.out.println("--------------");
        System.out.println("Machine Constant Names: " + model.getLoadedMachine().getConstantNames());
        System.out.println("--------------");
        System.out.println("Machine Variable Names: " + model.getLoadedMachine().getVariableNames());
        System.out.println("--------------");
        System.out.println("Machine Operations Names: " + model.getLoadedMachine().getOperationNames());
        System.out.println("--------------");
    }

    /**
     * Executes a random trace of the model.
     * This method creates a subscription to the "session_machine" and generates a random trace with a specified number of steps.
     * 
     * @param steps the number of steps in the random trace
     */
    public void executeRandomTrace(int steps) {
        modelExecuter.createSubscription("session_machine");
        modelExecuter.generateRandomTrace(10);
    }

    /**
     * Executes a specific trace of the model.
     * This method creates a subscription to the "session_machine" and generates a trace that includes both client and server hello messages.
     * It is useful for testing specific scenarios in the TLS handshake process.
     */
    public void executeSpecificTrace() {
        modelExecuter.createSubscription("session_machine");
        modelExecuter.generateClientAndServerHello();
    }

    /**
     * Generates a ClientHello message using the model.
     * Creates a subscription to the session machine and generates only ClientHello messages.
     * This is useful for testing the initial phase of the TLS handshake.
     */
    public void generateClientHello() {
        modelExecuter.createSubscription("session_machine");
        modelExecuter.generateClientHelloMessages();
    }


    /**
     * Generates both ClientHello and ServerHello messages using the model.
     * Creates a subscription to the session machine and generates the complete handshake sequence.
     * This method facilitates testing the full TLS handshake exchange.
     */
    public void generateClientAndServerHello(){
        modelExecuter.createSubscription("session_machine");
        modelExecuter.generateClientAndServerHello();
    }

    /**
     * Validates a ServerHello message from the System Under Test against the model.
     * Creates a subscription to the session machine and validates the ServerHello message
     * loaded from the specified YAML file path against the model's expected behavior.
     * 
     * @param yamlPath the path to the YAML file containing the ServerHello message to validate
     * @return true if the ServerHello message is valid according to the model, false otherwise
     */
    public boolean validateServerHelloFromSUT(String yamlPath) {
    modelExecuter.createSubscription("session_machine"); 
        return modelExecuter.validateServerHelloFromYaml(yamlPath);
    }

    /**
     * Generates a valid ClientHello message with transitions.
     * This method creates a subscription to the session machine and generates a valid ClientHello message
     * with transitions, which can be used for further testing or validation.
     * @param yamlFilePath the path to the YAML file where the generated ClientHello message will be saved
     * @return true if the ClientHello message is valid, false otherwise
    //  */
    // public boolean generateValidClientHelloWithFindTransitions(String yamlFilePath) {
    //     modelExecuter.createSubscription("session_machine");
    //     return modelExecuter.generateValidClientHelloWithFindTransitions(yamlFilePath);
    // }

    /**
     * Terminates the ProB StateSpace process.
     * This method should be called when the model is no longer needed to release resources
     * and ensure that the underlying ProB process is properly shut down.
     */
    public void killModel() {
        if (model != null) {
            model.kill();
        }
    }

    public ModelExecuter getModelExecuter() {
        return modelExecuter;
    }
}



