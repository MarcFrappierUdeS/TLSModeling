package application.system_under_test.tls_attacker.utils;

import java.util.Map;

/**
 * Data Transfer Object representing a command from ProB to the SUT.
 */
public class ProbCommand {
    private String action; // SEND or LISTEN
    private String messageType; // e.g., ClientHello, ServerHello
    private Map<String, Object> parameters;

    public ProbCommand() {}

    public ProbCommand(String action, String messageType, Map<String, Object> parameters) {
        this.action = action;
        this.messageType = messageType;
        this.parameters = parameters;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getMessageType() {
        return messageType;
    }

    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }

    public Map<String, Object> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, Object> parameters) {
        this.parameters = parameters;
    }
}
