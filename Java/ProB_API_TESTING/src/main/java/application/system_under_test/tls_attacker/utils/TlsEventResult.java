package application.system_under_test.tls_attacker.utils;

import java.util.Map;

/**
 * Data Transfer Object representing an event result from the SUT to ProB.
 */
public class TlsEventResult {
    private String status; // e.g., SUCCESS, FAILURE, SENT_OK
    private String messageType;
    private Map<String, String> extractedParameters;

    public TlsEventResult() {}

    public TlsEventResult(String status, String messageType, Map<String, String> extractedParameters) {
        this.status = status;
        this.messageType = messageType;
        this.extractedParameters = extractedParameters;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getMessageType() {
        return messageType;
    }

    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }

    public Map<String, String> getExtractedParameters() {
        return extractedParameters;
    }

    public void setExtractedParameters(Map<String, String> extractedParameters) {
        this.extractedParameters = extractedParameters;
    }
}
