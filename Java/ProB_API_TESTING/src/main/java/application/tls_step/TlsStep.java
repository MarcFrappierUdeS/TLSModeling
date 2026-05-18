package application.tls_step;

import java.util.List;

public class TlsStep {
    public String action;
    public List<String> parameters;
    public String status; // ex: "PENDING", "SUCCESS", "FAILED"

    public TlsStep() {} // Requis pour Jackson
    public TlsStep(String action, List<String> parameters) {
        this.action = action;
        this.parameters = parameters;
        this.status = "PENDING";
    }
}
