package application.system_under_test.tls_attacker.utils;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.DumperOptions;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;

/**
 * Utility class for reading and writing TLS message data in YAML format.
 */
public class TlsYamlParser {
    
    /**
     * Reads a YAML file and returns its contents as a Map.
     * @param filename The path to the YAML file
     * @return Map containing the YAML data
     * @throws RuntimeException if the file cannot be read
     */
    public static Map<String, String> readYaml(String filename) {
        try (FileReader reader = new FileReader(filename)) {
            Yaml yaml = new Yaml();
            return yaml.load(reader);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read YAML file: " + filename, e);
        }
    }

    /**
     * Reads a YAML file and returns its contents as a generic Map.
     * Used when the YAML has nested structures.
     * @return Map containing the YAML data
     * @param filename The path to the YAML file
     * @throws RuntimeException if the file cannot be read
     */
    public static Map<String, Object> readYamlAsObject(String filename) {
        try (FileReader reader = new FileReader(filename)) {
            Yaml yaml = new Yaml();
            return yaml.load(reader);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read YAML file: " + filename, e);
        }
    }


    /**
     * Writes data to a YAML file.
     * @param data The data to write
     * @param filename The path where to write the YAML file
     * @throws RuntimeException if the file cannot be written
     */
    public static void writeYaml(Map<String, ?> data, String filename){
        try (FileWriter writer = new FileWriter(filename)) {
            DumperOptions options = new DumperOptions();
                options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK); //key here
                options.setIndent(2); // indentation level
                options.setPrettyFlow(true);

            Yaml yaml = new Yaml(options);
            yaml.dump(data, writer);
        } catch (IOException e) {
            throw new RuntimeException("Failed to write YAML file: " + filename, e);
        }
    }

    /**
     * Parses a prob_command.yaml file.
     */
    public static ProbCommand parseProbCommand(String filePath) {
        Map<String, Object> data = readYamlAsObject(filePath);
        ProbCommand cmd = new ProbCommand();
        cmd.setAction((String) data.get("action"));
        cmd.setMessageType((String) data.get("messageType"));
        cmd.setParameters((Map<String, Object>) data.get("parameters"));
        return cmd;
    }

    /**
     * Writes a TlsEventResult to a tls_event.yaml file.
     */
    public static void writeTlsEvent(TlsEventResult result, String filePath) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        
        // Use a map to avoid class tags like !!application.system_under_test...
        java.util.Map<String, Object> data = new java.util.HashMap<>();
        data.put("status", result.getStatus());
        data.put("messageType", result.getMessageType());
        data.put("extractedParameters", result.getExtractedParameters());
        
        Yaml yaml = new Yaml(options);
        try (FileWriter writer = new FileWriter(filePath)) {
            yaml.dump(data, writer);
        } catch (IOException e) {
            throw new RuntimeException("Failed to write TLS event: " + filePath, e);
        }
    }
}
