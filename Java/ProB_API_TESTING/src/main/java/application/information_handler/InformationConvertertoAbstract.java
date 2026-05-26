package application.information_handler;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.representer.Representer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import application.system_under_test.tls_attacker.utils.TlsMessageParser;
import application.system_under_test.tls_attacker.utils.TlsMessageBuilder;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Utility class for converting and processing abstract information to/from YAML format.
 * This class provides comprehensive YAML handling capabilities for Model-Based Testing,
 * including serialization of information holders, file processing, and data retrieval.
 */
public class InformationConvertertoAbstract {

    // YAML configuration initialized once
    private static final DumperOptions options;
    private static final Yaml yaml;

    static {
        options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setExplicitStart(false);
        yaml = new Yaml(new Representer(options), options);
    }

    /**
     * Removes the first line of a YAML file, typically used to strip global tags.
     * 
     * @param filePath The path to the YAML file to process.
     */
    public static void removeGlobalTagsYaml(String filePath) {
        try {
            Path path = Paths.get(filePath).toAbsolutePath();
            if (!Files.exists(path)) {
                System.err.println("File not found: " + path);
                return;
            }

            String updatedContent = Files.lines(path)
                    .skip(1)
                    .collect(Collectors.joining(System.lineSeparator()));

            Files.write(path, updatedContent.getBytes());
        } catch (IOException e) {
            System.err.println("Error processing file " + filePath);
            e.printStackTrace();
        }
    }

    /**
     * Serializes a Java object to a YAML file.
     * 
     * @param obj The object to serialize.
     * @param filePath The destination file path.
     */
    public static void serializeToYAML(Object obj, String filePath) {
        try {
            Path path = Paths.get(filePath).toAbsolutePath();
            Files.createDirectories(path.getParent());
            
            try (FileWriter writer = new FileWriter(filePath)) {
                yaml.dump(obj, writer);
                System.out.println("YAML file created: " + path);
            }
        } catch (IOException e) {
            System.err.println("Failed to write YAML to " + filePath);
            e.printStackTrace();
        }
    }

    /**
     * Reconfigures global YAML dumper options.
     */
    public static void configureYAML() {
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setExplicitStart(false);
    }

    /**
     * Loads YAML content from a file into a Map.
     * 
     * @param yamlFilePath The path to the YAML file.
     * @return A map representation of the YAML data, or null if loading fails.
     */
    public static Map<String, Object> retreiveYamlInformation(String yamlFilePath) {
        try {
            Path path = Paths.get(yamlFilePath).toAbsolutePath();
            if (!Files.exists(path)) {
                System.err.println("YAML file not found: " + path);
                return null;
            }

            try (InputStream input = Files.newInputStream(path)) {
                Map<String, Object> result = yaml.load(input);
                return result;
            }
        } catch (Exception e) {
            System.err.println("Error loading YAML from " + yamlFilePath);
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Extracts abstract data from a raw TLS-Attacker message.
     * 
     * @param message The protocol message to parse.
     * @return A map of abstract property-value pairs.
     */
    public static Map<String, String> extractAbstractData(ProtocolMessage message) {
        if (message instanceof ServerHelloMessage) {
            return TlsMessageParser.parseServerHello((ServerHelloMessage) message);
        } else if (message instanceof ClientHelloMessage) {
            return TlsMessageParser.parseClientHello((ClientHelloMessage) message);
        } else if (message instanceof EncryptedExtensionsMessage) {
            return TlsMessageParser.parseEncryptedExtensions((EncryptedExtensionsMessage) message);
        } else if (message instanceof CertificateMessage) {
            return TlsMessageParser.parseCertificate((CertificateMessage) message);
        } else if (message instanceof FinishedMessage) {
            return TlsMessageParser.parseFinished((FinishedMessage) message);
        } else if (message instanceof AlertMessage) {
            return TlsMessageParser.parseAlert((AlertMessage) message);
        }
        return null;
    }

    /**
     * Identity mapping for abstract ProB data.
     * 
     * @param probMessage The input map.
     * @return The same map.
     */
    public static Object buildFromAbstract(Map<String, String> probMessage) {
        return probMessage; 
    }
}
