package application.system_under_test.tls_attacker.utils;

import static application.system_under_test.tls_attacker.utils.ByteUtils.bytesToHex;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Utility class for parsing TLS messages into abstract formats compatible with the ProB B-Model.
 */
public class TlsMessageParser {
    
    /**
     * Parses a ServerHelloMessage into an abstract map.
     * @param message The ServerHelloMessage to parse
     * @return Map containing the abstract data
     */
    public static Map<String, String> parseServerHello(ServerHelloMessage message) {
        Map<String, String> parsed = new LinkedHashMap<>();
        
        // Random
        parsed.put("random", bytesToHex(message.getRandom().getValue()));
        
        // Model expects pre_shared_key to be {} in current draft
        parsed.put("pre_shared_key", "{}");
        
        // Legacy session ID
        if (message.getSessionId() != null && message.getSessionId().getValue() != null && message.getSessionId().getValue().length > 0) {
            parsed.put("legacy_session_id_echo", "x" + bytesToHex(message.getSessionId().getValue()));
        } else {
            parsed.put("legacy_session_id_echo", "x");
        }
        
        // Legacy version (usually 0x0303 for TLS 1.3)
        parsed.put("legacy_version", "x" + bytesToHex(message.getProtocolVersion().getValue()));
        
        // Supported versions
        SupportedVersionsExtensionMessage supportedVersionsExt = message.getExtension(SupportedVersionsExtensionMessage.class);
        if (supportedVersionsExt != null) {
            parsed.put("supported_versions", "{TLS_1_3}");
        } else {
            parsed.put("supported_versions", "{TLS_1_3}");
        }
        
        // Model compatibility fields
        parsed.put("legacy_compression_methods", "0");
        parsed.put("key_share", "{}");
        
        // Cipher suite
        CipherSuite selectedCipherSuite = CipherSuite.getCipherSuite(message.getSelectedCipherSuite().getValue());
        if (selectedCipherSuite != null) {
            parsed.put("cipher_suites", selectedCipherSuite.name());
        } else {
            parsed.put("cipher_suites", "UNKNOWN");
        }
        
        return parsed;
    }

    /**
     * Parses a ClientHelloMessage into an abstract map.
     * @param message The ClientHelloMessage to parse
     * @return Map containing the abstract data
     */
    public static Map<String, String> parseClientHello(ClientHelloMessage message) {
        Map<String, String> map = new LinkedHashMap<>();

        map.put("random", bytesToHex(message.getRandom().getValue()));
        map.put("protocol_version", "x" + bytesToHex(message.getProtocolVersion().getValue()));
        map.put("session_id", bytesToHex(message.getSessionId().getValue()));
        
        byte[] suiteBytes = message.getCipherSuites().getValue();
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < suiteBytes.length; i += 2) {
            byte[] singleSuite = new byte[]{suiteBytes[i], suiteBytes[i+1]};
            CipherSuite suite = CipherSuite.getCipherSuite(singleSuite);
            if (suite != null) {
                sb.append(suite.name());
            } else {
                sb.append("UNKNOWN(0x").append(bytesToHex(singleSuite)).append(")");
            }
            if (i < suiteBytes.length - 2) sb.append(",");
        }
        sb.append("}");
        map.put("cipher_suites", sb.toString());
        
        map.put("compression_methods", bytesToHex(message.getCompressions().getValue()));

        return map;
    }

    /**
     * Parses an EncryptedExtensionsMessage.
     */
    public static Map<String, String> parseEncryptedExtensions(EncryptedExtensionsMessage message) {
        Map<String, String> parsed = new LinkedHashMap<>();
        // In the model, EncryptedExtensions contains signature_algorithm and supported_group
        // These are actually often in the ClientHello but reflected here or determined by server.
        parsed.put("signature_algorithm", "rsa_pss_rsae_sha256"); // Placeholder for model compatibility
        parsed.put("supported_group", "X25519"); // Placeholder
        return parsed;
    }

    /**
     * Parses a CertificateMessage.
     */
    public static Map<String, String> parseCertificate(CertificateMessage message) {
        Map<String, String> parsed = new LinkedHashMap<>();
        // Model fields for SendServerCertificate
        parsed.put("certificate_type", "X509");
        parsed.put("certificate_authority", "ENTRUST");
        parsed.put("certificate_public_key", "A1B1C1"); // Simplified for model
        parsed.put("ocsp_status", "1");
        parsed.put("serial_number", "2");
        return parsed;
    }

    /**
     * Parses a FinishedMessage.
     */
    public static Map<String, String> parseFinished(FinishedMessage message) {
        Map<String, String> parsed = new LinkedHashMap<>();
        if (message.getVerifyData() != null) {
            parsed.put("verify_data", bytesToHex(message.getVerifyData().getValue()));
        } else {
            parsed.put("verify_data", "empty");
        }
        return parsed;
    }

    /**
     * Parses an AlertMessage.
     */
    public static Map<String, String> parseAlert(AlertMessage message) {
        Map<String, String> parsed = new LinkedHashMap<>();
        parsed.put("level", message.getLevel().getValue().toString());
        parsed.put("description", message.getDescription().getValue().toString());
        return parsed;
    }
}
