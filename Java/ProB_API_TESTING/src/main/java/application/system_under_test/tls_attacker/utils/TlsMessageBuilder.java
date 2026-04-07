package application.system_under_test.tls_attacker.utils;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
// import de.rub.nds.tlsattacker.core.constants.NamedGroup;
// import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
// import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import java.security.*;
import java.security.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * Utility class for building TLS message components.
 */
public class TlsMessageBuilder {
    
    /**
     * Builds a SupportedVersionsExtensionMessage from YAML data.
     * @param data The YAML data containing supported_versions field
     * @return The built extension message
     */
    public static SupportedVersionsExtensionMessage buildSupportedVersions(Map<String, String> data) {
        SupportedVersionsExtensionMessage versions = new SupportedVersionsExtensionMessage();
        List<Byte> versionBytes = new ArrayList<>();

        String versionsStr = data.get("supported_versions");

        if (versionsStr != null && !versionsStr.isEmpty()) {
            versionsStr = versionsStr.replaceAll("[{}\\[\\]]", "");
            String[] versionArray = versionsStr.split(",");

            for (String version : versionArray) {
                ProtocolVersion pv = switch (version.trim()) {
                    case "TLS_1_3" -> ProtocolVersion.TLS13;
                    case "TLS_1_2" -> ProtocolVersion.TLS12;
                    case "TLS_1_1" -> ProtocolVersion.TLS11;
                    case "TLS_1_0" -> ProtocolVersion.TLS10;
                    default -> {
                        System.err.println("TLS version not recognized: " + version.trim());
                        yield null;
                    }
                };

                if (pv != null) {
                    byte[] raw = pv.getValue(); // 2-byte version value
                    versionBytes.add(raw[0]);
                    versionBytes.add(raw[1]);
                }
            }
        }

        if (versionBytes.isEmpty()) {
            byte[] fallback = ProtocolVersion.TLS13.getValue();
            versionBytes.add(fallback[0]);
            versionBytes.add(fallback[1]);
        }

        byte[] result = new byte[versionBytes.size()];
        for (int i = 0; i < versionBytes.size(); i++) {
            result[i] = versionBytes.get(i);
        }

        versions.setSupportedVersions(result);
        return versions;
    }

    /**
     * Builds a SignatureAndHashAlgorithmsExtensionMessage from YAML data.
     * @param data The YAML data
     * @return The built extension message
     */
    public static SignatureAndHashAlgorithmsExtensionMessage buildSignatureAlgorithms(Map<String, String> data) {
        SignatureAndHashAlgorithmsExtensionMessage sigHash = new SignatureAndHashAlgorithmsExtensionMessage();
        List<Byte> sigBytes = new ArrayList<>();

        String algoStr = data.get("signature_algorithms");

        if (algoStr != null && !algoStr.isEmpty()) {
            algoStr = algoStr.replaceAll("[{}\\[\\]]", "");
            String[] algoArray = algoStr.split(",");

            for (String algo : algoArray) {
                String trimmedAlgo = algo.trim();
                SignatureAndHashAlgorithm scheme = null;
                
                // Handle hex format (e.g., x0403)
                if (trimmedAlgo.startsWith("x") && trimmedAlgo.length() == 5) {
                    try {
                        int value = Integer.parseInt(trimmedAlgo.substring(1), 16);
                        scheme = switch (value) {
                            case 0x0403 -> SignatureAndHashAlgorithm.ECDSA_SHA256;
                            case 0x0804 -> SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256;
                            case 0x0805 -> SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384;
                            case 0x0806 -> SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512;
                            case 0x0401 -> SignatureAndHashAlgorithm.RSA_SHA256;
                            case 0x0501 -> SignatureAndHashAlgorithm.RSA_SHA384;
                            case 0x0601 -> SignatureAndHashAlgorithm.RSA_SHA512;
                            default -> null;
                        };
                    } catch (NumberFormatException e) {
                        System.err.println("Invalid hex signature algorithm: " + trimmedAlgo);
                    }
                } else {
                    // Handle string format
                    scheme = switch (trimmedAlgo) {
                        case "rsa_pss_rsae_sha512"     -> SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512;
                        case "rsa_pss_rsae_sha256"     -> SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256;
                        case "ecdsa_secp256r1_sha256"  -> SignatureAndHashAlgorithm.ECDSA_SHA256;
                        case "ecdsa_secp384r1_sha384"  -> SignatureAndHashAlgorithm.ECDSA_SHA384;
                        case "ed25519"                 -> SignatureAndHashAlgorithm.ED25519;
                        case "rsa_pkcs1_sha256", "rsa_pkcs1_sha25" -> SignatureAndHashAlgorithm.RSA_SHA256;

                        default -> null;
                    };
                }

                if (scheme != null) {
                    sigBytes.add((byte)scheme.getSignatureAlgorithm().ordinal());
                    sigBytes.add((byte)scheme.getHashAlgorithm().ordinal());
                } else {
                    System.err.println("Signature algorithm not recognized: " + trimmedAlgo);
                }
            }
        }

        if (sigBytes.isEmpty()) {
            SignatureAndHashAlgorithm defaultScheme = SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512;
            sigBytes.add((byte)defaultScheme.getSignatureAlgorithm().ordinal());
            sigBytes.add((byte)defaultScheme.getHashAlgorithm().ordinal());
        }

        byte[] result = new byte[sigBytes.size()];
        for (int i = 0; i < sigBytes.size(); i++) {
            result[i] = sigBytes.get(i);
        }

        sigHash.setSignatureAndHashAlgorithms(result);
        return sigHash;
    }




    private static byte[] encodePublicKey(NamedGroup group, PublicKey pubKey) {
        // Pour X25519 / X448 : getEncoded() renvoie déjà les octets bruts
        if (group == NamedGroup.ECDH_X25519 || group == NamedGroup.ECDH_X448) {
            return pubKey.getEncoded();
        }

        // Pour SECP256R1 / SECP384R1 : il faut extraire le point EC non compressé
        if (pubKey instanceof java.security.interfaces.ECPublicKey ecPub) {
            java.security.spec.ECPoint w = ecPub.getW();
            int fieldSize = ecPub.getParams().getCurve().getField().getFieldSize();
            int byteLen = (fieldSize + 7) / 8;

            byte[] xb = toFixedLength(w.getAffineX().toByteArray(), byteLen);
            byte[] yb = toFixedLength(w.getAffineY().toByteArray(), byteLen);

            byte[] uncompressed = new byte[1 + xb.length + yb.length];
            uncompressed[0] = 0x04; // format uncompressed
            System.arraycopy(xb, 0, uncompressed, 1, xb.length);
            System.arraycopy(yb, 0, uncompressed, 1 + xb.length, yb.length);

            return uncompressed;
        }

        throw new IllegalArgumentException("Unsupported public key encoding for group: " + group);
    }

    private static byte[] toFixedLength(byte[] src, int len) {
        if (src.length == len) return src;
        byte[] dst = new byte[len];
        if (src.length > len) {
            System.arraycopy(src, src.length - len, dst, 0, len);
        } else {
            System.arraycopy(src, 0, dst, len - src.length, src.length);
        }
        return dst;
    }

    /**
     * Allows you to retrieve the private key associated with a group for calculating the shared secret.
     */
    public static PrivateKey getPrivateKey(NamedGroup group) {
        return ephemeralPrivateKeys.get(group);
    }


    public static KeyPair generateKeyPair(NamedGroup group) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg;
        switch (group) {
            case ECDH_X25519:
                kpg = KeyPairGenerator.getInstance("X25519", "BC");
                break;
            case ECDH_X448:
                kpg = KeyPairGenerator.getInstance("X448", "BC");
                break;
            case SECP256R1:
                kpg = KeyPairGenerator.getInstance("EC", "BC");
                kpg.initialize(new ECGenParameterSpec("secp256r1"));
                break;
            case SECP384R1:
                kpg = KeyPairGenerator.getInstance("EC", "BC");
                kpg.initialize(new ECGenParameterSpec("secp384r1"));
                break;
            default:
                throw new IllegalArgumentException("Unsupported group: " + group);
        }
        return kpg.generateKeyPair();
    }


    private static final Map<NamedGroup, PrivateKey> ephemeralPrivateKeys = new HashMap<>();
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    /**
     * Builds a KeyShareExtensionMessage from YAML data.
     * @param data The YAML data
     * @return The built extension message
     */
    public static KeyShareExtensionMessage buildKeyShare(Map<String, String> data) throws Exception {
        KeyShareExtensionMessage keyShare = new KeyShareExtensionMessage();
        List<KeyShareEntry> entries = new ArrayList<>();

        // read group from yaml
        String groupStr = data.getOrDefault("key_share_group", "x25519").trim().toLowerCase();

        NamedGroup group = switch (groupStr) {
            case "x25519"    -> NamedGroup.ECDH_X25519;
            case "x448"      -> NamedGroup.ECDH_X448;
            case "secp256r1" -> NamedGroup.SECP256R1;
            case "secp384r1" -> NamedGroup.SECP384R1;
            default -> {
                System.err.println("Unknown group: " + groupStr + " — fallback to X25519");
                yield NamedGroup.ECDH_X25519;
            }
        };

        // Genrate ephemeral private/public key
        KeyPair kp = generateKeyPair(group);
        ephemeralPrivateKeys.put(group, kp.getPrivate());

        // Encode the public key in the format expected by TLS
        byte[] encodedPubKey = encodePublicKey(group, kp.getPublic());

        // Create KeyShare entry
        KeyShareEntry entry = new KeyShareEntry();
        entry.setGroupConfig(group);
        entry.setPublicKey(encodedPubKey);

        entries.add(entry);
        keyShare.setKeyShareList(entries);

        return keyShare;
    }


    /**
     * Builds a list of CipherSuite from YAML data.
     * @param data The YAML data
     * @return List of cipher suites
     */
    public static List<CipherSuite> buildCipherSuites(Map<String, String> data) {
        List<CipherSuite> suites = new ArrayList<>();
        String cipherSuitesStr = data.get("cipher_suites");
        
        System.out.println("DEBUG: cipher_suites from YAML: " + cipherSuitesStr);
        
        if (cipherSuitesStr != null && !cipherSuitesStr.isEmpty()) {
            // Remove brackets and split by comma
            cipherSuitesStr = cipherSuitesStr.replaceAll("[{}\\[\\]]", "");
            String[] suiteArray = cipherSuitesStr.split(",");
            
            for (String suite : suiteArray) {
                String trimmedSuite = suite.trim();
                CipherSuite cs = switch (trimmedSuite) {
                    case "TLS_AES_128_GCM_SHA256" -> CipherSuite.TLS_AES_128_GCM_SHA256;
                    case "TLS_AES_256_GCM_SHA384" -> CipherSuite.TLS_AES_256_GCM_SHA384;
                    case "TLS_CHACHA20_POLY1305_SHA256" -> CipherSuite.TLS_CHACHA20_POLY1305_SHA256;
                    case "TLS_AES_128_CCM_SHA256" -> CipherSuite.TLS_AES_128_CCM_SHA256;
                    case "TLS_AES_128_CCM_8_SHA256" -> CipherSuite.TLS_AES_128_CCM_8_SHA256;
                    
                    default -> {
                        System.err.println("Cipher suite not recognized: " + trimmedSuite);
                        yield null;
                    }
                };
                if (cs != null) {
                    suites.add(cs);
                    System.out.println("DEBUG: Added cipher suite: " + cs.name());
                }
            }
        }
        
        // Fallback to default if no valid suites found
        if (suites.isEmpty()) {
            System.out.println("DEBUG: No cipher suites parsed, adding default");
            suites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        }
        
        System.out.println("DEBUG: Total cipher suites: " + suites.size());
        return suites;
    }

    /**
     * Builds an EllipticCurvesExtensionMessage (supported groups) from YAML data.
     * @param data The YAML data
     * @return The built extension message
     */
    public static EllipticCurvesExtensionMessage buildSupportedGroupsExtension(Map<String, String> data) {
        EllipticCurvesExtensionMessage groupsExt = new EllipticCurvesExtensionMessage();
        List<NamedGroup> groups = buildNamedGroups(data);
        
        // Convert NamedGroup list to byte array
        List<Byte> groupBytes = new ArrayList<>();
        for (NamedGroup group : groups) {
            byte[] groupValue = group.getValue();
            groupBytes.add(groupValue[0]);
            groupBytes.add(groupValue[1]);
        }
        
        byte[] result = new byte[groupBytes.size()];
        for (int i = 0; i < groupBytes.size(); i++) {
            result[i] = groupBytes.get(i);
        }
        
        groupsExt.setSupportedGroups(result);
        return groupsExt;
    }

    /**
     * Builds a list of NamedGroup from YAML data.
     * @param data The YAML data
     * @return List of named groups
     */
    public static List<NamedGroup> buildNamedGroups(Map<String, String> data) {
        List<NamedGroup> groups = new ArrayList<>();
        String groupsStr = data.get("supported_groups");
        
        System.out.println("DEBUG: supported_groups from YAML: " + groupsStr);
        
        if (groupsStr != null && !groupsStr.isEmpty()) {
            // Remove brackets and split by comma
            groupsStr = groupsStr.replaceAll("[{}\\[\\]]", "");
            String[] groupArray = groupsStr.split(",");
            
            for (String group : groupArray) {
                String trimmedGroup = group.trim();
                NamedGroup ng = switch (trimmedGroup) {
                    case "x001d" -> NamedGroup.ECDH_X25519;
                    case "x0017" -> NamedGroup.SECP256R1;
                    case "x0018" -> NamedGroup.SECP384R1;
                    case "x0019" -> NamedGroup.SECP521R1;
                    case "x001e" -> NamedGroup.ECDH_X448;
                    case "x0100" -> NamedGroup.FFDHE2048;
                    case "x0101" -> NamedGroup.FFDHE3072;
                    case "X25519" -> NamedGroup.ECDH_X25519;
                    case "secp256r1" -> NamedGroup.SECP256R1;
                    case "secp384r1" -> NamedGroup.SECP384R1;
                    case "secp521r1" -> NamedGroup.SECP521R1;
                    default -> {
                        System.err.println("Named group not recognized: " + trimmedGroup);
                        yield null;
                    }
                };
                if (ng != null) {
                    groups.add(ng);
                    System.out.println("DEBUG: Added named group: " + ng.name());
                }
            }
        }
        
        // Fallback to default if no valid groups found
        if (groups.isEmpty()) {
            System.out.println("DEBUG: No named groups parsed, adding default");
            groups.add(NamedGroup.ECDH_X25519);
            groups.add(NamedGroup.SECP256R1);
        }
        
        System.out.println("DEBUG: Total named groups: " + groups.size());
        return groups;
    }

    /**
     * Configures TLS-Attacker Config from YAML data BEFORE creating ClientHello.
     * This ensures cipher suites and other settings are applied correctly.
     * 
     * @param clientHelloMap The YAML data containing client hello fields
     * @param config The TLS configuration to update
     */
    public static void configureFromYaml(Map<String, String> clientHelloMap, Config config) {
        // Build and set Cipher Suites FIRST
        List<CipherSuite> suites = buildCipherSuites(clientHelloMap);
        config.setDefaultClientSupportedCipherSuites(suites);
        
        // Build and set Supported Groups
        List<NamedGroup> groups = buildNamedGroups(clientHelloMap);
        config.setDefaultClientNamedGroups(groups);
        
        System.out.println("Pre-configured " + suites.size() + " cipher suites in Config:");
        for (CipherSuite suite : suites) {
            System.out.println("  - " + suite.name() + " (0x" + 
                String.format("%04X", (suite.getByteValue()[0] & 0xFF) << 8 | (suite.getByteValue()[1] & 0xFF)) + ")");
        }
    }

    /**
     * Adds extensions to an already created ClientHello message.
     * 
     * @param clientHelloMap The YAML data containing client hello fields
     * @param clientHello The ClientHelloMessage to add extensions to
     */
    public static void addExtensionsToClientHello(Map<String, String> clientHelloMap, ClientHelloMessage clientHello) {
        // Clear any existing extensions to avoid duplicates
        clientHello.getExtensions().clear();
        
        // Build and add Supported Versions extension
        SupportedVersionsExtensionMessage versions = buildSupportedVersions(clientHelloMap);
        clientHello.addExtension(versions);

        // Build and add Signature Algorithms extension
        SignatureAndHashAlgorithmsExtensionMessage sigHash = buildSignatureAlgorithms(clientHelloMap);
        clientHello.addExtension(sigHash);

        // Build and add Supported Groups extension (REQUIRED for TLS 1.3)
        EllipticCurvesExtensionMessage supportedGroups = buildSupportedGroupsExtension(clientHelloMap);
        clientHello.addExtension(supportedGroups);

        // Build and add Key Share extension
        KeyShareExtensionMessage keyShare = null;
        try {
            keyShare = buildKeyShare(clientHelloMap);
        } catch (Exception e) {
            e.printStackTrace();
        }
        clientHello.addExtension(keyShare);

        System.out.println("Added " + clientHello.getExtensions().size() + " extensions to ClientHello");
        for (int i = 0; i < clientHello.getExtensions().size(); i++) {
            System.out.println("  Extension " + i + ": " + clientHello.getExtensions().get(i).getClass().getSimpleName());
        }
    }


    /**
     * Builds a ClientHelloMessage from YAML data.
     * @param clientHelloMap The YAML data containing client hello fields
     * @param clientHello The ClientHelloMessage to build
     * @param config The TLS configuration
     */
    public static void buildClientHello(Map<String, String> clientHelloMap ,ClientHelloMessage clientHello, Config config) {
        // Clear any existing extensions to avoid duplicates
        clientHello.getExtensions().clear();
        
        // Build and add Supported Versions extension
        SupportedVersionsExtensionMessage versions = buildSupportedVersions(clientHelloMap);
        clientHello.addExtension(versions);

        // Build and add Signature Algorithms extension
        SignatureAndHashAlgorithmsExtensionMessage sigHash = buildSignatureAlgorithms(clientHelloMap);
        clientHello.addExtension(sigHash);

        // Build and add Supported Groups extension (REQUIRED for TLS 1.3)
        EllipticCurvesExtensionMessage supportedGroups = buildSupportedGroupsExtension(clientHelloMap);
        clientHello.addExtension(supportedGroups);

        // Build and add Key Share extension
        KeyShareExtensionMessage keyShare = null;
        try {
            keyShare = buildKeyShare(clientHelloMap);
        } catch (Exception e) {
            e.printStackTrace();
        }
        clientHello.addExtension(keyShare);

        // Build and set Cipher Suites
        List<CipherSuite> suites = buildCipherSuites(clientHelloMap);
        config.setDefaultClientSupportedCipherSuites(suites);
        
        // IMPORTANT: Set cipher suites in the config BEFORE creating the ClientHello
        // TLS-Attacker will use the config to populate the message
        
        System.out.println("Configured " + suites.size() + " cipher suites:");
        for (CipherSuite suite : suites) {
            System.out.println("  - " + suite.name() + " (0x" + 
                String.format("%04X", (suite.getByteValue()[0] & 0xFF) << 8 | (suite.getByteValue()[1] & 0xFF)) + ")");
        }

        // Build and set Supported Groups
        List<NamedGroup> groups = buildNamedGroups(clientHelloMap);
        config.setDefaultClientNamedGroups(groups);

        System.out.println("ClientHello built with " + clientHello.getExtensions().size() + " extensions");
        for (int i = 0; i < clientHello.getExtensions().size(); i++) {
            System.out.println("  Extension " + i + ": " + clientHello.getExtensions().get(i).getClass().getSimpleName());
        }
    }


    /**
     * Builds a ServerHelloMessage from YAML data.
     * @param serverHelloMap The YAML data containing server hello fields
     * @param serverHello The ServerHelloMessage to build
     * @param config The TLS configuration
     */
    public static void buildServerHello(Map<String, String> serverHelloMap, ServerHelloMessage serverHello, Config config){
        // TODO: Implement server hello message building logic
        throw new UnsupportedOperationException("ServerHello message building not yet implemented");
        

    }

}