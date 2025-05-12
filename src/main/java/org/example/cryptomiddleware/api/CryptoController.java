package org.example.cryptomiddleware.api;

import org.example.cryptomiddleware.keystore.Pkcs11KeyStoreManager;
import org.example.cryptomiddleware.keystore.Pkcs12KeyStoreManager;
import org.example.cryptomiddleware.pki.CertificateGenerator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.*;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/crypto")
@Tag(name = "Crypto API", description = "APIs for cryptographic operations and PKI")
public class CryptoController {
    private static final Logger LOGGER = Logger.getLogger(CryptoController.class.getName());

    private final Pkcs11KeyStoreManager pkcs11KeyStoreManager;
    private final Pkcs12KeyStoreManager pkcs12KeyStoreManager;

    public CryptoController(Pkcs11KeyStoreManager pkcs11KeyStoreManager, Pkcs12KeyStoreManager pkcs12KeyStoreManager) {
        this.pkcs11KeyStoreManager = pkcs11KeyStoreManager;
        this.pkcs12KeyStoreManager = pkcs12KeyStoreManager;
    }

    @PostMapping("/initialize")
    @Operation(summary = "Initialize keystore", description = "Initialize PKCS#11 or PKCS#12 keystore")
    public String initialize(@RequestParam String type, @RequestParam String configPath, @RequestParam String password) throws Exception {
        LOGGER.info("Received parameters: type=" + type + ", configPath=" + configPath );
        try {
            if ("pkcs11".equalsIgnoreCase(type)) {
                pkcs11KeyStoreManager.initialize(configPath, password);
                return "Keystore initialized: pkcs11";
            } else if ("pkcs12".equalsIgnoreCase(type)) {
                pkcs12KeyStoreManager.initialize(configPath, password);
                return "Keystore initialized: pkcs12";
            } else {
                throw new IllegalArgumentException("Unsupported keystore type: " + type);
            }
        } catch (Exception e) {
            LOGGER.severe("Initialization failed: " + e.getMessage());
            throw new RuntimeException("Initialization failed: " + e.getMessage(), e);
        }
    }

    @PostMapping("/generateKeyPair")
    @Operation(summary = "Generate key pair and certificate", description = "Generate a key pair and self-signed certificate")
    public String generateKeyPair(@RequestParam String type, @RequestParam String configPath, @RequestParam String algorithm, @RequestParam int keySize, @RequestParam String alias) throws Exception {
        LOGGER.info("Generating key pair: type=" + type + ", configPath=" + configPath + ", algorithm=" + algorithm + ", keySize=" + keySize + ", alias=" + alias);
        try {
            KeyPair keyPair;
            if ("pkcs11".equalsIgnoreCase(type)) {
                if (!pkcs11KeyStoreManager.isInitialized()) {
                    throw new IllegalStateException("PKCS#11 keystore not initialized.");
                }
                keyPair = pkcs11KeyStoreManager.generateKeyPair(algorithm, keySize, alias);
                X509Certificate cert = CertificateGenerator.generateSelfSignedCertificate(keyPair, "CN=" + alias);
                pkcs11KeyStoreManager.storeCertificate(cert, alias);
            } else if ("pkcs12".equalsIgnoreCase(type)) {
                if (!pkcs12KeyStoreManager.isInitialized(configPath)) {
                    throw new IllegalStateException("PKCS#12 keystore not initialized for: " + configPath);
                }
                keyPair = pkcs12KeyStoreManager.generateKeyPair(configPath, algorithm, keySize, alias);
                // Certificate is already stored in Pkcs12KeyStoreManager.generateKeyPair
            } else {
                throw new IllegalArgumentException("Unsupported keystore type: " + type);
            }
            LOGGER.info("Key pair and certificate generated for alias: " + alias + " in keystore: " + configPath);
            return "Key pair and certificate generated for alias: " + alias;
        } catch (Exception e) {
            LOGGER.severe("Key pair generation failed: " + e.getMessage());
            throw e;
        }
    }

    @PostMapping("/sign")
    @Operation(summary = "Sign data", description = "Sign data using the private key associated with the alias")
    public byte[] sign(@RequestParam String type, @RequestParam String configPath, @RequestParam String alias, @RequestBody String data) throws Exception {
        LOGGER.info("Signing data: type=" + type + ", configPath=" + configPath + ", alias=" + alias);
        try {
            String Cleaned_data = data.replace("\"","") ;
            byte[] dataBytes = Cleaned_data.getBytes("UTF-8"); // Convert string to bytes
            System.out.print("data Bytes reveived " + Arrays.toString(dataBytes) + "\n") ;
            byte[] signature;
            if ("pkcs11".equalsIgnoreCase(type)) {
                if (!pkcs11KeyStoreManager.isInitialized()) {
                    throw new IllegalStateException("PKCS#11 keystore not initialized.");
                }
                signature = pkcs11KeyStoreManager.signData(alias, dataBytes);
            } else if ("pkcs12".equalsIgnoreCase(type)) {
                if (!pkcs12KeyStoreManager.isInitialized(configPath)) {
                    throw new IllegalStateException("PKCS#12 keystore not initialized for: " + configPath);
                }
                signature = pkcs12KeyStoreManager.signData(configPath, alias, dataBytes);
            } else {
                throw new IllegalArgumentException("Unsupported keystore type: " + type);
            }
            LOGGER.info("Data signed for alias: " + alias + " in keystore: " + configPath);
            return signature ;
        } catch (Exception e) {
            LOGGER.severe("Signing failed: " + e.getMessage());
            throw e;
        }
    }

    @PostMapping("/encrypt")
    @Operation(summary = "Encrypt data", description = "Encrypt data using the public key associated with the alias")
    public byte[] encrypt(@RequestParam String type, @RequestParam String configPath, @RequestParam String alias, @RequestBody byte[] data) throws Exception {
        LOGGER.info("Encrypting data: type=" + type + ", configPath=" + configPath + ", alias=" + alias);
        try {
            byte[] encrypted;
            if ("pkcs11".equalsIgnoreCase(type)) {
                if (!pkcs11KeyStoreManager.isInitialized()) {
                    throw new IllegalStateException("PKCS#11 keystore not initialized.");
                }
                encrypted = pkcs11KeyStoreManager.encryptData(alias, data);
            } else if ("pkcs12".equalsIgnoreCase(type)) {
                if (!pkcs12KeyStoreManager.isInitialized(configPath)) {
                    throw new IllegalStateException("PKCS#12 keystore not initialized for: " + configPath);
                }
                encrypted = pkcs12KeyStoreManager.encryptData(configPath, alias, data);
            } else {
                throw new IllegalArgumentException("Unsupported keystore type: " + type);
            }
            LOGGER.info("Data encrypted for alias: " + alias + " in keystore: " + configPath);
            System.out.print(Base64.getEncoder().encodeToString(encrypted));
            return encrypted;
        } catch (Exception e) {
            LOGGER.severe("Encryption failed: " + e.getMessage());
            throw e;
        }
    }

    @PostMapping("/decrypt")
    @Operation(summary = "Decrypt data", description = "Decrypt data using the private key associated with the alias")
    public byte[] decrypt(@RequestParam String type, @RequestParam String configPath, @RequestParam String alias, @RequestBody byte[] data) throws Exception {
        LOGGER.info("Decrypting data: type=" + type + ", configPath=" + configPath + ", alias=" + alias);
        try {
            byte[] decrypted;
            if ("pkcs11".equalsIgnoreCase(type)) {
                if (!pkcs11KeyStoreManager.isInitialized()) {
                    throw new IllegalStateException("PKCS#11 keystore not initialized.");
                }
                decrypted = pkcs11KeyStoreManager.decryptData(alias, data);
            } else if ("pkcs12".equalsIgnoreCase(type)) {
                if (!pkcs12KeyStoreManager.isInitialized(configPath)) {
                    throw new IllegalStateException("PKCS#12 keystore not initialized for: " + configPath);
                }
                decrypted = pkcs12KeyStoreManager.decryptData(configPath, alias, data);
            } else {
                throw new IllegalArgumentException("Unsupported keystore type: " + type);
            }
            LOGGER.info("Data decrypted for alias: " + alias + " in keystore: " + configPath);
            return decrypted;
        } catch (Exception e) {
            LOGGER.severe("Decryption failed: " + e.getMessage());
            throw e;
        }
    }
}