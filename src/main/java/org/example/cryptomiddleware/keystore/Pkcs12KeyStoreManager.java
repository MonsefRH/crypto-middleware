package org.example.cryptomiddleware.keystore;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.cryptomiddleware.pki.CertificateGenerator;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class Pkcs12KeyStoreManager implements KeyStoreManager {
    private static final Logger LOGGER = Logger.getLogger(Pkcs12KeyStoreManager.class.getName());
    private final Map<String, KeyStore> keyStores = new HashMap<>();
    private final Map<String, Boolean> initialized = new HashMap<>();
    private final Map<String, String> passwords = new HashMap<>(); // Store passwords for saving

    public Pkcs12KeyStoreManager() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public void initialize(String configPath, String password) throws Exception {
        try {
            File keystoreFile = new File(configPath);
            LOGGER.info("Loading PKCS#12 keystore from: " + keystoreFile.getAbsolutePath());
            if (!keystoreFile.exists()) {
                throw new IllegalArgumentException("Keystore file does not exist: " + configPath);
            }
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keyStore.load(fis, password.toCharArray());
            }
            keyStores.put(configPath, keyStore);
            initialized.put(configPath, true);
            passwords.put(configPath, password); // Store password for saving
            LOGGER.info("PKCS#12 keystore initialized successfully for: " + configPath + " with " + keyStore.size() + " entries.");
        } catch (Exception e) {
            LOGGER.severe("Failed to initialize PKCS#12 keystore: " + e.getMessage());
            throw new Exception("PKCS#12 initialization failed: " + e.getMessage(), e);
        }
    }

    @Override
    public KeyPair generateKeyPair(String algorithm, int keySize, String alias) throws Exception {
        throw new UnsupportedOperationException("Must specify configPath for multi-keystore operations");
    }

    public KeyPair generateKeyPair(String configPath, String algorithm, int keySize, String alias) throws Exception {
        checkInitialized(configPath);
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            keyPairGenerator.initialize(keySize);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Generate a self-signed certificate for the key pair
            X509Certificate cert = CertificateGenerator.generateSelfSignedCertificate(keyPair, "CN=" + alias);

            // Store the private key with the certificate chain
            KeyStore keyStore = keyStores.get(configPath);
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), null, new Certificate[]{cert});

            // Save the keystore to disk
            try (FileOutputStream fos = new FileOutputStream(configPath)) {
                keyStore.store(fos, passwords.get(configPath).toCharArray());
            }
            LOGGER.info("Key pair generated and stored for alias: " + alias + " in keystore: " + configPath);
            return keyPair;
        } catch (Exception e) {
            LOGGER.severe("Failed to generate key pair: " + e.getMessage());
            throw e;
        }
    }

    @Override
    public void storeCertificate(X509Certificate certificate, String alias) throws Exception {
        throw new UnsupportedOperationException("Must specify configPath for multi-keystore operations");
    }

    public void storeCertificate(String configPath, X509Certificate certificate, String alias) throws Exception {
        checkInitialized(configPath);
        try {
            KeyStore keyStore = keyStores.get(configPath);
            keyStore.setCertificateEntry(alias, certificate);

            // Save the keystore to disk
            try (FileOutputStream fos = new FileOutputStream(configPath)) {
                keyStore.store(fos, passwords.get(configPath).toCharArray());
            }
            LOGGER.info("Certificate stored for alias: " + alias + " in keystore: " + configPath);
        } catch (Exception e) {
            LOGGER.severe("Failed to store certificate: " + e.getMessage());
            throw e;
        }
    }

    @Override
    public byte[] signData(String alias, byte[] data) throws Exception {
        throw new UnsupportedOperationException("Must specify configPath for multi-keystore operations");
    }

    public byte[] signData(String configPath, String alias, byte[] data) throws Exception {
        checkInitialized(configPath);
        try {
            PrivateKey privateKey = (PrivateKey) keyStores.get(configPath).getKey(alias, null);
            if (privateKey == null) {
                throw new IllegalArgumentException("No private key found for alias: " + alias);
            }
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            byte[] signedData = signature.sign();
            LOGGER.info("Data signed for alias: " + alias + " in keystore: " + configPath);
            return signedData;
        } catch (Exception e) {
            LOGGER.severe("Failed to sign data: " + e.getMessage());
            throw e;
        }
    }

    @Override
    public byte[] encryptData(String alias, byte[] data) throws Exception {
        throw new UnsupportedOperationException("Must specify configPath for multi-keystore operations");
    }

    public byte[] encryptData(String configPath, String alias, byte[] data) throws Exception {
        checkInitialized(configPath);
        try {
            PublicKey publicKey = keyStores.get(configPath).getCertificate(alias).getPublicKey();
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedData = cipher.doFinal(data);
            LOGGER.info("Data encrypted for alias: " + alias + " in keystore: " + configPath);
            return encryptedData;
        } catch (Exception e) {
            LOGGER.severe("Failed to encrypt data: " + e.getMessage());
            throw e;
        }
    }

    @Override
    public byte[] decryptData(String alias, byte[] data) throws Exception {
        throw new UnsupportedOperationException("Must specify configPath for multi-keystore operations");
    }

    public byte[] decryptData(String configPath, String alias, byte[] data) throws Exception {
        checkInitialized(configPath);
        try {
            PrivateKey privateKey = (PrivateKey) keyStores.get(configPath).getKey(alias, null);
            if (privateKey == null) {
                throw new IllegalArgumentException("No private key found for alias: " + alias);
            }
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = cipher.doFinal(data);
            LOGGER.info("Data decrypted for alias: " + alias + " in keystore: " + configPath);
            return decryptedData;
        } catch (Exception e) {
            LOGGER.severe("Failed to decrypt data: " + e.getMessage());
            throw e;
        }
    }

    @Override
    public boolean isInitialized() {
        return !initialized.isEmpty();
    }

    public boolean isInitialized(String configPath) {
        return initialized.getOrDefault(configPath, false);
    }

    private void checkInitialized(String configPath) {
        if (!isInitialized(configPath)) {
            throw new IllegalStateException("PKCS#12 keystore not initialized for: " + configPath);
        }
    }
}