package org.example.cryptomiddleware.keystore;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import java.util.logging.Logger;

public class Pkcs11KeyStoreManager implements KeyStoreManager {
    private static final Logger LOGGER = Logger.getLogger(Pkcs11KeyStoreManager.class.getName());
    private KeyStore keyStore;
    private boolean initialized = false;

    public Pkcs11KeyStoreManager() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public void initialize(String configPath, String password) throws Exception {
        try {
            // Create PKCS#11 configuration
            String config = "name = SoftHSM\n" +
                    "library = " + configPath + "\n" +
                    "slotListIndex = 0\n";
            ByteArrayInputStream configStream = new ByteArrayInputStream(config.getBytes(StandardCharsets.UTF_8));

            Class<?> sunPKCS11Class = Class.forName("sun.security.pkcs11.SunPKCS11");
            Constructor<?> constructor = sunPKCS11Class.getDeclaredConstructor(InputStream.class);
            constructor.setAccessible(true); // bypass private access
            Provider provider = (Provider) constructor.newInstance(configStream);

            Security.addProvider(provider);
            keyStore = KeyStore.getInstance("PKCS11", provider);
            keyStore.load(null, password.toCharArray());
            initialized = true;
            LOGGER.info("PKCS#11 keystore initialized successfully with library: " + configPath);
        } catch (Exception e) {
            LOGGER.severe("Failed to initialize PKCS#11 keystore: " + e.getMessage());
            throw new Exception("PKCS#11 initialization failed: " + e.getMessage(), e);
        }
    }

    @Override
    public KeyPair generateKeyPair(String algorithm, int keySize, String alias) throws Exception {
        checkInitialized();
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, keyStore.getProvider());
            keyPairGenerator.initialize(keySize);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            // Note: Actual key storage in HSM may require vendor-specific handling
            LOGGER.info("Key pair generated for alias: " + alias);
            return keyPair;
        } catch (Exception e) {
            LOGGER.severe("Failed to generate key pair: " + e.getMessage());
            throw new Exception("Key pair generation failed: " + e.getMessage(), e);
        }
    }

    @Override
    public void storeCertificate(X509Certificate certificate, String alias) throws Exception {
        checkInitialized();
        try {
            keyStore.setCertificateEntry(alias, certificate);
            LOGGER.info("Certificate stored for alias: " + alias);
        } catch (Exception e) {
            LOGGER.severe("Failed to store certificate: " + e.getMessage());
            throw new Exception("Certificate storage failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] signData(String alias, byte[] data) throws Exception {
        checkInitialized();
        try {
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            if (privateKey == null) {
                throw new IllegalArgumentException("No private key found for alias: " + alias);
            }
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            byte[] signedData = signature.sign();
            LOGGER.info("Data signed for alias: " + alias);
            return signedData;
        } catch (Exception e) {
            LOGGER.severe("Failed to sign data: " + e.getMessage());
            throw new Exception("Signing failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] encryptData(String alias, byte[] data) throws Exception {
        checkInitialized();
        try {
            PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedData = cipher.doFinal(data);
            LOGGER.info("Data encrypted for alias: " + alias);
            return encryptedData;
        } catch (Exception e) {
            LOGGER.severe("Failed to encrypt data: " + e.getMessage());
            throw new Exception("Encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decryptData(String alias, byte[] data) throws Exception {
        checkInitialized();
        try {
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            if (privateKey == null) {
                throw new IllegalArgumentException("No private key found for alias: " + alias);
            }
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = cipher.doFinal(data);
            LOGGER.info("Data decrypted for alias: " + alias);
            return decryptedData;
        } catch (Exception e) {
            LOGGER.severe("Failed to decrypt data: " + e.getMessage());
            throw new Exception("Decryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean isInitialized() {
        return initialized;
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("PKCS#11 keystore not initialized.");
        }
    }
}