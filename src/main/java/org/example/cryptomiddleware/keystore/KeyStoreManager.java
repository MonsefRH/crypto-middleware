package org.example.cryptomiddleware.keystore;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public interface KeyStoreManager {
    void initialize(String configPath, String password) throws Exception;
    KeyPair generateKeyPair(String algorithm, int keySize, String alias) throws Exception;
    void storeCertificate(X509Certificate certificate, String alias) throws Exception;
    byte[] signData(String alias, byte[] data) throws Exception;
    byte[] encryptData(String alias, byte[] data) throws Exception;
    byte[] decryptData(String alias, byte[] data) throws Exception;
    boolean isInitialized();
}