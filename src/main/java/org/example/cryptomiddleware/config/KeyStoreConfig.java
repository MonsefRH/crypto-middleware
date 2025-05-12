package org.example.cryptomiddleware.config;


import org.example.cryptomiddleware.keystore.KeyStoreManager;
import org.example.cryptomiddleware.keystore.Pkcs11KeyStoreManager;
import org.example.cryptomiddleware.keystore.Pkcs12KeyStoreManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeyStoreConfig {

    @Bean
    public Pkcs11KeyStoreManager pkcs11KeyStoreManager() {
        return new Pkcs11KeyStoreManager();
    }

    @Bean
    public Pkcs12KeyStoreManager pkcs12KeyStoreManager() {
        return new Pkcs12KeyStoreManager();
    }
}
