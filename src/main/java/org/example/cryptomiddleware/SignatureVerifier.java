package org.example.cryptomiddleware;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

public class SignatureVerifier {
    public static boolean verifyBase64Signature(String certPath, byte[] originalData, String base64Signature) throws Exception {
        // Decode Base64 signature
        byte[] signature = Base64.getDecoder().decode(base64Signature);

        // Load the certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(Files.newInputStream(Paths.get(certPath)));

        // Get public key from certificate
        PublicKey publicKey = cert.getPublicKey();

        // Create signature object
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(originalData);

        // Verify signature
        return sig.verify(signature);
    }

    public static void main(String[] args) {
        try {
            String base64Signature = "your-base64-signature";
            byte[] originalData = Files.readAllBytes(Paths.get("path/to/data.txt"));
            boolean isVerified = verifyBase64Signature("path/to/cert.pem", originalData, base64Signature);
            System.out.println("Signature Verification: " + isVerified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
