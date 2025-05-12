package org.example.cryptomiddleware.pki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Logger;

public class CertificateGenerator {
    private static final Logger LOGGER = Logger.getLogger(CertificateGenerator.class.getName());

    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDN) throws Exception {
        try {
            long now = System.currentTimeMillis();
            Date startDate = new Date(now);
            Date endDate = new Date(now + 365 * 24 * 60 * 60 * 1000L); // 1 year validity

            X500Name subject = new X500Name(subjectDN);
            BigInteger serial = BigInteger.valueOf(now);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    subject, serial, startDate, endDate, subject, keyPair.getPublic());

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                    .build(keyPair.getPrivate());

            X509CertificateHolder certHolder = certBuilder.build(signer);
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
            LOGGER.info("Self-signed certificate generated for subject: " + subjectDN);
            return certificate;
        } catch (Exception e) {
            LOGGER.severe("Failed to generate certificate: " + e.getMessage());
            throw e;
        }
    }
}
