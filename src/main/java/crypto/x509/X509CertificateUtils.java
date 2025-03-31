package crypto.x509;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class X509CertificateUtils {

    static {
        // Add Bouncy Castle Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generates a self-signed X.509v3 certificate.
     *
     * @param subjectDN    Subject Distinguished Name
     * @param issuerDN     Issuer Distinguished Name
     * @param validityDays Validity period in days
     * @param keyPair      Key pair for certificate
     * @param algorithm    Signature algorithm (e.g., "SHA256withRSA")
     * @return Generated X.509 certificate
     */
    public static X509Certificate generateSelfSignedCertificate(
            String subjectDN,
            String issuerDN,
            int validityDays,
            KeyPair keyPair,
            String algorithm) throws GeneralSecurityException, OperatorCreationException, IOException {

        // Current time minus 1 day to avoid time zone issues
        Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date endDate = new Date(System.currentTimeMillis() + (long) validityDays * 24 * 60 * 60 * 1000);

        // Serial number
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        // Create certificate builder
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                new X500Name(issuerDN),
                serialNumber,
                startDate,
                endDate,
                new X500Name(subjectDN),
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        );

        // Add extensions
        certBuilder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(true));

        certBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        certBuilder.addExtension(
                Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(new KeyPurposeId[]{
                        KeyPurposeId.id_kp_serverAuth,
                        KeyPurposeId.id_kp_clientAuth
                }));

        // Sign the certificate
        ContentSigner signer = new JcaContentSignerBuilder(algorithm)
                .setProvider("BC")
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);

        // Convert to X509Certificate
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);
    }

    /**
     * Generates a certificate signed by a CA.
     *
     * @param subjectDN    Subject Distinguished Name
     * @param issuerDN     Issuer Distinguished Name
     * @param validityDays Validity period in days
     * @param publicKey    Public key for the subject
     * @param caPrivateKey CA private key for signing
     * @param algorithm    Signature algorithm (e.g., "SHA256withRSA")
     * @return Generated X.509 certificate
     */
    public static X509Certificate generateSignedCertificate(
            String subjectDN,
            String issuerDN,
            int validityDays,
            PublicKey publicKey,
            PrivateKey caPrivateKey,
            String algorithm) throws GeneralSecurityException, OperatorCreationException, IOException {

        // Current time minus 1 day to avoid time zone issues
        Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date endDate = new Date(System.currentTimeMillis() + (long) validityDays * 24 * 60 * 60 * 1000);

        // Serial number
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        // Create certificate builder
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                new X500Name(issuerDN),
                serialNumber,
                startDate,
                endDate,
                new X500Name(subjectDN),
                SubjectPublicKeyInfo.getInstance(publicKey.getEncoded())
        );

        // Add extensions
        certBuilder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(false));

        certBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        certBuilder.addExtension(
                Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(new KeyPurposeId[]{
                        KeyPurposeId.id_kp_serverAuth,
                        KeyPurposeId.id_kp_clientAuth
                }));

        // Sign the certificate
        ContentSigner signer = new JcaContentSignerBuilder(algorithm)
                .setProvider("BC")
                .build(caPrivateKey);

        X509CertificateHolder certHolder = certBuilder.build(signer);

        // Convert to X509Certificate
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);
    }

    /**
     * Reads an X.509 certificate from a file.
     *
     * @param filePath Path to the certificate file
     * @return X.509 certificate
     */
    public static X509Certificate readCertificate(String filePath) throws CertificateException, IOException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    /**
     * Verifies if a certificate is signed by a CA.
     *
     * @param certificate   Certificate to verify
     * @param caCertificate CA certificate
     * @return true if verified, false otherwise
     */
    public static boolean verifyCertificate(X509Certificate certificate, X509Certificate caCertificate) {
        try {
            certificate.verify(caCertificate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Saves a certificate to a file in PEM format.
     *
     * @param certificate Certificate to save
     * @param filePath    Path to save the certificate
     */
    public static void saveCertificate(X509Certificate certificate, String filePath) throws IOException, CertificateException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            fos.write(java.util.Base64.getEncoder().encode(certificate.getEncoded()));
            fos.write("\n-----END CERTIFICATE-----".getBytes());
        }
    }

    /**
     * Generates a new RSA key pair.
     *
     * @param keySize Key size in bits (e.g., 2048)
     * @return Generated key pair
     */
    public static KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }
}