package network;

import crypto.dsa.DSAKeyPair;
import crypto.dsa.DSASignature;
import crypto.hash.HashUtil;
import crypto.hmac.HmacUtil;
import crypto.rsa.RSAUtils;
import crypto.symmetric.SymmetricCryptoUtil;
import crypto.x509.X509CertificateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.security.*;

public class Server {
    private final ServerSocket serverSocket;
    private final ServerSocket objectServerSocket;
    private final RSAUtils.RSAEncryption rsaEncryption;
    private static KeyPair caKeyPair;
    private static X509Certificate caCertificate;
    private X509Certificate serverCertificate;

    public Server(int port) throws IOException {
        serverSocket = new ServerSocket(port);
        objectServerSocket = new ServerSocket(8889);
        rsaEncryption = new RSAUtils.RSAEncryption();
    }

    public void start() throws Exception {
        System.out.println("Server starting on port " + serverSocket.getLocalPort());

        try {
            // Generate CA key pair and certificate if they don't exist
            File caKeyFile = new File("ca-private.key");
            File caCertFile = new File("ca.crt");

            if (!caKeyFile.exists() || !caCertFile.exists()) {
                // Generate new CA key pair and certificate
                caKeyPair = X509CertificateUtils.generateRSAKeyPair(2048);
                caCertificate = X509CertificateUtils.generateSelfSignedCertificate(
                        "CN=FH,O=Campus,C=AT",
                        "CN=FH,O=Campus,C=AT",
                        3650, // 10 years validity
                        caKeyPair,
                        "SHA256withRSA"
                );

                // Save CA certificate (public)
                X509CertificateUtils.saveCertificate(caCertificate, "ca.crt");

                // Save CA private key (securely)
                try (FileOutputStream fos = new FileOutputStream("ca-private.key")) {
                    fos.write(caKeyPair.getPrivate().getEncoded());
                }

                System.out.println("New CA certificate and private key generated.");
            } else {
                // Load existing CA certificate and private key
                caCertificate = X509CertificateUtils.readCertificate("ca.crt");

                byte[] keyBytes;
                try (FileInputStream fis = new FileInputStream("ca-private.key")) {
                    keyBytes = fis.readAllBytes();
                }
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = kf.generatePrivate(spec);

                // We don't have the public key, but we can get it from the certificate
                PublicKey publicKey = caCertificate.getPublicKey();
                caKeyPair = new KeyPair(publicKey, privateKey);

                System.out.println("Loaded existing CA certificate and private key.");
            }

            // Generate server key pair
            KeyPair serverKeyPair = X509CertificateUtils.generateRSAKeyPair(2048);

            // Generate server certificate
            serverCertificate = X509CertificateUtils.generateSignedCertificate(
                    "CN=server,O=Campus,C=AT",
                    "CN=FH,O=Campus,C=AT",
                    365, // 1 year validity
                    serverKeyPair.getPublic(),
                    caKeyPair.getPrivate(),
                    "SHA256withRSA"
            );

            // Save server certificate
            X509CertificateUtils.saveCertificate(serverCertificate, "server.crt");

            System.out.println("Server certificate generated and signed by CA.");
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        while (true) {
            Socket clientSocket = serverSocket.accept();
            Socket objectClientSocket = objectServerSocket.accept();
            System.out.println("Client connected: " + clientSocket.getInetAddress());

            new Thread(() -> handleClient(clientSocket, objectClientSocket)).start();
        }
    }

    private void handleClient(Socket clientSocket, Socket objectClientSocket) {
        try {
            ObjectOutputStream outObject = new ObjectOutputStream(objectClientSocket.getOutputStream());
            ObjectInputStream inObject = new ObjectInputStream(objectClientSocket.getInputStream());

            // First, send CA certificate to client
            outObject.writeObject(caCertificate);
            outObject.flush();
            outObject.writeObject(serverCertificate);
            outObject.flush();

            // Receive CSR from client
            byte[] csrBytes = (byte[]) inObject.readObject();

            // Process CSR
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);
            JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr);

            // Extract information from CSR
            X500Name subject = csr.getSubject();
            PublicKey clientPublicKey = jcaCsr.getPublicKey();

            // Generate client certificate
            X509Certificate clientCertificate = X509CertificateUtils.generateSignedCertificate(
                    subject.toString(),
                    "CN=FH,O=Campus,C=AT",
                    365, // 1 year validity
                    clientPublicKey,
                    caKeyPair.getPrivate(),
                    "SHA256withRSA"
            );

            // Send signed client certificate back
            outObject.writeObject(clientCertificate);
            outObject.flush();

            DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

            // Send public key components to client
            out.writeUTF(rsaEncryption.getPublicKey().toString());
            out.writeUTF(rsaEncryption.getModulus().toString());

            while (true) {
                String operation = in.readUTF();

                switch (operation) {
                    case "DECRYPT_RSA":
                        String encryptedMessageStr = in.readUTF();
                        byte[] encryptedMessage = new BigInteger(encryptedMessageStr).toByteArray();
                        String decryptedMessage = new String(rsaEncryption.decrypt(encryptedMessage));
                        out.writeUTF(decryptedMessage);
                        break;
                    case "VERIFY_SIGNATURE":
                        // Receive message and public key
                        String receivedMessage = in.readUTF();
                        String receivedPublicKey = in.readUTF();
                        String receivedSignature = in.readUTF();

                        // Reconstruct key pair and signature
                        DSAKeyPair.KeyPair publicKeyPair = DSAKeyPair.KeyPair.deserializePublicKey(receivedPublicKey);
                        DSASignature.Signature signature = DSASignature.Signature.deserialize(receivedSignature);

                        // Verify signature
                        boolean isVerified = DSASignature.verify(
                                receivedMessage.getBytes(),
                                signature,
                                publicKeyPair
                        );

                        out.writeBoolean(isVerified);
                        break;
                    case "VERIFY_HMAC":
                        String hmacMessage = in.readUTF();
                        String hmac = in.readUTF();
                        String secretKey = in.readUTF();

                        byte[] encryptedKey = new BigInteger(secretKey).toByteArray();
                        String decryptedKey = new String(rsaEncryption.decrypt(encryptedKey));

                        boolean hmacValid = new HmacUtil().verifyHmac(hmacMessage, decryptedKey, hmac, HmacUtil.HMAC_SHA256);

                        out.writeBoolean(hmacValid);
                        break;
                    case "VERIFY_HASH":
                        String hashMessage = in.readUTF();
                        String hash = in.readUTF();
                        String  hashFunction = in.readUTF();

                        byte[] encryptedHashType = new BigInteger(hashFunction).toByteArray();
                        String decryptedHashType = new String(rsaEncryption.decrypt(encryptedHashType));

                        HashUtil.HashAlgorithm hashAlgorithm = HashUtil.HashAlgorithm.valueOf(decryptedHashType);

                        boolean hashValid = HashUtil.verify(hashMessage, hash, hashAlgorithm);

                        out.writeBoolean(hashValid);
                        break;
                    case "DECRYPT_AES":
                        String encrypted = in.readUTF();
                        String keyAES = in.readUTF();

                        byte[] encryptedKeyAES = new BigInteger(keyAES).toByteArray();
                        String decryptedKeyAES = new String(rsaEncryption.decrypt(encryptedKeyAES));
                        SecretKey aesKey = SymmetricCryptoUtil.stringToKey(decryptedKeyAES);

                        System.out.println("AES Key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

                        byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
                        String decryptedAES = SymmetricCryptoUtil.decrypt(encryptedBytes, aesKey);

                        out.writeUTF(decryptedAES);
                        break;
                    case "EXIT":
                        serverSocket.close();
                        objectServerSocket.close();
                        return;
                }
            }
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }

    public static void main(String[] args) {
        try {
            new Server(8888).start();
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }
}