package network;

import crypto.dsa.DSAKeyPair;
import crypto.dsa.DSASignature;
import crypto.hash.HashUtil;
import crypto.hmac.HmacUtil;
import crypto.rsa.RSAUtils;
import crypto.symmetric.SymmetricCryptoUtil;
import crypto.x509.X509CertificateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.*;

public class Client {

    private final Socket socket;
    private final Socket objectSocket;
    private DataInputStream in;
    private DataOutputStream out;
    private final RSAUtils.RSAEncryption rsaEncryption;
    private BigInteger serverPublicKey;
    private BigInteger serverModulus;
    private final DSAKeyPair.KeyPair dsaKeyPair;

    public Client(String host, int port) throws IOException {
        socket = new Socket(host, port);
        objectSocket = new Socket(host, 8889);
        rsaEncryption = new RSAUtils.RSAEncryption();
        dsaKeyPair = DSAKeyPair.generateKeyPair();
    }

    public void connect() throws Exception {
        ObjectInputStream inObject = new ObjectInputStream(objectSocket.getInputStream());
        ObjectOutputStream outObject = new ObjectOutputStream(objectSocket.getOutputStream());

        System.out.println("\n--- Certificate exchange... ---");

        // Generate client key pair
        KeyPair clientKeyPair = X509CertificateUtils.generateRSAKeyPair(2048);
        System.out.println("Client key pair generated.");

        // Receive CA certificate from server
        X509Certificate caCertificate = (X509Certificate) inObject.readObject();
        System.out.println("Received CA certificate from server.");

        // Receive server certificate
        X509Certificate serverCertificate = (X509Certificate) inObject.readObject();
        System.out.println("Received server certificate from server.");

        // Verify server certificate using CA certificate
        boolean isValidServerCert = X509CertificateUtils.verifyCertificate(serverCertificate, caCertificate);
        System.out.println("Server certificate is valid: " + isValidServerCert);

        if (isValidServerCert) {
            // Create CSR
            X500Name subject = new X500Name("CN=client,O=Campus,C=AT");
            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                    subject, clientKeyPair.getPublic());

            // Sign the CSR with client private key
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC")
                    .build(clientKeyPair.getPrivate());

            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            // Send CSR to server
            outObject.writeObject(csr.getEncoded());
            outObject.flush();
            System.out.println("Sent CSR to server.");

            // Receive signed client certificate
            X509Certificate clientCertificate = (X509Certificate) inObject.readObject();
            System.out.println("Received signed client certificate from server.");

            // Verify client certificate using CA certificate
            boolean isValidClientCert = X509CertificateUtils.verifyCertificate(clientCertificate, caCertificate);
            System.out.println("Client certificate is valid: " + isValidClientCert);

            // Send verification result to server
            outObject.writeBoolean(true);
            outObject.flush();

            if (isValidClientCert) {
                System.out.println("--- Done ---");

                // Save client certificate
                X509CertificateUtils.saveCertificate(clientCertificate, "client.crt");

                System.out.println("\n--- Preparing communication stream... ---");

                // Open new data streams for continuous communication
                in = new DataInputStream(socket.getInputStream());
                out = new DataOutputStream(socket.getOutputStream());

                // Receive server's RSA public key components
                serverPublicKey = new BigInteger(in.readUTF());
                serverModulus = new BigInteger(in.readUTF());
                System.out.println("Received server RSA public key");
                System.out.println("--- Done ---");
            }
        } else {
            System.out.println("Server certificate verification failed. Aborting.");
            // Close connection
            socket.close();
            objectSocket.close();
            return;
        }

        // If everything is verified, start CLI
        interactiveCLI();
    }

    private void interactiveCLI() throws Exception {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\n--- Crypto Menu ---");
            System.out.println("1. Send RSA Encrypted Message");
            System.out.println("2. Verify DSA Signature");
            System.out.println("3. Verify HMAC");
            System.out.println("4. Verify Hash");
            System.out.println("5. Send AES Encrypted Message");
            System.out.println("6. Exit");
            System.out.print("Choose an option: ");

            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            switch (choice) {
                case 1:
                    sendEncryptedMessageRSA(scanner);
                    break;
                case 2:
                    testDSASignature(scanner);
                    break;
                case 3:
                    testHMAC(scanner);
                    break;
                case 4:
                    testHash(scanner);
                    break;
                case 5:
                    sendEncryptedMessageAES(scanner);
                    break;
                case 6:
                    System.out.println("\n--- Exiting program... ---");
                    out.writeUTF("EXIT");
                    objectSocket.close();
                    socket.close();
                    return;
                default:
                    System.out.println("Invalid option. Try again.");
            }
        }
    }

    private void sendEncryptedMessageRSA(Scanner scanner) throws Exception {
        System.out.println("\n--- RSA Encryption ---");
        System.out.print("Enter message to encrypt: ");
        String message = scanner.nextLine();

        // Encrypt message
        byte[] encryptedMessage = rsaEncryption.encrypt(message.getBytes(), serverPublicKey, serverModulus);

        System.out.println("Sending request to server with...");
        System.out.println("Message: " + message);
        System.out.println("RSA Encrypted: " + new String(encryptedMessage));

        // Send RSA decrypt request
        out.writeUTF("DECRYPT_RSA");
        out.writeUTF(new BigInteger(1, encryptedMessage).toString());

        // Receive decrypted plaintext message
        String decryptedMessage = in.readUTF();
        System.out.println("\nMessage decrypted by server: " + decryptedMessage);
        System.out.println("--- Done ---");
    }

    private void testDSASignature(Scanner scanner) throws Exception {
        System.out.println("\n--- DSA Signature ---");
        System.out.print("Enter message to sign: ");
        String message = scanner.nextLine();

        // Sign message
        DSASignature.Signature signature = DSASignature.sign(
                message.getBytes(),
                dsaKeyPair
        );

        System.out.println("Sending request to server with...");
        System.out.println("Message: " + message);
        System.out.println("Public Key: " + dsaKeyPair.serializePublicKey());
        System.out.println("Signature: " + signature.serialize());

        // Send message, public key, and signature
        out.writeUTF("VERIFY_SIGNATURE");
        out.writeUTF(message);
        out.writeUTF(dsaKeyPair.serializePublicKey());
        out.writeUTF(signature.serialize());


        boolean SignatureVerified = in.readBoolean();
        System.out.println("\nSignature Verification Result: " + SignatureVerified);
        System.out.println("--- Done ---");
    }

    private void testHMAC(Scanner scanner) throws Exception {
        System.out.println("\n--- HMAC ---");
        System.out.print("Enter message to test hmac: ");
        String message = scanner.nextLine();

        System.out.print("Enter secret key: ");
        String secretKey = scanner.nextLine();

        // Generate HMAC_SHA256
        String hmacSha256 = new HmacUtil().generateHmac(message, secretKey, HmacUtil.HMAC_SHA256);

        System.out.println("Sending request to server with...");
        System.out.println("Message: " + message);
        System.out.println("HMAC: " + hmacSha256);
        System.out.println("Secrete Key: " + secretKey);

        // Encrypt secret using the previous RSA function
        byte[] encryptedKey = rsaEncryption.encrypt(secretKey.getBytes(), serverPublicKey, serverModulus);

        // Send message, hmac and the encrypted secret
        out.writeUTF("VERIFY_HMAC");
        out.writeUTF(message);
        out.writeUTF(hmacSha256);
        out.writeUTF(new BigInteger(1, encryptedKey).toString());

        boolean HmacVerified = in.readBoolean();
        System.out.println("\nHMAC Verification Result: " + HmacVerified);
        System.out.println("--- Done ---");
    }

    private void testHash(Scanner scanner) throws Exception {
        System.out.println("\n--- Hash ---");
        System.out.print("Enter message to test hash: ");
        String message = scanner.nextLine();

        // Display and select the desired hash function
        System.out.print(HashUtil.getAvailableAlgorithmsInfo());
        System.out.print("Select a hash function: ");
        int hashSelection = scanner.nextInt();
        String hash;
        HashUtil.HashAlgorithm algorithm;

        // Hash the message according to selection
        switch (hashSelection) {
            case 1:
                algorithm = HashUtil.HashAlgorithm.MD5;
                hash = HashUtil.hash(message, HashUtil.HashAlgorithm.MD5);
                break;
            case 2:
                algorithm = HashUtil.HashAlgorithm.SHA1;
                hash = HashUtil.hash(message, HashUtil.HashAlgorithm.SHA1);
                break;
            case 3:
                algorithm = HashUtil.HashAlgorithm.SHA256;
                hash = HashUtil.hash(message, HashUtil.HashAlgorithm.SHA256);
                break;
            case 4:
                algorithm = HashUtil.HashAlgorithm.SHA512;
                hash = HashUtil.hash(message, HashUtil.HashAlgorithm.SHA512);
                break;
            default:
                // Default to MD5
                System.out.println("Invalid option. Defaulting to MD5.");
                algorithm = HashUtil.HashAlgorithm.MD5;
                hash = HashUtil.hash(message, HashUtil.HashAlgorithm.MD5);
        }

        System.out.println("Sending request to server with...");
        System.out.println("Message: " + message);
        System.out.println("Hash: " + hash);
        System.out.println("Algorithm: " + algorithm.getAlgorithmName());

        // Encrypt used hash algorithm
        byte[] encryptedAlgorithmType = rsaEncryption.encrypt(algorithm.getAlgorithmName().getBytes(), serverPublicKey, serverModulus);

        // Send message, hash and encrypted hash type
        out.writeUTF("VERIFY_HASH");
        out.writeUTF(message);
        out.writeUTF(hash);
        out.writeUTF(new BigInteger(1, encryptedAlgorithmType).toString());

        boolean HashVerified = in.readBoolean();
        System.out.println("\nHashVerification Result: " + HashVerified);
        System.out.println("--- Done ---");
    }

    private void sendEncryptedMessageAES(Scanner scanner) throws Exception {
        System.out.println("\n--- AES ---");
        System.out.print("Enter message to encrypt: ");
        String message = scanner.nextLine();

        SecretKey key = SymmetricCryptoUtil.generateKey();

        // Encrypt message and send RSA encrypted AES secret
        byte[] encryptedMessage = SymmetricCryptoUtil.encrypt(message, key);
        byte[] encryptedKey = rsaEncryption.encrypt(SymmetricCryptoUtil.keyToString(key).getBytes(), serverPublicKey, serverModulus);

        System.out.println("Sending request to server with...");
        System.out.println("Message: " + message);
        System.out.println("AES Key: " + SymmetricCryptoUtil.keyToString(key));

        // Send encrypted message and secret key
        out.writeUTF("DECRYPT_AES");
        out.writeUTF(Base64.getEncoder().encodeToString(encryptedMessage));
        out.writeUTF(new BigInteger(1, encryptedKey).toString());

        String decryptedMessage = in.readUTF();
        System.out.println("\nServer decrypted message: " + decryptedMessage);
        System.out.println("--- Done ---");
    }

    public static void main(String[] args) {
        try {
            new Client("localhost", 8888).connect();
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }
}