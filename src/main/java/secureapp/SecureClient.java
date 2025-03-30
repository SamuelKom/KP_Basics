package secureapp;

import crypto.dsa.DSAKeyPair;
import crypto.dsa.DSASignature;
import crypto.hash.HashUtil;
import crypto.hmac.HmacUtil;
import crypto.symmetric.SymmetricCryptoUtil;

import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.*;

public class SecureClient {
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private CryptoUtils.RSAEncryption rsaEncryption;
    private BigInteger serverPublicKey;
    private BigInteger serverModulus;
    private DSAKeyPair.KeyPair dsaKeyPair;

    public SecureClient(String host, int port) throws IOException {
        socket = new Socket(host, port);
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());
        rsaEncryption = new CryptoUtils.RSAEncryption();
        dsaKeyPair = DSAKeyPair.generateKeyPair();
    }

    public void connect() throws Exception {
        // Receive server's public key components
        serverPublicKey = new BigInteger(in.readUTF());
        serverModulus = new BigInteger(in.readUTF());

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
                    out.writeUTF("EXIT");
                    in.close();
                    out.close();
                    socket.close();
                    return;
                default:
                    System.out.println("Invalid option. Try again.");
            }
        }
    }

    private void sendEncryptedMessageRSA(Scanner scanner) throws Exception {
        System.out.print("Enter message to encrypt: ");
        String message = scanner.nextLine();

        // Encrypt message
        byte[] encryptedMessage = rsaEncryption.encrypt(message.getBytes(), serverPublicKey, serverModulus);

        System.out.println("Sending request to server with...");
        System.out.println("Message: " + message);
        System.out.println("RSA Encrypted: " + new String(encryptedMessage));

        // Send encryption request
        out.writeUTF("DECRYPT_RSA");
        out.writeUTF(new BigInteger(1, encryptedMessage).toString());

        // Receive decrypted message
        String decryptedMessage = in.readUTF();
        System.out.println("Message decrypted by server: " + decryptedMessage);
    }

    private void testDSASignature(Scanner scanner) throws Exception {
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

        out.writeUTF("VERIFY_SIGNATURE");
        // Send message, public key, and signature
        out.writeUTF(message);
        out.writeUTF(dsaKeyPair.serializePublicKey());
        out.writeUTF(signature.serialize());


        boolean SignatureVerified = in.readBoolean();
        System.out.println("Signature Verification Result: " + SignatureVerified);
    }

    private void testHMAC(Scanner scanner) throws Exception {
        System.out.print("Enter message to test hmac: ");
        String message = scanner.nextLine();

        System.out.print("Enter secret key: ");
        String secretKey = scanner.nextLine();

        String hmacSha256 = new HmacUtil().generateHmac(message, secretKey, HmacUtil.HMAC_SHA256);

        System.out.println("Sending request to server with...");
        System.out.println("Message: " + message);
        System.out.println("HMAC: " + hmacSha256);
        System.out.println("Secrete Key: " + secretKey);

        // Encrypt secret
        byte[] encryptedKey = rsaEncryption.encrypt(secretKey.getBytes(), serverPublicKey, serverModulus);

        out.writeUTF("VERIFY_HMAC");
        out.writeUTF(message);
        out.writeUTF(hmacSha256);
        out.writeUTF(new BigInteger(1, encryptedKey).toString());

        boolean HmacVerified = in.readBoolean();
        System.out.println("HMAC Verification Result: " + HmacVerified);
    }

    private void testHash(Scanner scanner) throws Exception {
        System.out.print("Enter message to test hash: ");
        String message = scanner.nextLine();

        System.out.print(HashUtil.getAvailableAlgorithmsInfo());
        System.out.print("Select a hash function: ");
        int hashSelection = scanner.nextInt();
        String hash = "";
        HashUtil.HashAlgorithm algorithm;

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
                System.out.println("Invalid option. Defaulting to MD5.");
                algorithm = HashUtil.HashAlgorithm.MD5;
                hash = HashUtil.hash(message, HashUtil.HashAlgorithm.MD5);
        }

        System.out.println("Sending request to server with...");
        System.out.println("Message: " + message);
        System.out.println("Hash: " + hash);
        System.out.println("Algorithm: " + algorithm.getAlgorithmName());

        // Encrypt secret
        byte[] encryptedAlgorithmType = rsaEncryption.encrypt(algorithm.getAlgorithmName().getBytes(), serverPublicKey, serverModulus);

        out.writeUTF("VERIFY_HASH");
        out.writeUTF(message);
        out.writeUTF(hash);
        out.writeUTF(new BigInteger(1, encryptedAlgorithmType).toString());

        boolean HashVerified = in.readBoolean();
        System.out.println("HashVerification Result: " + HashVerified);
    }

    private void sendEncryptedMessageAES(Scanner scanner) throws Exception {
        System.out.print("Enter message to encrypt: ");
        String message = scanner.nextLine();

        SecretKey key = SymmetricCryptoUtil.generateKey();

        // Encrypt message
        byte[] encryptedMessage = SymmetricCryptoUtil.encrypt(message, key);
        byte[] encryptedKey = rsaEncryption.encrypt(SymmetricCryptoUtil.keyToString(key).getBytes(), serverPublicKey, serverModulus);

        System.out.println("Sending request to server with...");
        System.out.println("Message: " + message);
        System.out.println("AES Key: " + SymmetricCryptoUtil.keyToString(key));

        // Send encryption request
        out.writeUTF("DECRYPT_AES");
        out.writeUTF(Base64.getEncoder().encodeToString(encryptedMessage));
        out.writeUTF(new BigInteger(1, encryptedKey).toString());

        // Receive decrypted message
        String decryptedMessage = in.readUTF();
        System.out.println("Server decrypted message: " + decryptedMessage);
    }

    public static void main(String[] args) {
        try {
            new SecureClient("localhost", 8888).connect();
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }
}