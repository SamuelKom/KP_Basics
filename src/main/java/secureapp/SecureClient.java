package secureapp;

import crypto.dsa.DSAKeyPair;
import crypto.dsa.DSASignature;
import crypto.hash.HashUtil;
import crypto.hmac.HmacUtil;

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
            System.out.println("1. Send Encrypted Message");
            System.out.println("2. Test DSA Signature");
            System.out.println("3. Test HMAC");
            System.out.println("4. Test Hash");
            System.out.println("5. Exit");
            System.out.print("Choose an option: ");

            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            switch (choice) {
                case 1:
                    sendEncryptedMessage(scanner);
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

    private void sendEncryptedMessage(Scanner scanner) throws Exception {
        System.out.print("Enter message to encrypt: ");
        String message = scanner.nextLine();

        // Encrypt message
        byte[] encryptedMessage = rsaEncryption.encrypt(
                message.getBytes(),
                serverPublicKey,
                serverModulus
        );

        // Send encryption request
        out.writeUTF("ENCRYPT");
        out.writeUTF(new BigInteger(1, encryptedMessage).toString());

        // Receive decrypted message
        String decryptedMessage = in.readUTF();
        System.out.println("Server decrypted message: " + decryptedMessage);
    }

    private void testDSASignature(Scanner scanner) throws Exception {
        System.out.print("Enter message to sign: ");
        String message = scanner.nextLine();

        // Sign message
        DSASignature.Signature signature = DSASignature.sign(
                message.getBytes(),
                dsaKeyPair
        );

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

        System.out.println("Sending message with hmac...");
        out.writeUTF("VERIFY_HMAC");
        out.writeUTF(message);
        out.writeUTF(hmacSha256);
        out.writeUTF(secretKey);

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

        System.out.println("Sending message with hash...");
        System.out.println(message);
        System.out.println(hash);
        System.out.println(algorithm.getAlgorithmName());
        out.writeUTF("VERIFY_HASH");
        out.writeUTF(message);
        out.writeUTF(hash);
        out.writeUTF(algorithm.getAlgorithmName());

        boolean HashVerified = in.readBoolean();
        System.out.println("HashVerification Result: " + HashVerified);
    }

    public static void main(String[] args) {
        try {
            new SecureClient("localhost", 8888).connect();
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }
}