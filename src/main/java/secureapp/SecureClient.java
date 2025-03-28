package secureapp;

import crypto.dsa.DSAKeyPair;
import crypto.dsa.DSASignature;

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
            System.out.println("\n--- Secure Communication Menu ---");
            System.out.println("1. Send Encrypted Message");
            System.out.println("2. Test DSA Signature");
            System.out.println("3. Exit");
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


        boolean isVerified = in.readBoolean();
        System.out.println("Signature Verification Result: " + isVerified);
    }

    public static void main(String[] args) {
        try {
            new SecureClient("localhost", 8888).connect();
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }
}