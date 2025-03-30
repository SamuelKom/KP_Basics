package secureapp;

import crypto.dsa.DSAKeyPair;
import crypto.dsa.DSASignature;
import crypto.hash.HashUtil;
import crypto.hmac.HmacUtil;

import java.io.*;
import java.math.BigInteger;
import java.net.*;

public class SecureServer {
    private ServerSocket serverSocket;
    private CryptoUtils.RSAEncryption rsaEncryption;

    public SecureServer(int port) throws IOException {
        serverSocket = new ServerSocket(port);
        rsaEncryption = new CryptoUtils.RSAEncryption();
    }

    public void start() throws Exception {
        System.out.println("Server started on port " + serverSocket.getLocalPort());

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected: " + clientSocket.getInetAddress());

            new Thread(() -> handleClient(clientSocket)).start();
        }
    }

    private void handleClient(Socket clientSocket) {
        try {
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

            // Send public key components to client
            out.writeUTF(rsaEncryption.getPublicKey().toString());
            out.writeUTF(rsaEncryption.getModulus().toString());

            label:
            while (true) {
                String operation = in.readUTF();

                switch (operation) {
                    case "ENCRYPT":
                        String encryptedMessageStr = in.readUTF();
                        byte[] encryptedMessage = new BigInteger(encryptedMessageStr).toByteArray();
                        byte[] decryptedMessage = rsaEncryption.decrypt(encryptedMessage);
                        out.writeUTF(new String(decryptedMessage));
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

                        boolean hmacValid = new HmacUtil().verifyHmac(hmacMessage, secretKey, hmac, HmacUtil.HMAC_SHA256);

                        out.writeBoolean(hmacValid);
                        break;
                    case "VERIFY_HASH":
                        String hashMessage = in.readUTF();
                        String hash = in.readUTF();
                        String  hashFunction = in.readUTF();

                        System.out.println(hashMessage);
                        System.out.println(hash);
                        System.out.println(hashFunction);

                        HashUtil.HashAlgorithm hashAlgorithm = HashUtil.HashAlgorithm.valueOf(hashFunction);

                        boolean hashValid = HashUtil.verify(hashMessage, hash, hashAlgorithm);

                        out.writeBoolean(hashValid);
                        break;
                    case "EXIT":
                        break label;
                }
            }

            clientSocket.close();
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }

    public static void main(String[] args) {
        try {
            new SecureServer(8888).start();
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }
}