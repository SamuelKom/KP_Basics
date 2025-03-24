package network;

import crypto.rsa.RSAUtils;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;

class Client {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 5000);
             BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            // Generate RSA keys for client
            RSAUtils.generateRSAKeys();

            // Receive public key from server
            BigInteger serverPublicKey = new BigInteger(in.readLine());
            RSAUtils.setServerPublicKey(serverPublicKey);
            System.out.println("Received public key from server.");

            // Send public key to server
            out.println(RSAUtils.getPublicKey());
            System.out.println("Sent public key to server.");

            System.out.println("Connected to server. Type a message:");
            String input;
            while ((input = userInput.readLine()) != null) {
                BigInteger encryptedMessage = RSAUtils.encryptWithServerPublicKey(input);
                out.println(encryptedMessage);

                BigInteger responseEncrypted = new BigInteger(in.readLine());
                String responseDecrypted = RSAUtils.decryptRSA(responseEncrypted);
                System.out.println("Server (decrypted): " + responseDecrypted);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}