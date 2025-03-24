package network;

import crypto.rsa.RSAUtils;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

class Server {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(5000)) {
            System.out.println("Server started. Waiting for client...");
            Socket socket = serverSocket.accept();
            System.out.println("Client connected.");

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // Generate RSA keys for server
            RSAUtils.generateRSAKeys();

            // Send public key to client
            out.println(RSAUtils.getPublicKey());
            System.out.println("Sent public key to client.");

            // Receive public key from client
            BigInteger clientPublicKey = new BigInteger(in.readLine());
            RSAUtils.setClientPublicKey(clientPublicKey);
            System.out.println("Received public key from client.");

            String received;
            while ((received = in.readLine()) != null) {
                BigInteger encryptedMessage = new BigInteger(received);
                String decryptedMessage = RSAUtils.decryptRSA(encryptedMessage);
                System.out.println("Client (decrypted): " + decryptedMessage);

                // Encrypt response using client's public key
                BigInteger responseEncrypted = RSAUtils.encryptWithClientPublicKey("Message received.");
                out.println(responseEncrypted);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}