package network;

import java.io.*;
import java.net.*;

public class Server {
    public static void main(String[] args) throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(12345)) {
            System.out.println("Server is running on port 12345...");
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client is connected to server.");

            DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            String message = in.readUTF();

            System.out.println(message);
        }



    }
}
