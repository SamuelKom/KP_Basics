package network;

import java.io.*;
import java.net.*;
import java.util.Scanner;

public class Client {
    public static void main(String[] args) throws IOException {

        try (Socket clientSocket = new Socket("localhost", 12345)) {
            System.out.println("Client is running on port 12345...");

            Scanner scanner = new Scanner(System.in);
            System.out.println("Please enter a message: ");
            String message = scanner.nextLine();

            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

            out.writeUTF(message);
        }


    }
}
