package com.company;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.util.Scanner;

public class Server {

    private Socket socket = null;
    private ServerSocket server = null;
    private DataInputStream in = null;
    private DataOutputStream out = null;

    public Server(int port) {
        try {
            server = new ServerSocket(port);
            System.out.println("Server started");
            System.out.println("Waiting for a client...");

            while (true) {
                try {
                    socket = server.accept();
                    System.out.println("Client accepted");

                    in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                    out = new DataOutputStream(socket.getOutputStream());

                    System.out.println("Assigning new thread for this client");

                    Thread t = new ClientHandler(socket, in, out);
                    t.start();
                } catch (Exception e) {
                    socket.close();
                }
            }
        }catch (IOException i) {
            System.out.println(i);
        }
    }
    public static void main(String args[]) {
        Server server = new Server(5000);
    }

}
class ClientHandler extends Thread {

    final DataInputStream in;
    final DataOutputStream out;
    final Socket socket;

    public ClientHandler (Socket socket, DataInputStream in, DataOutputStream out) {
        this.in = in;
        this.out = out;
        this.socket = socket;
    }

    public void run () {
        String received = "";
        String toReturn;

        while (true) {
            try {
                while (!received.equals("Over")) {
                    out.writeUTF("Type Over to terminate connection");

                    try {
                        received = in.readUTF();
                        System.out.println(received);
                    } catch (Exception e) {
                        // System.out.println(e);
                    }
                }

                System.out.println("Closing connection");

                socket.close();
                in.close();
                out.close();
                break;

            } catch (IOException e){
                try {
                    socket.close();
                } catch (IOException i){
                    System.out.println(i);
                }
                e.printStackTrace();
            }
        }
    }
}

