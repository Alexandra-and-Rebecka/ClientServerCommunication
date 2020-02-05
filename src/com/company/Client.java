package com.company;

import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Scanner;

public class Client {

    private Socket socket = null;
    private Scanner input = null;
    private DataInputStream in = null;
    private DataOutputStream out = null;

    public Client( String address, int port) {
        try {
            socket = new Socket(address, port);
            System.out.println("Connected");

            input = new Scanner(System.in);
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

        } catch (IOException i) {
            System.out.println(i);
        }

        try {
            String received = in.readUTF();
            System.out.println(received);
        } catch (IOException i) {
            System.out.println(i);
        }

        try {
            String username = input.nextLine();
            String password = input.nextLine();
            out.writeUTF(username);
            out.writeUTF(password);
        } catch (IOException i) {
            System.out.println(i);
        }

        try {
            input.close();
            in.close();
            out.close();
            socket.close();
        } catch (IOException i) {
            System.out.println(i);
        }
    }
    public static void main (String args[]) {
        Client client = new Client("localhost", 5000);
    }
}
