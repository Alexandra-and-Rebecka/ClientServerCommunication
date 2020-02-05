package com.company;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.locks.ReentrantLock;

public class Server {

    private Socket socket = null;
    private ServerSocket server = null;
    private DataInputStream in = null;
    private DataOutputStream out = null;

    public Server(int port) {
        try {
            server = new ServerSocket(5000);
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
        } catch (IOException i) {
            System.out.println(i);
        }
    }

    public static void main(String args[]) {
        Server server = new Server(5000);
    }
}

class ClientHandler extends Thread {

    ReentrantLock lock = new ReentrantLock();

    final DataInputStream in;
    final DataOutputStream out;
    final Socket socket;

    public ClientHandler (Socket socket, DataInputStream in, DataOutputStream out) {
        this.in = in;
        this.out = out;
        this.socket = socket;
    }

    public void run () {
        String username = "";
        String password = "";
        byte[] salt = null;
        int rowNumber;
        int cellNumber = 0;
        FileInputStream file = null;
        XSSFWorkbook workbook = null;
        XSSFSheet sheet = null;

        try {
            out.writeUTF("Give a username and a password");

            try {
                username = in.readUTF();
                password = in.readUTF();
            } catch (Exception e) {
                System.out.println(e);
            }

            try {
                salt = HashPassword.getSalt();
            } catch (NoSuchAlgorithmException e) {
                System.out.println(e);
            }

            password = HashPassword.getHashedPassword(password, salt);

            lock.lock();
            try {
                file = new FileInputStream(new File("Authentication.xlsx"));
                workbook = new XSSFWorkbook(file);
                sheet = workbook.getSheetAt(0);

                rowNumber = sheet.getLastRowNum() + 1;

                Row row = sheet.createRow(rowNumber);
                Cell cell = row.createCell(cellNumber);
                cell.setCellValue(username);
                cellNumber++;
                cell = row.createCell(cellNumber);
                cell.setCellValue(password);
                cellNumber++;
                cell = row.createCell(cellNumber);
                cell.setCellValue(salt.toString());

                FileOutputStream outputStream = new FileOutputStream("Authentication.xlsx");
                workbook.write(outputStream);
            } finally {
                lock.unlock();
            }

            System.out.println("Closing connection");

            socket.close();
            in.close();
            out.close();

        } catch (IOException e){
            try {
                socket.close();
            } catch (IOException i){
                System.out.println(i);
            }
        }
    }
}

