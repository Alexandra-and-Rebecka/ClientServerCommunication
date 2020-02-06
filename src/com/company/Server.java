package com.company;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

public class Server {

    private SSLSocket socket = null;
    private SSLServerSocket server = null;
    private DataInputStream in = null;
    private DataOutputStream out = null;

    public Server(int port) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("SunX509");
            keyMgrFact.init(null, "password".toCharArray());

            SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(keyMgrFact.getKeyManagers(), null, SecureRandom.getInstance("DEFAULT", Security.getProvider("BC")));

            SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
            SSLServerSocket server = (SSLServerSocket) fact.createServerSocket(5000);

            System.out.println("Server started");
            System.out.println("Waiting for a client...");

            while (true) {
                try {
                    socket = (SSLSocket) server.accept();
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
        } catch (Exception i) {
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
        String action = "register";
        /*try {
            action = in.readUTF();
        } catch (IOException e) {
            e.printStackTrace();
        }*/

        if (action.equals("register")) {
            register();
        } else {
            login();
        }
    }

    private void register() {
        boolean userExists = false;
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

                for (int i=1; i < rowNumber; i++){

                    String user = sheet.getRow(i).getCell(0).toString();
                    if (username.equals(user)) {
                        userExists = true;
                        break;
                    }
                }

                if (!userExists) {
                    Row row = sheet.createRow(rowNumber);
                    Cell cell = row.createCell(cellNumber);
                    cell.setCellValue(username);
                    cellNumber++;
                    cell = row.createCell(cellNumber);
                    cell.setCellValue(password);
                    cellNumber++;
                    cell = row.createCell(cellNumber);
                    cell.setCellValue(Base64.getEncoder().encodeToString(salt));

                    FileOutputStream outputStream = new FileOutputStream("Authentication.xlsx");
                    workbook.write(outputStream);
                    out.writeUTF("New user is registered");
                } else {
                    out.writeUTF("User already exists");
                }
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

    private void login() {
        boolean userExists = false;
        String username = "";
        String password = "";
        int rowNumber;
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

            lock.lock();
            try {
                file = new FileInputStream(new File("Authentication.xlsx"));
                workbook = new XSSFWorkbook(file);
                sheet = workbook.getSheetAt(0);

                rowNumber = sheet.getLastRowNum();

                for (int i=1; i <= rowNumber; i++){

                    String user = sheet.getRow(i).getCell(0).toString();
                    if (username.equals(user)) {
                        userExists = true;
                        rowNumber = i;
                        break;
                    }
                }

                if (userExists) {
                    String hashedPass = sheet.getRow(rowNumber).getCell(1).toString();
                    byte[] salt = Base64.getDecoder().decode(sheet.getRow(rowNumber).getCell(2).toString());

                    String hashedPass2 = HashPassword.getHashedPassword(password, salt);

                    if (hashedPass.equals(hashedPass2)){
                        out.writeUTF("Login succeeded");
                    } else {
                        out.writeUTF("Wrong password");
                    }

                    FileOutputStream outputStream = new FileOutputStream("Authentication.xlsx");
                    workbook.write(outputStream);
                } else {
                    out.writeUTF("User doesn't exist");
                }
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

