package com.company;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Date;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

public class Server {

    private SSLSocket socket = null;
    private SSLServerSocket server = null;
    private DataInputStream in = null;
    private DataOutputStream out = null;

    public Server(int port) throws KeyStoreException {
        try {
            Security.addProvider(new BouncyCastleProvider());

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            char[] keyStorePassword = "AlexReb123!".toCharArray();
            try(InputStream keyStoreData = new FileInputStream("server.keystore")) {
                keyStore.load(keyStoreData, keyStorePassword);
            }

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("SunX509");
            keyMgrFact.init(keyStore, keyStorePassword);

            SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(keyMgrFact.getKeyManagers(), null, SecureRandom.getInstance("DEFAULT", Security.getProvider("BC")));

            SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
            server = (SSLServerSocket) fact.createServerSocket(port);

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
    public static void main(String args[]) throws KeyStoreException {
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
        int userId = 0;
        String action = "";

        try {
            action = in.readUTF();
            
            System.out.println(action);
            if (action.equals("register")) {
                userId = register();
                createSessionToken(userId);
            } else if (action.equals("login")) {
                userId = login();
                createSessionToken(userId);
            } else if (action.equals("checkToken")) {
                String sessionToken = in.readUTF();
                System.out.println(sessionToken);
                checkSessionToken(sessionToken);
            }
        } catch (IOException e) {
            System.out.println(e);
        }

        System.out.println("Closing connection");

        try {
            socket.close();
            in.close();
            out.close();
        } catch (IOException i) {
            System.out.println(i);
        }
    }

    private int register() {
        boolean success = false;
        boolean userExists = false;
        String username = "";
        String password = "";
        byte[] salt = null;
        int rowNumber = 0;
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
                    success = true;
                } else {
                    out.writeUTF("User already exists");
                }
                file.close();
            } finally {
                lock.unlock();
            }
        } catch (IOException e){
            try {
                socket.close();
            } catch (IOException i){
                System.out.println(i);
            }
        }
        if(success){
            return rowNumber;
        } else {
            return 0;
        }
    }

    private int login() {
        boolean success = false;
        boolean userExists = false;
        String username = "";
        String password = "";
        int rowNumber = 0;
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
                        success = true;
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
            file.close();
        } catch (IOException e){
            try {
                socket.close();
            } catch (IOException i){
                System.out.println(i);
            }
        }
        if(success){
            return rowNumber;
        } else {
            return 0;
        }
    }

    private void createSessionToken(int userId){
        Date date = new Date();
        if (userId != 0) {
            try {
                SessionKey sessionKey = new SessionKey();
                String encodedKey = sessionKey.encodedSessionKey();

                lock.lock();
                try {
                    FileInputStream file = new FileInputStream(new File("Authentication.xlsx"));
                    XSSFWorkbook workbook = new XSSFWorkbook(file);
                    XSSFSheet sheet = workbook.getSheetAt(0);

                    Cell sessionKeyCell = sheet.getRow(userId).createCell(3);
                    sessionKeyCell.setCellValue(encodedKey);

                    Cell timeCell = sheet.getRow(userId).createCell(4);
                    timeCell.setCellValue(date.getTime());

                    FileOutputStream outputStream = new FileOutputStream("Authentication.xlsx");
                    workbook.write(outputStream);
                    out.writeUTF(encodedKey);
                    file.close();
                } finally {
                    lock.unlock();
                }


            } catch (NoSuchAlgorithmException | IOException e) {
                System.out.println(e);
            }
        }
    }

    private void checkSessionToken(String sessionToken) {
        boolean sessionValid = false;
        int rowNumber = 0;
        FileInputStream file = null;
        XSSFWorkbook workbook = null;
        XSSFSheet sheet = null;


        lock.lock();
        try {
            file = new FileInputStream(new File("Authentication.xlsx"));
            workbook = new XSSFWorkbook(file);
            sheet = workbook.getSheetAt(0);

            rowNumber = sheet.getLastRowNum();

            System.out.println(rowNumber);
            for (int i=1; i <= rowNumber; i++){
                String sessionKey = sheet.getRow(i).getCell(3).toString();
                if (sessionToken.equals(sessionKey)) {
                    sessionValid = true;
                    rowNumber = i;
                    break;
                }
            }

            if (sessionValid) {
                out.writeUTF("Valid");
            } else {
                out.writeUTF("Invalid");
            }

            file.close();

        } catch (IOException i) {
            System.out.println(i);
        } finally {
            lock.unlock();
        }
    }
}

