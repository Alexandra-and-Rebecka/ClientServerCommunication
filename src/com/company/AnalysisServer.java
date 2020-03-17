package com.company;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import java.util.concurrent.locks.ReentrantLock;

public class AnalysisServer {
    private SSLSocket socket = null;
    private SSLServerSocket server = null;
    private DataInputStream in = null;
    private DataOutputStream out = null;

    public AnalysisServer(int port) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            KeyStore truststore = KeyStore.getInstance("PKCS12", "BC");
            char[] keyStorePassword = "AlexReb123!".toCharArray();
            try(InputStream keyStoreData = new FileInputStream("analysisServer.keystore")) {
                keyStore.load(keyStoreData, keyStorePassword);
            }
            try(InputStream trustStoreData = new FileInputStream("analysisServer.truststore")) {
                truststore.load(trustStoreData, keyStorePassword);
            }

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("SunX509");
            keyMgrFact.init(keyStore, keyStorePassword);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(truststore);

            SSLContext serverContext = SSLContext.getInstance("TLSv1");
            serverContext.init(keyMgrFact.getKeyManagers(), trustManagerFactory.getTrustManagers(), SecureRandom.getInstance("DEFAULT", Security.getProvider("BC")));

            SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
            server = (SSLServerSocket) fact.createServerSocket(port);
            server.setNeedClientAuth(true);


            System.out.println("Analysis Server started");
            System.out.println("Waiting for a client...");

            while (true) {
                try {
                    socket = (SSLSocket) server.accept();
                    System.out.println("Client accepted");

                    in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                    out = new DataOutputStream(socket.getOutputStream());

                    System.out.println("Assigning new thread for this client");

                    Thread t = new AnalysisClientHandler(socket, in, out);
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
        AnalysisServer server = new AnalysisServer(5050);
    }
}

class AnalysisClientHandler extends Thread {
    ReentrantLock lock = new ReentrantLock();

    final DataInputStream in;
    final DataOutputStream out;
    final Socket socket;

    public AnalysisClientHandler (Socket socket, DataInputStream in, DataOutputStream out) {
        this.in = in;
        this.out = out;
        this.socket = socket;
    }

    public void run () {
        boolean sessionTokenValid = false;
        int rowNumber = 0;
        int cellNumber = 0;
        FileInputStream file = null;
        XSSFWorkbook workbook = null;
        XSSFSheet sheet = null;
        String message = "";
        String sessionToken = "";

        try {
            message = in.readUTF();
            sessionToken = in.readUTF();
        } catch (Exception e) {
            System.out.println(e);
        }

        AnalysisServerAsClient analysisServerAsClient = new AnalysisServerAsClient("localhost", 5000);
        sessionTokenValid = analysisServerAsClient.isSessionTokenValid(sessionToken);
        analysisServerAsClient.closeConnection();

        if (sessionTokenValid) {
            lock.lock();
            try {
                file = new FileInputStream(new File("AnalysisServer.xlsx"));
                workbook = new XSSFWorkbook(file);
                sheet = workbook.getSheetAt(0);

                rowNumber = sheet.getLastRowNum() + 1;
                Cell firstCell = sheet.createRow(rowNumber).createCell(0);
                firstCell.setCellValue(message);

                FileOutputStream outputStream = new FileOutputStream("AnalysisServer.xlsx");
                workbook.write(outputStream);
                file.close();

            } catch (FileNotFoundException e){
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                lock.unlock();
            }
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
}

class AnalysisServerAsClient{

    private SSLSocket socket = null;
    private DataInputStream in = null;
    private DataOutputStream out = null;

    public AnalysisServerAsClient(String address, int port) {
        try {

            KeyStore truststore = KeyStore.getInstance("PKCS12");
            char[] truststorePassword = "AlexReb123!".toCharArray();
            try(InputStream keyStoreData = new FileInputStream("analysisServer.truststore")){
                truststore.load(keyStoreData, truststorePassword);
            }

            Security.addProvider(new BouncyCastleProvider());

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");
            trustMgrFact.init(truststore);

            SSLContext clientContext = SSLContext.getInstance("TLS");
            clientContext.init(null, trustMgrFact.getTrustManagers(), SecureRandom.getInstance("DEFAULT", Security.getProvider("BC")));

            SSLSocketFactory fact = clientContext.getSocketFactory();
            socket = (SSLSocket) fact.createSocket(address, port) ;
            System.out.println("Connected");

            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
        } catch (Exception i) {
            System.out.println(i);
        }
    }
    public boolean isSessionTokenValid(String sessionToken) {
        try {
            out.writeUTF("checkToken");
            out.writeUTF(sessionToken);
            String result = in.readUTF();
            System.out.println(result);
            if (result.equals("Valid")) {
                return true;
            }
        } catch (IOException e) {
            System.out.println(e);
        }
        return false;
    }
    public void closeConnection() {
        System.out.println("closing");
        try {
            in.close();
            out.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}