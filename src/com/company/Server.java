package com.company;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.*;
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
        String username = "";
        String password = "";
        int rowNumber;
        int cellNumber = 0;
        FileInputStream file = null;
        XSSFWorkbook workbook = null;
        XSSFSheet sheet = null;

        try {
            file = new FileInputStream(new File("Authentication.xlsx"));
            workbook = new XSSFWorkbook(file);
            sheet = workbook.getSheetAt(0);
        } catch (IOException e) {
            System.out.println(e);
        }

        rowNumber = sheet.getLastRowNum() + 1;
        String content = sheet.getRow(rowNumber - 1).getCell(0).getStringCellValue();
        System.out.println(content);

            try {
                out.writeUTF("Give a username and a password");

                try {
                    username = in.readUTF();
                    password = in.readUTF();
                    System.out.println(username);
                    System.out.println(password);
                } catch (Exception e) {
                    System.out.println(e);
                }

                Row row = sheet.createRow(rowNumber);
                Cell cell = row.createCell(cellNumber);
                cell.setCellValue(username);
                cellNumber++;
                cell = row.createCell(cellNumber);
                cell.setCellValue(password);

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
                e.printStackTrace();
            }

        try (FileOutputStream outputStream = new FileOutputStream("Authentication.xlsx")) {
            workbook.write(outputStream);
        } catch (IOException i) {
            System.out.println(i);
        }
    }
}

