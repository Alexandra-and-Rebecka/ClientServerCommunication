package com.company;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;

public class Client {
    private SSLSocket socket = null;
    private Scanner input = null;
    private DataInputStream in = null;
    private DataOutputStream out = null;


    public Client(String address, int port) {
        try {

            KeyStore truststore = KeyStore.getInstance("PKCS12");
            char[] truststorePassword = "AlexReb123!".toCharArray();
            try(InputStream keyStoreData = new FileInputStream("client.truststore")){
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

            input = new Scanner(System.in);
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

            String username = input.nextLine();
            String password = input.nextLine();
            out.writeUTF(username);
            out.writeUTF(password);

            System.out.println("closing");
            input.close();
            in.close();
            out.close();
            socket.close();
        } catch (Exception i) {
            System.out.println(i);
        }
    }
    public static void main (String args[]) {
        Client client = new Client("localhost", 5050);
    }
}
