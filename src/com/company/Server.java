package com.company;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import javax.net.ssl.*;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

public class Server {

    private SSLSocket socket = null;
    private SSLServerSocket server = null;
    private DataInputStream in = null;
    private DataOutputStream out = null;
    private OutputStream outputStream = null;

    public Server(int port) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            KeyStore truststore = KeyStore.getInstance("PKCS12", "BC");
            char[] keyStorePassword = "AlexReb123!".toCharArray();
            InputStream keyStoreData = new FileInputStream(new File("server.keystore"));
            keyStore.load(keyStoreData, keyStorePassword);
            keyStoreData.close();

            InputStream trustStoreData = new FileInputStream(new File("server.truststore"));
            truststore.load(trustStoreData, keyStorePassword);
            trustStoreData.close();

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("SunX509");
            keyMgrFact.init(keyStore, keyStorePassword);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(truststore);

            SSLContext serverContext = SSLContext.getInstance("TLSv1");
            serverContext.init(keyMgrFact.getKeyManagers(), trustManagerFactory.getTrustManagers(), SecureRandom.getInstance("DEFAULT", Security.getProvider("BC")));

            SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
            server = (SSLServerSocket) fact.createServerSocket(port);
            server.setNeedClientAuth(true);

            System.out.println("Server started");
            System.out.println("Waiting for a client...");

            while (true) {
                try {
                    socket = (SSLSocket) server.accept();
                    System.out.println("Client accepted");

                    in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                    outputStream = socket.getOutputStream();
                    out = new DataOutputStream(socket.getOutputStream());

                    System.out.println("Assigning new thread for this client");

                    Thread t = new ClientHandler(socket, in, out, outputStream);
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
    final OutputStream outputStream;
    final Socket socket;

    public ClientHandler (Socket socket, DataInputStream in, DataOutputStream out, OutputStream outputStream) {
        this.in = in;
        this.out = out;
        this.outputStream = outputStream;
        this.socket = socket;
    }

    public void run () {
        int userId = 0;
        String action = "";

        try {
            action = in.readUTF();
            
            System.out.println(action);
            //createCertificate();
            if (action.equals("register")) {
                register();
            } else if (action.equals("login")) {
                login();
            } else if (action.equals("checkToken")) {
                String sessionToken = in.readUTF();
                System.out.println(sessionToken);
                checkSessionToken(sessionToken);
            }
        } catch (Exception e) {
            System.out.println(e);
        }

        System.out.println("Closing connection");

        try {
            socket.close();
            in.close();
            out.close();
            outputStream.close();
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
                    out.writeUTF("Success");
                    createSessionToken(rowNumber);
                    createCertificate();
                    success = true;
                } else {
                    out.writeUTF("User already exists");
                }
                file.close();
            } finally {
                lock.unlock();
            }
        } catch (IOException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException | KeyStoreException | UnrecoverableKeyException | SignatureException | InvalidKeyException | InvalidCipherTextException | OperatorCreationException | InvalidAlgorithmParameterException | CertPathValidatorException e){
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
                        out.writeUTF("Success");
                        createSessionToken(rowNumber);

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

    private void createCertificate() throws NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, KeyStoreException, UnrecoverableKeyException, SignatureException, InvalidKeyException, InvalidCipherTextException, OperatorCreationException, InvalidAlgorithmParameterException, CertPathValidatorException {
        Security.addProvider(new BouncyCastleProvider());

        //Generate a private RSA key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        //Loading the CA private key and certificate
        String caPassword = "AlexReb123!";
        String caAlias = "server-cert";

        KeyStore caKs = KeyStore.getInstance("PKCS12", "BC");
        FileInputStream inKs = new FileInputStream(new File("server.keystore"));
        caKs.load(inKs, caPassword.toCharArray());
        inKs.close();

        Key key = caKs.getKey(caAlias, caPassword.toCharArray());

        KeyStore caTs = KeyStore.getInstance("PKCS12", "BC");
        FileInputStream inTs = new FileInputStream(new File("server.truststore"));
        caTs.load(inTs, caPassword.toCharArray());
        inTs.close();

        if (key == null) {
            System.out.println("Got null key from keystore!");
        }

        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) key;
        X509Certificate caCert = (X509Certificate) caKs.getCertificate(caAlias);
        if(caCert == null) {
            System.out.println("Got null cert from the keystore!");
        }
        caCert.verify(caCert.getPublicKey());

        //Create x509 certificate
        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, 1024);

        X500Name x500Name = new X500Name("C=SE, ST=Stockholm, L=Stockholm, O=KTH, OU=CoS, CN=Alex, EMAILADDRESS=kolonia@kth.se");
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                x500Name, BigInteger.valueOf(System.currentTimeMillis()),
                new Time(new Date(System.currentTimeMillis())), new Time(expiry.getTime()),
                x500Name, SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        );
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = builder.build(privateKey);
        byte[] certBytes = certBuilder.build(signer).getEncoded();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate clientCert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));

        clientCert.verify(caCert.getPublicKey());

        //Writing the certificate as PKCS12 file
        PKCS12BagAttributeCarrier bagCert = (PKCS12BagAttributeCarrier) clientCert;
        bagCert.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("clients"));
        bagCert.setBagAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                new SubjectKeyIdentifier(pubKey.getEncoded())
        );

        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        KeyStore truststore = KeyStore.getInstance("PKCS12", "BC");
        store.load(null, null);
        truststore.load(null, null);
        X509Certificate[] chain = new X509Certificate[2];
        chain[0] = clientCert;
        chain[1] = caCert;

        KeyStore analTs = KeyStore.getInstance("PKCS12", "BC");
        FileInputStream inAnalTs = new FileInputStream(new File("analysisServer.truststore"));
        analTs.load(inAnalTs, caPassword.toCharArray());
        inAnalTs.close();

        store.setKeyEntry("clientTest-cert", privKey, "AlexReb123!".toCharArray(), chain);

        //Import certificates to truststores
        truststore.setCertificateEntry("clientTest-cert", clientCert);
        truststore.setCertificateEntry("server", caCert);
        truststore.setCertificateEntry("analysisServer-cert", caTs.getCertificate("analysisServer-cert"));

        caTs.setCertificateEntry("clientTest-cert", clientCert);
        analTs.setCertificateEntry("clientTest-cert", clientCert);

        FileOutputStream fOut = new FileOutputStream("clientTest.keystore");
        store.store(fOut, "AlexReb123!".toCharArray());
        fOut.close();

        FileOutputStream fOut1 = new FileOutputStream("clientTest.truststore");
        truststore.store(fOut1, "AlexReb123!".toCharArray());
        fOut1.close();

        FileOutputStream fOut2 = new FileOutputStream("server.truststore");
        caTs.store(fOut2, "AlexReb123!".toCharArray());
        fOut2.close();

        FileOutputStream fOut3 = new FileOutputStream("analysisServer.truststore");
        analTs.store(fOut3, "AlexReb123!".toCharArray());
        fOut3.close();


        //Send trustStore
        System.out.println("Sending truststore");
        File f = new File("clientTest.truststore");
        FileInputStream inS = new FileInputStream(f);
        byte[] b = new byte[inS.available()];
        inS.read(b);

        outputStream.write(b);
        outputStream.flush();
        inS.close();

        System.out.println(in.readUTF());

        //Sending keystore
        System.out.println("Sending keystore");

        f = new File("clientTest.keystore");
        inS = new FileInputStream(f);
        b = new byte[inS.available()];
        inS.read(b);

        outputStream.write(b);
        outputStream.flush();
        inS.close();

        System.out.println(in.readUTF());

    }
}

