package com.company;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;

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
            createCertificate();
            /*if (action.equals("register")) {
                userId = register();
                createSessionToken(userId);
            } else if (action.equals("login")) {
                userId = login();
                createSessionToken(userId);
            } else if (action.equals("checkToken")) {
                String sessionToken = in.readUTF();
                System.out.println(sessionToken);
                checkSessionToken(sessionToken);
            }*/
        } catch (IOException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException | KeyStoreException | UnrecoverableKeyException | SignatureException | InvalidKeyException | InvalidCipherTextException | OperatorCreationException | InvalidAlgorithmParameterException | CertPathValidatorException e) {
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
        caKs.load(new FileInputStream(new File("serverkeystore.p12")), caPassword.toCharArray());
        Key key = caKs.getKey(caAlias, caPassword.toCharArray());
        KeyStore caTs = KeyStore.getInstance("PKCS12", "BC");
        caTs.load(new FileInputStream(new File("server.truststore")), caPassword.toCharArray());
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
        store.load(null, null);
        X509Certificate[] chain = new X509Certificate[2];
        chain[0] = clientCert;
        chain[1] = caCert;

        for(int i = 0; i<chain.length-1; i++){
            X500Principal issuerDN = ((X509Certificate)chain[i]).getIssuerX500Principal();
            X500Principal subject = ((X509Certificate)chain[i+1]).getSubjectX500Principal();
            System.out.println(issuerDN);
            System.out.println(subject);
        }

        store.setKeyEntry("clients", privKey, "AlexReb123!".toCharArray(), chain);
        //store.setCertificateEntry("clients", clientCert);
        store.setCertificateEntry("server", caCert);
        store.setCertificateEntry("analysisServer-cert", caTs.getCertificate("analysisServer-cert"));
        caKs.setCertificateEntry("clients", clientCert);

        FileOutputStream fOut = new FileOutputStream("clientCert.pem");
        store.store(fOut, "AlexReb123!".toCharArray());
    }
}

