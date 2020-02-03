package com.company;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {
    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        String name = "BC";
	    if (Security.getProvider(name) == null) {
	        System.out.println("Not installed");
        } else {
	        System.out.println("Installed");
        }
    }
}
