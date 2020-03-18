package com.company;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionKey {
    private SecretKey sessionKey;

    public SessionKey() throws NoSuchAlgorithmException {
        KeyGenerator key = KeyGenerator.getInstance("AES");
        key.init(2048);
        this.sessionKey = key.generateKey();
    }

    public SecretKey getSessionKey() {
        return this.sessionKey;
    }

    public String encodedSessionKey() {
        return Base64.getEncoder().encodeToString(this.sessionKey.getEncoded());
    }
}
