package org.ospi;

import javax.crypto.SecretKey;
import java.security.*;
import java.util.Base64;

import static org.ospi.Encryption.*;

// Java 21 LTS is being used
public class Main {
    public static void main(String[] args) throws Exception {
        HMACExample();
    }

    public static void AESExample() throws Exception {
        String text = "Hello World!";
        byte[] keyy = generateDigest(text.getBytes());
        byte[] keyyy = new byte[32];
        System.arraycopy(keyy, 0, keyyy, 0, 32);
        SecretKey key = generateAESKey(keyyy);
        byte[] iv = generateIV();
        String encryptedText = encrypt(text, key, iv);
        String decryptedText = decrypt(encryptedText, key, iv);
        System.out.println("Encrypted Text: " + encryptedText);
        System.out.println("Decrypted Text: " + decryptedText);
    }

    public static void RSAExample() throws Exception {
        KeyPair keyPair = generateKeyPair();
        String data = "Hello World!";
        String signature = signData(data, keyPair.getPrivate());
        boolean isVerified = verifySignature(data, signature, keyPair.getPublic());
        System.out.println("Signature: " + signature);
        System.out.println("Is signature verified: " + isVerified);
    }

    public static void HMACExample() throws Exception {
        String data = "Hello World!";
        String key = "supersecretkey2";
        SecretKey sKey = generateHMACSHA256Key(key.getBytes());
        String hmac = generateHMAC(data, sKey);
        System.out.println("HMAC: " + hmac);
    }

    public static void DigestExample() throws Exception {
        byte[] digest = generateDigest("master key".getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : digest) {
            hexString.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        }
        System.out.println("SHA-512 Digest: " + hexString.toString());
        System.out.println(digest.length);
    }
}