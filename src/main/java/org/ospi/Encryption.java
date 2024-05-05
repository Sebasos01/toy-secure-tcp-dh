package org.ospi;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Encryption {

    // AESCBCEncryption-related methods
    public static SecretKey generateAESKey(byte[] key) throws Exception {
        return new SecretKeySpec(key, "AES");
    }

    public static byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static String encrypt(String plainText, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    // SHA256withRSA-related methods
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static String signData(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public static boolean verifySignature(String data, String signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data.getBytes());
        return sig.verify(Base64.getDecoder().decode(signature));
    }

    // HMACSHA256-related methods
    public static SecretKey generateHMACSHA256Key(byte[] key) {
        return new SecretKeySpec(key, "HmacSHA256");
    }

    public static String generateHMAC(String data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] hmac = mac.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(hmac);
    }

    // SHA512-related methods
    public static byte[] generateDigest(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(data);
        return md.digest();
    }

    // Helper methods
    public static DHParams loadDHParams(String filePath) throws IOException {
        String content = Files.readString(Path.of(filePath));
        BigInteger p = parseBigInteger(content, "P:");
        BigInteger g = parseBigInteger(content, "G:");
        return new DHParams(p, g);
    }

    private static BigInteger parseBigInteger(String content, String label) {
        Pattern pattern = Pattern.compile(label + "\\s*\\n([0-9a-f:]+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(content);
        if (matcher.find()) {
            String hexString = matcher.group(1).replace(":", "");
            return new BigInteger(hexString, 16);
        }
        throw new IllegalArgumentException("Could not find " + label + " in the input content.");
    }

    public static void saveKeyPairToFile(KeyPair keyPair, String filename) throws Exception {
        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        Files.write(Paths.get(filename), (publicKey + "\n" + privateKey).getBytes());
    }

    public static KeyPair loadKeyPair(String filename) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(filename));
        byte[] publicBytes = Base64.getDecoder().decode(lines.get(0));
        byte[] privateBytes = Base64.getDecoder().decode(lines.get(1));
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicBytes);
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return new KeyPair(keyFactory.generatePublic(publicSpec), keyFactory.generatePrivate(privateSpec));
    }

    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
}
