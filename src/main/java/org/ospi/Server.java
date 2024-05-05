package org.ospi;

import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.KeyPair;
import static org.ospi.Encryption.*;

import java.security.SecureRandom;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;

public class Server {
    private static KeyPair keyPair;
    private static DHParams dhParams;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            keyPair = loadKeyPair("key_pair.txt");
            dhParams = loadDHParams("dh_params.txt");
            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(() -> handleClient(clientSocket)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket clientSocket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

            String messageToSend;
            String inputLine;
            String[] parts;
            byte[] iv;
            SecretKey AESSEcretKey;
            SecretKey HMACSEcretKey;

            // Step 2
            inputLine = in.readLine();
            logMessage(Thread.currentThread().getName(), String.format("Received: %s", inputLine));
            parts = inputLine.split(";");
            if (parts.length != 2 || !"SECURE INIT".equals(parts[0])) {
                // Step 3
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(),  String.format("Sent: ERROR (INVALID SECURE INIT -> %s)",  "Expected SECURE INIT format but found other"));
                return;
            }
            String challengeStr =  parts[1];
            try {
                new BigInteger(challengeStr, 16);
                String publicKeyStr = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
                String challengeSignature = signData(challengeStr, keyPair.getPrivate());
                // Step 3
                messageToSend = String.format("%s;%s", publicKeyStr, challengeSignature);
                out.println(messageToSend);
                logMessage(Thread.currentThread().getName(),  String.format("Sent: %s", messageToSend));
            } catch (Exception e) {
                // Step 3
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (INVALID SECURE INIT -> %s)",  e.getMessage()));
                return;
            }

            // Step 6
            inputLine = in.readLine();
            logMessage(Thread.currentThread().getName(), String.format("Received: %s", inputLine));
            if (!inputLine.equals("OK")) {
                // Step 7
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (INVALID CHALLENGE RESPONSE ACKNOWLEDGMENT -> %s)", "Client did not acknowledge the challenge response"));
                return;
            }
            BigInteger X = new BigInteger(dhParams.P().bitLength(), new SecureRandom())
                    .mod(dhParams.P().subtract(BigInteger.ONE));
            BigInteger Y = dhParams.G().modPow(X, dhParams.P());
            iv = generateIV();
            String ivStr = Base64.getEncoder().encodeToString(iv);

            // Step 7
            String sessionParams = String.format("%s;%s;%s;%s"
                    , dhParams.G().toString(16),
                    dhParams.P().toString(16),
                    Y.toString(16),
                    ivStr);
            String sessionParamsSignature = signData(sessionParams, keyPair.getPrivate());
            messageToSend = String.format("%s;%s", sessionParams, sessionParamsSignature);
            out.println(messageToSend);
            logMessage(Thread.currentThread().getName(),  String.format("Sent: %s", messageToSend));

            // Step 11.b
            inputLine = in.readLine();
            logMessage(Thread.currentThread().getName(), String.format("Received: %s", inputLine));
            if (!inputLine.equals("OK")) {
                // Step 12
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (INVALID SESSION PARAMS ACKNOWLEDGMENT -> %s)", "Client did not acknowledge the session params"));
                return;
            }
            inputLine = in.readLine();
            logMessage(Thread.currentThread().getName(), String.format("Received: %s", inputLine));
            BigInteger Y2;
            try {
                Y2 = new BigInteger(inputLine, 16);
            } catch (Exception e) {
                // Step 12
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (INVALID Y FROM CLIENT -> %s)",  e.getMessage()));
                return;
            }
            BigInteger masterKey = Y2.modPow(X, dhParams.P());
            byte[] bMasterKey = masterKey.toByteArray();
            byte[] digest = generateDigest(bMasterKey);
            byte[] bAESSecretKey = Arrays.copyOfRange(digest, 0, 32);
            byte[] bHMACSecretKey = Arrays.copyOfRange(digest, 32, 64);
            AESSEcretKey = generateAESKey(bAESSecretKey);
            HMACSEcretKey = generateHMACSHA256Key(bHMACSecretKey);

            // Step 12
            out.println("CONTINUE");
            logMessage(Thread.currentThread().getName(), "Sent: CONTINUE");

            // Step 15
            inputLine = in.readLine();
            logMessage(Thread.currentThread().getName(), String.format("Received: %s", inputLine));
            parts = inputLine.split(";");
            if (parts.length != 2) {
                // Step 16
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (INVALID USER CREDENTIALS -> %s)", "Expected credentials format but found other"));
                return;
            }
            String encryptedUserCredentials = parts[0];
            String userCredentialsHMAC = parts[1];
            try {
                String userCredentials = decrypt(encryptedUserCredentials, AESSEcretKey, iv);
                String localHMAC = generateHMAC(userCredentials, HMACSEcretKey);
                if (!localHMAC.equals(userCredentialsHMAC)) {
                    throw new Exception("No credential integrity");
                }
                // Step 16
                out.println("OK");
                logMessage(Thread.currentThread().getName(), String.format("Sent: OK (VALID CREDENTIALS -> %s)", userCredentials));
            } catch (Exception e) {
                // Step 16
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (INVALID USER CREDENTIALS -> %s)",  e.getMessage()));
                return;
            }

            // Steps 19 - 20
            inputLine = in.readLine();
            logMessage(Thread.currentThread().getName(), String.format("Received: %s", inputLine));
            parts = inputLine.split(";");
            if (parts.length != 2) {
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (INVALID USER QUERY -> %s)", "Expected query format but found other"));
                return;
            }
            String encryptedUserQuery = parts[0];
            String userQueryHMAC = parts[1];
            try {
                String userQuery = decrypt(encryptedUserQuery, AESSEcretKey, iv);
                String localHMAC = generateHMAC(userQuery, HMACSEcretKey);
                if (!localHMAC.equals(userQueryHMAC)) {
                    throw new Exception("No query integrity");
                }
                String response = String.format("Query response from %s", Thread.currentThread().getName());
                String encryptedResponse = encrypt(response, AESSEcretKey, iv);
                String responseHMAC = generateHMAC(response, HMACSEcretKey);
                messageToSend = String.format("%s;%s", encryptedResponse, responseHMAC);
                out.println(messageToSend);
                logMessage(Thread.currentThread().getName(), String.format("Sent: %s)", messageToSend));
            } catch (Exception e) {
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (INVALID USER QUERY -> %s)",  e.getMessage()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void logMessage(String threadId, String message) {
        String log = ZonedDateTime.now(ZoneId.of("UTC-5")).format(DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss.nnnnnnnnn")) + " [" + threadId + "] " + message.strip();
        System.out.println(log);
    }
}
