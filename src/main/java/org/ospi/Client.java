package org.ospi;

import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;

import static org.ospi.Encryption.*;

public class Client {
    public static void main(String[] args) {
        int N = 32;
        for (int i = 0; i < N; i++) {
            new Thread(Client::makeRequest).start();
        }
    }

    public static void makeRequest() {
        try (Socket socket = new Socket("localhost", 8080);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            String messageToSend;
            String response;
            String[] parts;
            PublicKey serverPublicKey;
            byte[] iv;
            SecretKey AESSEcretKey;
            SecretKey HMACSEcretKey;

            // Step 1
            BigInteger challenge = new BigInteger(130, new SecureRandom());
            String challengeStr = challenge.toString(16);
            messageToSend = String.format("%s;%s", "SECURE INIT", challengeStr);
            out.println(messageToSend);
            logMessage(Thread.currentThread().getName(), String.format("Sent: %s", messageToSend));

            // Step 4
            response = in.readLine();
            logMessage(Thread.currentThread().getName(), String.format("Received: %s", response));
            parts = response.split(";");
            if (parts.length != 2) {
                // Step 5
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(),  String.format("Sent: ERROR (Invalid CHALLENGE RESPONSE -> %s)",  "Expected CHALLENGE RESPONSE format but found other"));
                return;
            }
            try {
                String publicKeyStr = parts[0];
                String challengeSignature = parts[1];
                serverPublicKey = getPublicKey(publicKeyStr);
                boolean challengeVerified = verifySignature(challengeStr, challengeSignature, serverPublicKey);
                if (!challengeVerified) {
                    throw new RuntimeException("Invalid signature");
                }
                // Step 5
                out.println("OK");
                logMessage(Thread.currentThread().getName(), "Sent: OK");
            } catch (Exception e) {
                // Step 5
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (Invalid CHALLENGE RESPONSE -> %s)",  e.getMessage()));
                return;
            }

            // Step 8
            response = in.readLine();
            logMessage(Thread.currentThread().getName(), String.format("Received: %s", response));
            parts = response.split(";");
            if (parts.length != 5) {
                // Step 9
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(),  String.format("Sent: ERROR (Invalid SESSION PARAMS -> %s)",  "Expected SESSION PARAMS format but found other"));
                return;
            }
            StringBuilder sessionParams = new StringBuilder();
            for (int i = 0 ; i < 3; i++) {
                sessionParams.append(parts[i]).append(";");
            }
            sessionParams.append(parts[3]);
            String sessionParamsSignature = parts[4];
            BigInteger P;
            BigInteger G;
            BigInteger Y2;
           try {
               boolean sessionParamsVerified = verifySignature(sessionParams.toString(), sessionParamsSignature, serverPublicKey);
               if (!sessionParamsVerified) {
                   throw new RuntimeException("Invalid signature");
               }
               String GStr = parts[0];
               String PStr = parts[1];
               String Y2Str = parts[2];
               String ivStr = parts[3];
               G = new BigInteger(GStr, 16);
               P = new BigInteger(PStr, 16);
               Y2 = new BigInteger(Y2Str, 16);
               iv = Base64.getDecoder().decode(ivStr);
               // Step 9
               out.println("OK");
               logMessage(Thread.currentThread().getName(), "Sent: OK");
           } catch (Exception e) {
               // Step 9
               out.println("ERROR");
               logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (Invalid SESSION PARAMS -> %s)",  e.getMessage()));
               return;
           }

           // Step 10
            BigInteger X = new BigInteger(P.bitLength(), new SecureRandom())
                    .mod(P.subtract(BigInteger.ONE));
            BigInteger Y = G.modPow(X, P);
            messageToSend = Y.toString(16);
            out.println(messageToSend);
            logMessage(Thread.currentThread().getName(),  String.format("Sent: %s", messageToSend));

            // Step 11.a
            BigInteger masterKey = Y2.modPow(X, P);
            byte[] bMasterKey = masterKey.toByteArray();
            byte[] digest = generateDigest(bMasterKey);
            byte[] bAESSecretKey = Arrays.copyOfRange(digest, 0, 32);
            byte[] bHMACSecretKey = Arrays.copyOfRange(digest, 32, 64);
            AESSEcretKey = generateAESKey(bAESSecretKey);
            HMACSEcretKey = generateHMACSHA256Key(bHMACSecretKey);

            // Steps 13 - 14
            response = in.readLine();
            logMessage(Thread.currentThread().getName(), String.format("Received: %s", response));
            if (!response.equals("CONTINUE")) {
                out.println("ERROR");
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (Invalid CONTINUITY ACKNOWLEDGMENT -> %s)", "Server did not acknowledge continuity"));
                return;
            }
            String login = String.format("User%s", Thread.currentThread().getName()).replace("\\s+", "");
            String password = String.format("Password%s", Thread.currentThread().getName()).replace("\\s+", "");;
            String credentials = String.format("%s %s", login, password);
            String encryptedCredentials = encrypt(credentials, AESSEcretKey, iv);
            String credentialsHAMC = generateHMAC(credentials, HMACSEcretKey);
            messageToSend = String.format("%s;%s", encryptedCredentials, credentialsHAMC);
            out.println(messageToSend);
            logMessage(Thread.currentThread().getName(),  String.format("Sent: %s", messageToSend));

            // Steps 17 - 18
            response = in.readLine();
            logMessage(Thread.currentThread().getName(), String.format("Received: %s", response));
            String query = String.format("Query about %s", Thread.currentThread().getName());
            String encryptedQuery = encrypt(query, AESSEcretKey, iv);
            String queryHAMC = generateHMAC(query, HMACSEcretKey);
            messageToSend = String.format("%s;%s", encryptedQuery, queryHAMC);
            out.println(messageToSend);
            logMessage(Thread.currentThread().getName(),  String.format("Sent: %s", messageToSend));

            // Step 21
            response = in.readLine();
            logMessage(Thread.currentThread().getName(), String.format("Received: %s", response));
            parts = response.split(";");
            if (parts.length != 2) {
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (INVALID SERVER QUERY RESPONSE -> %s)", "Expected response format but found other"));
                return;
            }
            String encryptedServerResponse = parts[0];
            String serverResponseHMAC = parts[1];
            try {
                String serverResponse = decrypt(encryptedServerResponse, AESSEcretKey, iv);
                String localHMAC = generateHMAC(serverResponse, HMACSEcretKey);
                if (!localHMAC.equals(serverResponseHMAC)) {
                    throw new Exception("No response integrity");
                }
                logMessage(Thread.currentThread().getName(), String.format("Sent: OK (VALID SERVER QUERY RESPONSE -> %s)", serverResponse));
            } catch (Exception e) {
                logMessage(Thread.currentThread().getName(), String.format("Sent: ERROR (INVALID SERVER QUERY RESPONSE -> %s)",  e.getMessage()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void logMessage(String threadId, String message) {
        String log = ZonedDateTime.now(ZoneId.of("UTC-5")).format(DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss.nnnnnnnnn")) + " [" + threadId + "] " + message.strip();
        System.out.println(log);
    }
}
