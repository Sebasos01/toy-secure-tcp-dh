# Toy Secure TCP with RSA-signed Diffie-Hellman

A compact Java 17 project that demonstrates how to graft a minimal secure channel on top of raw TCP sockets.  
It is **not production-worthy**—parameters are intentionally small and many protocol corner-cases are ignored—but every cryptographic primitive is wired up exactly as you would in real software.

## Build & run

```bash
mvn package
# start the server
java -cp target/toy-secure-tcp-dh-1.0.jar org.ospi.Server
# in another terminal, start one or more clients
java -cp target/toy-secure-tcp-dh-1.0.jar org.ospi.Client
````

The client spawns a configurable number of threads (`N` in `Client.main`) so you can observe concurrent handshakes.

## Directory structure

```
.
├── dh_params.txt      # 1024-bit MODP group (P,G) used by both peers
├── key_pair.txt       # PEM-style Base64 of the server’s RSA-2048 key pair
├── respuesta_preguntas.txt
├── pom.xml            # Maven build – includes JUnit 5 and Bouncy Castle
└── src/main/java/org/ospi
    ├── Server.java    # threaded echo server implementing the handshake
    ├── Client.java    # demo client; spins up N connections
    ├── Encryption.java# cryptographic helpers (AES, HMAC, RSA, DH)
    └── DHParams.java  # simple record for (P,G)
```

## Protocol walk-through

| Phase | Actor | Message (high-level)                             | Purpose                                                           |
| ----- | ----- | ------------------------------------------------ | ----------------------------------------------------------------- |
| 1     | C → S | `SECURE INIT ; randomChal`                       | Start handshake; deliver a 1024-bit challenge.                    |
| 2-3   | S → C | `Base64(RSA_pub) ; Sign(chal)`                   | Send RSA pubkey & prove possession of RSA priv by signing `chal`. |
| 4     | C → S | `OK` / `ERROR`                                   | Client verifies signature; aborts on failure.                     |
| 5-7   | S → C | `G ; P ; Y_srv ; iv ; Sign(all)`                 | Ephemeral DH params, IV and their RSA signature.                  |
| 8-9   | C → S | `OK` / `ERROR`; then `Y_cli`                     | Client checks signature, echoes ACK, returns its DH share.        |
| 10    | both  | derive `K_master = Y_other^X_self mod P`         | Ephemeral shared secret.                                          |
| 11    | both  | `SHA-512(K_master)` → `AES-256‖HMAC‖IV`          | Key expansion.                                                    |
| 12    | S → C | `CONTINUE`                                       | Application phase ready.                                          |
| 13-16 | C ↔ S | encrypted credentials + HMAC                     | Example authenticated login.                                      |
| 17-21 | C ↔ S | encrypted query + HMAC → encrypted answer + HMAC | Demo request/response.                                            |

Any malformed packet yields `ERROR` and closes the connection.

## Cryptographic choices

| Primitive                    | Spec                    | Purpose                                             |
| ---------------------------- | ----------------------- | --------------------------------------------------- |
| RSA-2048 / `SHA256withRSA`   | X.509 PKI-style signing | Authenticating server & all parameter blobs.        |
| DH-1024 (MODP-group 2)       | RFC 3526                | Ephemeral key agreement, basis for forward secrecy. |
| AES-256-CBC + PKCS#5 padding | FIPS-197                | Bulk confidentiality.                               |
| HMAC-SHA-256                 | RFC 2104                | Per-message integrity & authentication.             |
| SHA-512                      | FIPS-180-4              | KDF to stretch `K_master` into sub-keys/IV.         |

## Limitations & learning points

* **Weak parameters:** 1024-bit DH is breakable with nation-state resources; raise to ≥3072 for realism.
* **Replay protection:** The protocol lacks sequence numbers or nonces beyond the initial challenge.
* **No length-hiding:** Plain `println()` leaks message size; production protocols frame ciphertext with a MAC before length is revealed.
* **No certificate validation:** The client blindly trusts whatever RSA pubkey the server sends.
* **Single-process trust model:** All keys live in local text files; real deployments store long-term secrets in an HSM or TPM.

Despite these caveats, the code is short, readable and shows the *exact* API calls you would use for AES, HMAC, RSA and DH in the Java Cryptography Architecture. Clone it, step through with a debugger and tweak parameters to watch the handshake evolve.

