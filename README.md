# Cryptographic Protocols - Basics
This project shows different primitive cryptographic implementations which are mostly used in a client-server architecture.

## Setup
* Programming Language: Java
* JDK: Oracle OpenJDK 23.0.2
* Maven version 4.0.0

## Client Server Architecture and Usage
The basic usage of most of the cryptographic functions is a client-server architecture.
The server has to be started first which then listens on the localhost port 8888 and 8889.  
Port 8889 is a separate socket only used for certificate exchange as shown in a later chapter.  
Port 8888 is the socket for the main communication and testing of the functions via the clients CLI.

After the server has been started the client follows and tries to connect to the sockets.
The process is as follows:  
1. Connection of the two sockets.
2. Generation and exchange of CA, server and client X.509v3 certificates.
3. After successful certificate verification the client CLI is enabled.
4. The user is prompted with a menu to choose different functionalities.

The different functions are explained in the next chapters.

## RSA
When choosing the RSA function in the CLI menu, the user can send an encrypted message to the server.
Using the servers public key, which has been exchanged during the connection phase, the entered string is encrypted and send to the server.
The server responds by decrypting the message using its private key and sending the decrypted message back to the client in plaintext as verification.

## Elliptic Curve Scalar Multiplication
This implementation is not directly used by the client-server architecture, but it provides basic operations for elliptic curves over finite fields, including point addition and scalar multiplication.
Scalar multiplication is performed using the double-and-add algorithm for computation of 𝑘𝑃 for a given point 𝑃 and scalar 𝑘.
It also includes point validity checks to ensure correct calculations.

## DSA Signature Generation and Verification
The DSA function implements the Digital Signature Algorithm for message authentication through the DSAKeyPair and DSASignature classes.
The client generates a DSA key pair during initialization and provides signature functionality in the testDSASignature method of the client CLI.
When a user enters a message, the client signs it with their private key and sends the message, public key, and signature to the server.
The server then verifies the signature using the transmitted public key, confirming message authenticity and integrity.
The server responds with a boolean "true" and "false" based on if the validation was successful or not.

## X.509v3 Certificates
On startup, the server generates or loads a self-signed CA certificate and corresponding key pair, then creates a server certificate signed by this CA.
During connection establishment, the client receives both CA and server certificates, verifying the server certificate's authenticity against the CA.
The client then generates a Certificate Signing Request (CSR), which the server uses to issue a client certificate.

If everything is verified and no problems occurred, then the program enables the CLI for further communications.

## HMAC
The HMAC (Hash-based Message Authentication Code) function is used for message authentication with a shared secret.
In the CLI HMAC method, the client generates an HMAC-SHA256 tag for a user-provided message using a secret key.
For secure transmission, the client encrypts the secret key with the server's RSA public key before sending the message, HMAC tag, and encrypted secret to the server.
The server then decrypts the secret key and independently verifies the HMAC by recalculating it on the received message, confirming both message integrity and authenticity.
Finally, the server responds with a boolean "true" and "false" based on if the validation was successful or not.

## Hashing
The HashUtil class supports multiple algorithms including MD5, SHA-1, SHA-256, and SHA-512.
In the CLI, the client allows users to select a hash algorithm, generates a hash of the input message, and sends both the message and hash to the server along with the encrypted algorithm identifier.
On the server side it then decrypts the algorithm information, recalculates the hash using the specified algorithm, and verifies if it matches the received hash.
The server responds with a boolean "true" and "false" based on if the validation was successful or not.

## Symmetric Ciphers
The implemented symmetric cypher chosen is AES.
Using the CLI, the client generates a random AES secret key, encrypts the user's message with this key, and then encrypts the AES key itself using the server's RSA public key for secure transmission.
The server receives both the encrypted message and the encrypted key, decrypts the AES key using its private RSA key, and then uses this recovered key to decrypt the original message.
The server responds by decrypting the message using the recovered AES key and sending the decrypted message back to the client in plaintext as verification.