package crypto.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAUtils {
    private static BigInteger n, d, e;
    private static BigInteger serverPublicKey, clientPublicKey;
    private static final int BIT_LENGTH = 2048;
    private static final SecureRandom random = new SecureRandom();

    // RSA Key Generation
    public static void generateRSAKeys() {
        BigInteger p = new BigInteger(BIT_LENGTH / 2, 100, random);
        BigInteger q = new BigInteger(BIT_LENGTH / 2, 100, random);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("65537"); // Common public exponent
        d = e.modInverse(phi);
        System.out.println("RSA Keys Generated.");
    }

    public static String getPublicKey() {
        return n.toString();
    }

    public static void setServerPublicKey(BigInteger publicKey) {
        serverPublicKey = publicKey;
    }

    public static void setClientPublicKey(BigInteger publicKey) {
        clientPublicKey = publicKey;
    }

    // RSA Encryption with server's public key
    public static BigInteger encryptWithServerPublicKey(String message) {
        return new BigInteger(message.getBytes()).modPow(e, serverPublicKey);
    }

    // RSA Encryption with client's public key
    public static BigInteger encryptWithClientPublicKey(String message) {
        return new BigInteger(message.getBytes()).modPow(e, clientPublicKey);
    }

    // RSA Decryption
    public static String decryptRSA(BigInteger encryptedMessage) {
        return new String(encryptedMessage.modPow(d, n).toByteArray());
    }
}