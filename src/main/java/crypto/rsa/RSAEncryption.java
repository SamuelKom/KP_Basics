package crypto.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAEncryption {
    private BigInteger n, d, e;
    private int bitLength = 1024;

    public RSAEncryption() {
        generateKeys();
    }

    private void generateKeys() {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        e = new BigInteger("65537"); // Common public exponent
        d = e.modInverse(phi);
    }

    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    public BigInteger decrypt(BigInteger ciphertext) {
        return ciphertext.modPow(d, n);
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getE() {
        return e;
    }

    public BigInteger getD() {
        return d;
    }
}