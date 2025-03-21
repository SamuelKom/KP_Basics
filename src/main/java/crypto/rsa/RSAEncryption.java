package crypto.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAEncryption {
    private BigInteger  d, e, n;

    public RSAEncryption() {
        generateKeys();
    }

    private void generateKeys() {
        SecureRandom random = new SecureRandom();
        int bitLength = 2048;
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        do {
            e = new BigInteger(bitLength / 2, random);
        } while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));

        d = e.modInverse(phi);
    }

    public BigInteger encrypt(String message) {
        return new BigInteger(message.getBytes()).modPow(e, n);
    }

    public String decrypt(BigInteger ciphertext) {
        return new String(ciphertext.modPow(d, n).toByteArray());
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getE() {
        return e;
    }
}