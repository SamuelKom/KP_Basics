package crypto.dsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public class DSAKeyPair {
    private static final int KEY_LENGTH = 1024;
    private static final int CERTAINTY = 100;

    // Key Generation Class
    public static class KeyPair {
        public BigInteger p;    // Prime modulus
        public BigInteger q;    // Prime order of subgroup
        public BigInteger g;    // Generator of subgroup
        public BigInteger x;    // Private key
        public BigInteger y;    // Public key

        public KeyPair(BigInteger p, BigInteger q, BigInteger g, BigInteger x, BigInteger y) {
            this.p = p;
            this.q = q;
            this.g = g;
            this.x = x;
            this.y = y;
        }

        // Convert public key to string for network transmission
        public String serializePublicKey() {
            return p.toString() + ":" +
                    q.toString() + ":" +
                    g.toString() + ":" +
                    y.toString();
        }

        // Reconstruct public key from serialized string
        public static KeyPair deserializePublicKey(String serialized) {
            String[] parts = serialized.split(":");
            return new KeyPair(
                    new BigInteger(parts[0]),
                    new BigInteger(parts[1]),
                    new BigInteger(parts[2]),
                    BigInteger.ZERO,
                    new BigInteger(parts[3])
            );
        }
    }

    // Generate DSA Key Pair
    public static KeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();

        // Generate safe prime p
        BigInteger p, q, g;
        do {
            q = BigInteger.probablePrime(160, random);  // SHA-1 hash length is 160 bits
            p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
        } while (!p.isProbablePrime(CERTAINTY));

        // Find generator g
        BigInteger h = BigInteger.TWO;
        g = h.modPow(p.subtract(BigInteger.ONE).divide(q), p);
        while (g.equals(BigInteger.ONE)) {
            h = h.add(BigInteger.ONE);
            g = h.modPow(p.subtract(BigInteger.ONE).divide(q), p);
        }

        // Generate private key x
        BigInteger x = new BigInteger(160, random).mod(q);

        // Generate public key y
        BigInteger y = g.modPow(x, p);

        return new KeyPair(p, q, g, x, y);
    }
}
