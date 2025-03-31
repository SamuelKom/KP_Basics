package crypto.dsa;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class DSASignature {

    public static class Signature {
        public BigInteger r;
        public BigInteger s;

        public Signature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }

        // Convert signature to string for network transmission
        public String serialize() {
            return r.toString() + ":" + s.toString();
        }

        // Reconstruct signature from serialized string
        public static Signature deserialize(String serialized) {
            String[] parts = serialized.split(":");
            return new Signature(
                    new BigInteger(parts[0]),
                    new BigInteger(parts[1])
            );
        }
    }

    // Generate SHA-1 Hash
    public static BigInteger sha1Hash(byte[] message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = digest.digest(message);
            return new BigInteger(1, hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 not available", e);
        }
    }

    // Sign Message
    public static Signature sign(byte[] message, DSAKeyPair.KeyPair keyPair) {
        SecureRandom random = new SecureRandom();
        BigInteger k, r, s;

        do {
            // Generate random k where 1 < k < q
            do {
                k = new BigInteger(160, random).mod(keyPair.q);
            } while (k.compareTo(BigInteger.ONE) <= 0);

            // Calculate r
            r = keyPair.g.modPow(k, keyPair.p).mod(keyPair.q);

            // Calculate hash of message
            BigInteger hash = sha1Hash(message);

            // Calculate s
            BigInteger kInverse = k.modInverse(keyPair.q);
            s = kInverse.multiply(hash.add(keyPair.x.multiply(r))).mod(keyPair.q);
        } while (r.equals(BigInteger.ZERO) || s.equals(BigInteger.ZERO));

        return new Signature(r, s);
    }

    // Verify Signature
    public static boolean verify(byte[] message, Signature signature, DSAKeyPair.KeyPair keyPair) {
        // Check signature values are in valid range
        if (signature.r.compareTo(BigInteger.ZERO) <= 0 ||
                signature.r.compareTo(keyPair.q) >= 0 ||
                signature.s.compareTo(BigInteger.ZERO) <= 0 ||
                signature.s.compareTo(keyPair.q) >= 0) {
            return false;
        }

        // Calculate hash of message
        BigInteger hash = sha1Hash(message);

        // Calculate w (s inverse)
        BigInteger w = signature.s.modInverse(keyPair.q);

        // Calculate u1 and u2
        BigInteger u1 = hash.multiply(w).mod(keyPair.q);
        BigInteger u2 = signature.r.multiply(w).mod(keyPair.q);

        // Calculate v
        BigInteger v = keyPair.g.modPow(u1, keyPair.p)
                .multiply(keyPair.y.modPow(u2, keyPair.p))
                .mod(keyPair.p)
                .mod(keyPair.q);

        // Verify signature
        return v.equals(signature.r);
    }
}
