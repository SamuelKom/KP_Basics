package crypto.rsa;

import java.math.BigInteger;
import java.util.*;


public class RSAUtils {

    public static class RSAEncryption {
        private BigInteger privateKey;
        private BigInteger publicKey;
        private BigInteger modulus;

        public RSAEncryption() {
            generateKeys();
        }

        private void generateKeys() {
            BigInteger p = BigInteger.probablePrime(1024, new Random());
            BigInteger q = BigInteger.probablePrime(1024, new Random());

            modulus = p.multiply(q);

            BigInteger phi = p.subtract(BigInteger.ONE)
                    .multiply(q.subtract(BigInteger.ONE));

            publicKey = BigInteger.valueOf(65537);
            privateKey = publicKey.modInverse(phi);
        }

        public byte[] encrypt(byte[] message, BigInteger key, BigInteger mod) {
            BigInteger m = new BigInteger(1, message);
            return m.modPow(key, mod).toByteArray();
        }

        public byte[] decrypt(byte[] encryptedMessage) {
            BigInteger encrypted = new BigInteger(1, encryptedMessage);
            return encrypted.modPow(privateKey, modulus).toByteArray();
        }

        public BigInteger getPublicKey() {
            return publicKey;
        }

        public BigInteger getModulus() {
            return modulus;
        }
    }

    // Elliptic Curve Scalar Multiplication Utility
    public static class ECScalarMultiplication {
        public static class ECPoint {
            private BigInteger x;
            private BigInteger y;
            private BigInteger prime;

            public ECPoint(BigInteger x, BigInteger y, BigInteger prime) {
                this.x = x;
                this.y = y;
                this.prime = prime;
            }

            public ECPoint multiply(BigInteger scalar) {
                ECPoint result = new ECPoint(
                        BigInteger.ZERO,
                        BigInteger.ZERO,
                        prime
                );
                ECPoint current = this;

                while (scalar.compareTo(BigInteger.ZERO) > 0) {
                    if (scalar.mod(BigInteger.TWO).equals(BigInteger.ONE)) {
                        result = addPoints(result, current);
                    }
                    current = doublePoint(current);
                    scalar = scalar.divide(BigInteger.TWO);
                }

                return result;
            }

            private ECPoint addPoints(ECPoint p1, ECPoint p2) {
                BigInteger lambda = p2.y.subtract(p1.y)
                        .multiply(p2.x.subtract(p1.x).modInverse(prime))
                        .mod(prime);

                BigInteger x3 = lambda.multiply(lambda)
                        .subtract(p1.x)
                        .subtract(p2.x)
                        .mod(prime);

                BigInteger y3 = lambda.multiply(p1.x.subtract(x3))
                        .subtract(p1.y)
                        .mod(prime);

                return new ECPoint(x3, y3, prime);
            }

            private ECPoint doublePoint(ECPoint p) {
                BigInteger lambda = p.x.multiply(BigInteger.valueOf(3))
                        .multiply(p.x)
                        .multiply(BigInteger.valueOf(2).multiply(p.y).modInverse(prime))
                        .mod(prime);

                BigInteger x3 = lambda.multiply(lambda)
                        .subtract(p.x.multiply(BigInteger.valueOf(2)))
                        .mod(prime);

                BigInteger y3 = lambda.multiply(p.x.subtract(x3))
                        .subtract(p.y)
                        .mod(prime);

                return new ECPoint(x3, y3, prime);
            }
        }
    }
}