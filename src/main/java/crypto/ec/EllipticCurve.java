package crypto.ec;

import java.math.BigInteger;

public class EllipticCurve {
    private final BigInteger a;
    private final BigInteger b;
    private final BigInteger p; // Prime modulus

    public EllipticCurve(BigInteger a, BigInteger b, BigInteger p) {
        this.a = a;
        this.b = b;
        this.p = p;
    }

    public ECPoint add(ECPoint P, ECPoint Q) {
        if (P.isInfinity()) return Q;
        if (Q.isInfinity()) return P;

        BigInteger lambda;
        if (P.x.equals(Q.x) && P.y.equals(Q.y)) {
            // Point doubling
            BigInteger numerator = P.x.pow(2).multiply(BigInteger.valueOf(3)).add(a);
            BigInteger denominator = P.y.multiply(BigInteger.valueOf(2)).modInverse(p);
            lambda = numerator.multiply(denominator).mod(p);
        } else {
            // Regular addition
            BigInteger numerator = Q.y.subtract(P.y);
            BigInteger denominator = Q.x.subtract(P.x).modInverse(p);
            lambda = numerator.multiply(denominator).mod(p);
        }

        BigInteger xR = lambda.pow(2).subtract(P.x).subtract(Q.x).mod(p);
        BigInteger yR = lambda.multiply(P.x.subtract(xR)).subtract(P.y).mod(p);

        return new ECPoint(xR, yR);
    }
}