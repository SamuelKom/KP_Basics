package crypto.ec;

import java.math.BigInteger;

public class EllipticCurve {
    public static class Point {
        public BigInteger x, y;
        public boolean isInfinity;

        public Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
            this.isInfinity = false;
        }

        public static Point infinity() {
            Point p = new Point(BigInteger.ZERO, BigInteger.ZERO);
            p.isInfinity = true;
            return p;
        }
    }

    private final BigInteger a, b, p;

    public EllipticCurve(BigInteger a, BigInteger b, BigInteger p) {
        this.a = a;
        this.b = b;
        this.p = p;
    }

    public boolean isValidPoint(Point P) {
        if (P.isInfinity) return true;

        BigInteger left = P.y.modPow(BigInteger.TWO, p);
        BigInteger right = P.x.modPow(BigInteger.valueOf(3), p)
                .add(a.multiply(P.x)).add(b).mod(p);

        return left.equals(right);
    }

    public Point add(Point P, Point Q) {
        if (!isValidPoint(P) || !isValidPoint(Q)) {
            throw new IllegalArgumentException("Invalid point on the curve");
        }

        if (P.isInfinity) return Q;
        if (Q.isInfinity) return P;

        if (P.x.equals(Q.x) && P.y.equals(Q.y.negate().mod(p))) {
            return Point.infinity();
        }

        BigInteger lambda;
        if (P.x.equals(Q.x) && P.y.equals(Q.y)) {
            lambda = P.x.pow(2).multiply(BigInteger.valueOf(3)).add(a)
                    .multiply(P.y.multiply(BigInteger.TWO).modInverse(p)).mod(p);
        } else {
            lambda = Q.y.subtract(P.y).multiply(Q.x.subtract(P.x).modInverse(p)).mod(p);
        }

        BigInteger xR = lambda.pow(2).subtract(P.x).subtract(Q.x).mod(p);
        BigInteger yR = lambda.multiply(P.x.subtract(xR)).subtract(P.y).mod(p);

        Point result = new Point(xR, yR);
        if (!isValidPoint(result)) {
            throw new IllegalStateException("Resulting point is invalid");
        }

        return result;
    }

    public Point scalarMultiply(Point P, BigInteger k) {
        if (!isValidPoint(P)) {
            throw new IllegalArgumentException("Invalid point on the curve");
        }

        Point R = Point.infinity();
        Point base = P;

        while (k.signum() > 0) {
            if (k.testBit(0)) {
                R = add(R, base);
            }
            base = add(base, base);
            k = k.shiftRight(1);
        }
        return R;
    }

    public static void main(String[] args) {
        // Define curve parameters: y^2 = x^3 + ax + b (mod p)
        BigInteger a = BigInteger.valueOf(2);
        BigInteger b = BigInteger.valueOf(3);
        BigInteger p = BigInteger.valueOf(97); // A prime number

        EllipticCurve ec = new EllipticCurve(a, b, p);

        // Define a point on the curve
        EllipticCurve.Point P = new EllipticCurve.Point(BigInteger.valueOf(3), BigInteger.valueOf(6));

        // Verify if P is valid
        System.out.println("P is valid: " + ec.isValidPoint(P));
        System.out.println("P: (" + P.x + ", " + P.y + ")");


        // Perform scalar multiplication
        BigInteger k = BigInteger.valueOf(3);
        EllipticCurve.Point result = ec.scalarMultiply(P, k);

        // Check if the resulting point is still on the curve
        System.out.println("Resulting point: (" + result.x + ", " + result.y + ")");
        System.out.println("Result is valid: " + ec.isValidPoint(result));
    }
}
