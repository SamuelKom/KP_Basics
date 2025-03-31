package crypto.ec;

import java.math.BigInteger;

public class EllipticCurve {
    public static class Point {
        public BigInteger x, y;
        public boolean isInfinity;

        /**
         * Constructs a point with given coordinates.
         * @param x X-coordinate of the point.
         * @param y Y-coordinate of the point.
         */
        public Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
            this.isInfinity = false;
        }

        /**
         * Returns the point at infinity (neutral element in elliptic curve operations).
         * @return Point at infinity.
         */
        public static Point infinity() {
            Point p = new Point(BigInteger.ZERO, BigInteger.ZERO);
            p.isInfinity = true;
            return p;
        }
    }

    private final BigInteger a, b, p;

    /**
     * Constructs an elliptic curve defined by the equation y^2 = x^3 + ax + b over a finite field p.
     * @param a Coefficient 'a' of the curve equation.
     * @param b Coefficient 'b' of the curve equation.
     * @param p Prime modulus defining the finite field.
     */
    public EllipticCurve(BigInteger a, BigInteger b, BigInteger p) {
        this.a = a;
        this.b = b;
        this.p = p;
    }

    /**
     * Checks if a given point lies on the elliptic curve.
     * @param P The point to check.
     * @return True if the point is on the curve, false otherwise.
     */
    public boolean isValidPoint(Point P) {
        if (P.isInfinity) return true;

        BigInteger left = P.y.modPow(BigInteger.TWO, p);
        BigInteger right = P.x.modPow(BigInteger.valueOf(3), p)
                .add(a.multiply(P.x)).add(b).mod(p);

        return left.equals(right);
    }

    /**
     * Adds two points on the elliptic curve.
     * @param P First point.
     * @param Q Second point.
     * @return The resulting point after addition.
     */
    public Point add(Point P, Point Q) {
        if (!isValidPoint(P) || !isValidPoint(Q)) {
            throw new IllegalArgumentException("Invalid point on the curve");
        }

        // Handles special cases
        if (P.isInfinity) return Q;
        if (Q.isInfinity) return P;

        // Checking for inverse points (P + (-P) = infinity)
        if (P.x.equals(Q.x) && P.y.equals(Q.y.negate().mod(p))) {
            return Point.infinity();
        }

        BigInteger lambda;
        if (P.x.equals(Q.x) && P.y.equals(Q.y)) {
            // Point doubling formula
            lambda = P.x.pow(2).multiply(BigInteger.valueOf(3)).add(a)
                    .multiply(P.y.multiply(BigInteger.TWO).modInverse(p)).mod(p);
        } else {
            // Point addition formula
            lambda = Q.y.subtract(P.y).multiply(Q.x.subtract(P.x).modInverse(p)).mod(p);
        }

        // Compute new point x and y coordinates
        BigInteger xR = lambda.pow(2).subtract(P.x).subtract(Q.x).mod(p);
        BigInteger yR = lambda.multiply(P.x.subtract(xR)).subtract(P.y).mod(p);

        Point result = new Point(xR, yR);
        if (!isValidPoint(result)) {
            throw new IllegalStateException("Resulting point is invalid");
        }

        return result;
    }

    /**
     * Performs scalar multiplication of a point on the elliptic curve using the double-and-add method.
     * @param P The base point to multiply.
     * @param k The scalar multiplier.
     * @return The resulting point after multiplication.
     */
    public Point scalarMultiply(Point P, BigInteger k) {
        if (!isValidPoint(P)) {
            throw new IllegalArgumentException("Invalid point on the curve");
        }

        // Start at infinity (neutral element)
        Point R = Point.infinity();
        Point base = P;

        while (k.signum() > 0) {
            // Check if the least significant bit is 1
            if (k.testBit(0)) {
                R = add(R, base);
            }
            // Double the base point
            base = add(base, base);
            // Right shift k
            k = k.shiftRight(1);
        }
        return R;
    }

    // Only for testing purposes
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
