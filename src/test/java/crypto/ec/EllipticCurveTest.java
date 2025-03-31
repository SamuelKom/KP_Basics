package crypto.ec;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

class EllipticCurveTest {

    private final BigInteger a = BigInteger.valueOf(2);
    private final BigInteger b = BigInteger.valueOf(3);
    private final BigInteger p = BigInteger.valueOf(97);
    private final EllipticCurve ec = new EllipticCurve(a, b, p);
    private final EllipticCurve.Point P = new EllipticCurve.Point(BigInteger.valueOf(3), BigInteger.valueOf(6));

    @Test
    void testValidPoint() {
        assertTrue(ec.isValidPoint(P), "Point P should be valid on the curve");
    }

    @Test
    void testInvalidPoint() {
        EllipticCurve.Point invalidPoint = new EllipticCurve.Point(BigInteger.valueOf(10), BigInteger.valueOf(10));
        assertFalse(ec.isValidPoint(invalidPoint), "Point should be invalid on the curve");
    }

    @Test
    void testPointAddition() {
        EllipticCurve.Point Q = new EllipticCurve.Point(BigInteger.valueOf(3), BigInteger.valueOf(91)); // P + Q should be infinity
        EllipticCurve.Point result = ec.add(P, Q);
        assertTrue(result.isInfinity, "P + Q should be the point at infinity");
    }

    @Test
    void testScalarMultiplication() {
        BigInteger k = BigInteger.valueOf(5);
        EllipticCurve.Point result = ec.scalarMultiply(P, k);
        assertTrue(ec.isValidPoint(result), "Resulting point should still be on the curve");
    }
}