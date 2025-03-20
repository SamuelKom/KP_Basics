package crypto.ec;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

public class ScalarMultiplicationTest {

    @Test
    public void testScalarMultiplication() {
        // Define a simple elliptic curve y^2 = x^3 + ax + b over a prime field p
        BigInteger a = new BigInteger("2");
        BigInteger b = new BigInteger("3");
        BigInteger p = new BigInteger("97"); // Small prime for testing
        EllipticCurve curve = new EllipticCurve(a, b, p);

        // Define a base point G (generator)
        ECPoint G = new ECPoint(new BigInteger("3"), new BigInteger("6"));

        // Multiply G by a scalar (e.g., 2)
        ScalarMultiplication multiplier = new ScalarMultiplication(curve);
        ECPoint result = multiplier.multiply(G, new BigInteger("2"));

        // Expected result for 2 * G (manually computed)
        ECPoint expected = new ECPoint(new BigInteger("80"), new BigInteger("10"));

        assertEquals(expected.x, result.x, "X coordinate should match");
        assertEquals(expected.y, result.y, "Y coordinate should match");
    }
}
