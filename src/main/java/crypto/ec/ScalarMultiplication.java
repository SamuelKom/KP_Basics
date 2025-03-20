package crypto.ec;

import java.math.BigInteger;

public class ScalarMultiplication {
    private final EllipticCurve curve;

    public ScalarMultiplication(EllipticCurve curve) {
        this.curve = curve;
    }

    public ECPoint multiply(ECPoint P, BigInteger k) {
        ECPoint result = ECPoint.INFINITY;
        ECPoint addend = P;

        while (k.signum() > 0) {
            if (k.testBit(0)) {
                result = curve.add(result, addend);
            }
            addend = curve.add(addend, addend);
            k = k.shiftRight(1);
        }
        return result;
    }
}
