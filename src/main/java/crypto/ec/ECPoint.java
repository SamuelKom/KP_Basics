package crypto.ec;

import java.math.BigInteger;

public class ECPoint {
    public final BigInteger x;
    public final BigInteger y;
    public static final ECPoint INFINITY = new ECPoint(null, null); // Point at infinity

    public ECPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public boolean isInfinity() {
        return this.x == null || this.y == null;
    }
}