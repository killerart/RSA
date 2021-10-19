using System.Numerics;

namespace RSA {
    public static class BigIntegerExtensions {
        public static BigInteger? ModInverse(this BigInteger a, BigInteger m) {
            var (gcd, x, _) = GcdExtended(a, m);
            if (gcd != 1) {
                return null;
            }

            return (x % m + m) % m;
        }

        public static (BigInteger gcd, BigInteger x, BigInteger y) GcdExtended(BigInteger a, BigInteger b) {
            if (a == BigInteger.Zero) {
                return (b, BigInteger.Zero, BigInteger.One);
            }

            var (gcd, x1, y1) = GcdExtended(b % a, a);
            var x = y1 - (b / a) * x1;
            var y = x1;
            return (gcd, x, y);
        }
    }
}
