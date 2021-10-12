using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RSA {
    public class RSA {
        private static readonly BigInteger E = 65537;

        private BigInteger P;
        private BigInteger Q;
        private BigInteger N;
        private BigInteger DN;
        private BigInteger D;

        public RSA(int keySize) {
            GenerateKey(keySize);
        }

        private void GenerateRandomPrimes(int keySize) {
            using var rsa        = new RSACryptoServiceProvider(keySize);
            var       parameters = rsa.ExportParameters(true);
            P = new BigInteger(parameters.P, true, true);
            Q = new BigInteger(parameters.Q, true, true);
        }

        private void GenerateKey(int keySize) {
            do {
                GenerateRandomPrimes(keySize);
                DN = (P - 1) * (Q - 1);
            } while (BigInteger.GreatestCommonDivisor(E, DN) != BigInteger.One);

            N = P * Q;
            D = E.ModInverse(DN) ?? throw new Exception("There is no mod inverse");
        }

        public byte[] Encrypt(string message) {
            var messageBytes  = Encoding.Default.GetBytes(message);
            var messageBigInt = new BigInteger(messageBytes, true);
            messageBigInt = BigInteger.ModPow(messageBigInt, E, N);
            return messageBigInt.ToByteArray(true);
        }

        public string Decrypt(byte[] encryptedMessage) {
            var messageBigInt = new BigInteger(encryptedMessage, true);
            messageBigInt = BigInteger.ModPow(messageBigInt, D, N);
            var messageBytes = messageBigInt.ToByteArray(true);
            return Encoding.Default.GetString(messageBytes);
        }
    }
}
