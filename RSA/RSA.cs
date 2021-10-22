using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSA {
    public class RSA {
        private static readonly BigInteger E = 65537;

        private BigInteger P;
        private BigInteger Q;
        private BigInteger N;
        private BigInteger DN;
        private BigInteger D;

        private readonly int _blockByteSize;

        public RSA(int keySize = 2048) {
            if (keySize % 16 != 0) {
                keySize += 16 - keySize % 16;
            }

            keySize        = Math.Max(384, keySize);
            _blockByteSize = keySize / 8;
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
            var messageBytes = Encoding.Default.GetBytes(message);
            return ConvertMessage(messageBytes, E);
        }

        public string Decrypt(ReadOnlyMemory<byte> encryptedMessage) {
            var decryptedBytes = ConvertMessage(encryptedMessage, D);
            return Encoding.Default.GetString(decryptedBytes);
        }

        private byte[] ConvertMessage(ReadOnlyMemory<byte> message, BigInteger exponent) {
            var numOfBlocks = message.Length / _blockByteSize;
            if (message.Length % _blockByteSize != 0) {
                numOfBlocks++;
            }

            var encryptedMessage = new byte[numOfBlocks * _blockByteSize];
            Parallel.For(0,
                         numOfBlocks,
                         i => {
                             var start = i * _blockByteSize;

                             ReadOnlyMemory<byte> block;
                             try {
                                 block = message.Slice(start, _blockByteSize);
                             } catch (ArgumentOutOfRangeException) {
                                 block = message.Slice(start);
                             }

                             var messageBigInt = new BigInteger(block.Span, true);
                             messageBigInt = BigInteger.ModPow(messageBigInt, exponent, N);
                             var encryptedBlock = encryptedMessage.AsSpan().Slice(start, _blockByteSize);
                             messageBigInt.TryWriteBytes(encryptedBlock, out _, true);
                         });
            return encryptedMessage;
        }
    }
}
