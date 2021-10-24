using System;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

// ReSharper disable InconsistentNaming

namespace RSA {
    public class RSA {
        private static readonly BigInteger e = 65537;

        private BigInteger p;
        private BigInteger q;
        private BigInteger n;
        private BigInteger d;

        private readonly int _blockByteSize;

        public RSA(int keySize = 2048) {
            if (keySize % 64 != 0) {
                keySize += 64 - keySize % 64;
            }

            keySize        = Math.Max(512, keySize);
            _blockByteSize = keySize / 8;
            GenerateKey(keySize);
        }

        private void GenerateRandomPrimes(int keySize) {
            using var rsa        = System.Security.Cryptography.RSA.Create(keySize);
            var       parameters = rsa.ExportParameters(true);
            p = new BigInteger(parameters.P, true, true);
            q = new BigInteger(parameters.Q, true, true);
        }

        private void GenerateKey(int keySize) {
            BigInteger dn;
            do {
                GenerateRandomPrimes(keySize);
                dn = (p - 1) * (q - 1);
            } while (BigInteger.GreatestCommonDivisor(e, dn) != BigInteger.One);

            n = p * q;
            d = e.ModInverse(dn) ?? throw new Exception("There is no mod inverse");
        }

        public byte[] Encrypt(string message) {
            var messageBytes = Encoding.Default.GetBytes(message);
            return ConvertMessage(messageBytes, e);
        }

        public string Decrypt(ReadOnlyMemory<byte> encryptedMessage) {
            var decryptedBytes = ConvertMessage(encryptedMessage, d);
            return Encoding.Default.GetString(decryptedBytes).TrimEnd('\0');
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

                             var blockAsNum = new BigInteger(block.Span, true);
                             blockAsNum = blockAsNum.ModPow(exponent, n);
                             var encryptedBlock = encryptedMessage.AsSpan().Slice(start, _blockByteSize);
                             blockAsNum.TryWriteBytes(encryptedBlock, out _, true);
                         });
            return encryptedMessage;
        }
    }
}
