using System;
using System.Linq;
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

        public RSA(int keySize) {
            if (keySize % 16 != 0) {
                keySize += 16 - keySize % 16;
            }

            keySize        = Math.Min(384, Math.Max(keySize, 2048));
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
            return Encrypt(messageBytes);
        }

        public byte[] Encrypt(ReadOnlyMemory<byte> message) {
            var numOfBlocks = message.Length / _blockByteSize;
            if (message.Length % _blockByteSize != 0) {
                numOfBlocks++;
            }

            var blocks = new ReadOnlyMemory<byte>[numOfBlocks];
            for (var i = 0; i < numOfBlocks; i++) {
                var start = i * _blockByteSize;
                try {
                    blocks[i] = message.Slice(start, _blockByteSize);
                } catch (ArgumentOutOfRangeException) {
                    blocks[i] = message.Slice(start);
                }
            }

            var encryptedBlocks = new byte[numOfBlocks][];
            Parallel.For(0,
                         numOfBlocks,
                         i => {
                             var messageBigInt = new BigInteger(blocks[i].Span, true);
                             messageBigInt      = BigInteger.ModPow(messageBigInt, E, N);
                             encryptedBlocks[i] = messageBigInt.ToByteArray(true);
                         });
            return encryptedBlocks.SelectMany(block => block).ToArray();
        }

        public string Decrypt(ReadOnlyMemory<byte> encryptedMessage) {
            var numOfBlocks = encryptedMessage.Length / _blockByteSize;

            var blocks = new ReadOnlyMemory<byte>[numOfBlocks];
            for (var i = 0; i < numOfBlocks; i++) {
                blocks[i] = encryptedMessage.Slice(i * _blockByteSize, _blockByteSize);
            }

            var decryptedBlocks = new byte[numOfBlocks][];
            Parallel.For(0,
                         numOfBlocks,
                         i => {
                             var messageBigInt = new BigInteger(blocks[i].Span, true);
                             messageBigInt      = BigInteger.ModPow(messageBigInt, D, N);
                             decryptedBlocks[i] = messageBigInt.ToByteArray(true);
                         });

            var decryptedBytes = decryptedBlocks.SelectMany(block => block).ToArray();

            return Encoding.Default.GetString(decryptedBytes);
        }
    }
}
