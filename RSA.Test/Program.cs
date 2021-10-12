using System;
using System.Text;

namespace RSA.Test {
    class Program {
        static void Main(string[] args) {
            var rsa = new RSA(384);

            Console.Write("Input message: ");
            var message = Console.ReadLine();

            var encryptedMessage = rsa.Encrypt(message);
            Console.WriteLine($"Encrypted message: {Convert.ToHexString(encryptedMessage)}");

            var decryptedMessage = rsa.Decrypt(encryptedMessage);
            Console.WriteLine($"Decrypted message: {decryptedMessage}");
        }
    }
}
