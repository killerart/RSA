using System;

namespace RSA.Test {
    class Program {
        static void Main(string[] args) {
            var rsa = new RSA(2048);

            Console.Write("Input message: ");
            var message = Console.ReadLine();

            var encryptedMessage = rsa.Encrypt(message);
            Console.WriteLine($"\nEncrypted message: {Convert.ToHexString(encryptedMessage)}\n");

            var decryptedMessage = rsa.Decrypt(encryptedMessage);
            Console.WriteLine($"Decrypted message: {decryptedMessage}");
        }
    }
}
