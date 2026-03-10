using System.Security.Cryptography;
using System.Text;

namespace ParallelBlockCipher.Crypto
{
    public static class KeyDerivation
    {
        public static byte[] DeriveKey(string password, byte[] salt, int keySizeBytes = 32, int iterations = 100_000)
        {
            using var kdf = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256);
            return kdf.GetBytes(keySizeBytes);
        }
    }
}
