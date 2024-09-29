using System.Security.Cryptography;
using System.Text;

namespace AuthenticationAPI.Services
{
    public class PasswordService
    {
        private int keySize = int.Parse(Environment.GetEnvironmentVariable("KEY_SIZE")); //64;
        private int iterations = int.Parse(Environment.GetEnvironmentVariable("ITERATIONS")); //350000;
        HashAlgorithmName algorithmName = HashAlgorithmName.SHA512;

        public string HashPassword(string password, out byte[] salt)
        {
            salt = RandomNumberGenerator.GetBytes(keySize);
            var hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iterations,
                algorithmName,
                keySize
            );
            return Convert.ToHexString(hash);
        }

        public bool VerifyPasswordHash(string inputPassword, string storedHash, byte[] storedSalt)
        {
            var newHash = Rfc2898DeriveBytes.Pbkdf2(inputPassword, storedSalt, iterations, algorithmName, keySize);
            return CryptographicOperations.FixedTimeEquals(newHash, Convert.FromHexString(storedHash));
        }
    }
}
