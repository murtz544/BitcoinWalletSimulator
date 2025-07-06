using System;
using System.Security.Cryptography;
using System.Text;

namespace BitcoinCoreSimulator
{
    public static class BitcoinCoreKdf
    {
        // Fixed test parameters for proof of concept
        private static readonly string MASTER_KEY = "9f2da8671cbe33da22a7431f5b9928cc7e00abcd119944ee768855aa32bcde01";
        private static readonly string SALT = "a461ec31a1bfd17d";
        private static readonly int ITERATIONS = 1000;
        private static readonly string PASSPHRASE = "Azhar";

        public static string DeriveKey(string masterKeyHex, string saltHex, int iterations, string passphrase)
        {
            try
            {
                // Bitcoin Core uses the passphrase as the password input, not the master key
                byte[] password = Encoding.UTF8.GetBytes(passphrase);
                byte[] salt = HexToBytes(saltHex);

                // key = 32 bytes, iv = 16 bytes
                byte[] key = new byte[32];
                byte[] iv = new byte[16];

                EvpBytesToKey_SHA512(password, salt, iterations, key, iv);

                string keyHex = BytesToHex(key);
                return $"$bitcoin$64${keyHex}$16${saltHex}${iterations}$2$00$2$00";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error deriving key: {ex.Message}");
                return string.Empty;
            }
        }

        private static void EvpBytesToKey_SHA512(byte[] password, byte[] salt, int count, byte[] key, byte[] iv)
        {
            using (var sha512 = SHA512.Create())
            {
                int keyLen = key.Length;
                int ivLen = iv.Length;
                int totalLen = keyLen + ivLen;
                int hashLen = 64; // SHA512 produces 64 bytes

                byte[] result = new byte[totalLen];
                byte[] hash = new byte[0];
                int resultPos = 0;

                // Standard EVP_BytesToKey algorithm
                while (resultPos < totalLen)
                {
                    // Prepare input for this round
                    byte[] input = new byte[hash.Length + password.Length + (salt?.Length ?? 0)];
                    int inputPos = 0;

                    // Add previous hash if not first iteration
                    if (hash.Length > 0)
                    {
                        Array.Copy(hash, 0, input, inputPos, hash.Length);
                        inputPos += hash.Length;
                    }

                    // Add password
                    Array.Copy(password, 0, input, inputPos, password.Length);
                    inputPos += password.Length;

                    // Add salt if provided
                    if (salt != null && salt.Length > 0)
                    {
                        Array.Copy(salt, 0, input, inputPos, salt.Length);
                    }

                    // Compute initial hash
                    hash = sha512.ComputeHash(input);

                    // Apply iterations
                    for (int i = 1; i < count; i++)
                    {
                        hash = sha512.ComputeHash(hash);
                    }

                    // Copy as much as we can from this hash
                    int copyLen = Math.Min(hashLen, totalLen - resultPos);
                    Array.Copy(hash, 0, result, resultPos, copyLen);
                    resultPos += copyLen;
                }

                // Extract key and IV from result
                Array.Copy(result, 0, key, 0, keyLen);
                Array.Copy(result, keyLen, iv, 0, ivLen);
            }
        }

        private static byte[] HexToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex))
                throw new ArgumentException("Hex string cannot be null or empty", nameof(hex));

            hex = hex.Trim();
            if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                hex = hex[2..];

            if (hex.Length % 2 != 0)
                throw new ArgumentException("Hex string must have even length", nameof(hex));

            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        private static string BytesToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        // Test method to verify our implementation
        public static void RunTests()
        {
            Console.WriteLine("=== Bitcoin Core Wallet Key Derivation Simulator ===");
            Console.WriteLine("Proof of Concept - Fixed Parameters for Testing");
            Console.WriteLine();

            Console.WriteLine("Fixed Parameters:");
            Console.WriteLine($"Master Key: {MASTER_KEY}");
            Console.WriteLine($"Salt: {SALT}");
            Console.WriteLine($"Iterations: {ITERATIONS}");
            Console.WriteLine($"Passphrase: {PASSPHRASE}");
            Console.WriteLine();

            Console.WriteLine("Testing with 1000 iterations:");
            string result1 = DeriveKey(MASTER_KEY, SALT, 1000, PASSPHRASE);
            Console.WriteLine($"Result: {result1}");
            Console.WriteLine();

            Console.WriteLine("Testing with 2000 iterations:");
            string result2 = DeriveKey(MASTER_KEY, SALT, 2000, PASSPHRASE);
            Console.WriteLine($"Result: {result2}");
            Console.WriteLine();

            Console.WriteLine("Expected Bitcoin Core format outputs:");
            Console.WriteLine("1000 iterations should produce: $bitcoin$64$52ffd2336d265736bdfce4c2b8f3568dc062f7da2c86b9c18d1b146fdc5e8ca1$16$a461ec31a1bfd17d$1000$2$00$2$00");
            Console.WriteLine("2000 iterations should produce: $bitcoin$64$28b263d3a76dee9d7e7951494426d21a8b921d1541ee82e905d80d49c8facba4$16$a461ec31a1bfd17d$2000$2$00$2$00");
            Console.WriteLine();

            Console.WriteLine("Hash verification:");
            Console.WriteLine("If this matches your C++ Bitcoin Core implementation,");
            Console.WriteLine("the derived keys should be identical for the same parameters.");

            // Debug information
            Console.WriteLine("\n=== Debug Information ===");
            Console.WriteLine($"Master Key bytes: {BitConverter.ToString(HexToBytes(MASTER_KEY)).Replace("-", "")}");
            Console.WriteLine($"Salt bytes: {BitConverter.ToString(HexToBytes(SALT)).Replace("-", "")}");

            // Step-by-step verification
            Console.WriteLine("\n=== Step-by-step verification for 1000 iterations ===");
            DebugEvpBytesToKey(Encoding.UTF8.GetBytes(PASSPHRASE), HexToBytes(SALT), 1000);
        }

        private static void DebugEvpBytesToKey(byte[] password, byte[] salt, int count)
        {
            using (var sha512 = SHA512.Create())
            {
                Console.WriteLine($"Password: {BytesToHex(password)} ('{Encoding.UTF8.GetString(password)}')");
                Console.WriteLine($"Salt: {BytesToHex(salt)}");
                Console.WriteLine($"Iterations: {count}");

                int keyLen = 32;
                int ivLen = 16;
                int totalLen = keyLen + ivLen;
                int hashLen = 64; // SHA512 produces 64 bytes

                byte[] result = new byte[totalLen];
                byte[] hash = new byte[0];
                int resultPos = 0;
                int round = 0;

                // Standard EVP_BytesToKey algorithm
                while (resultPos < totalLen)
                {
                    Console.WriteLine($"\n--- Round {round + 1} ---");

                    // Prepare input for this round
                    byte[] input = new byte[hash.Length + password.Length + (salt?.Length ?? 0)];
                    int inputPos = 0;

                    // Add previous hash if not first iteration
                    if (hash.Length > 0)
                    {
                        Array.Copy(hash, 0, input, inputPos, hash.Length);
                        inputPos += hash.Length;
                        Console.WriteLine($"Previous hash: {BytesToHex(hash)}");
                    }

                    // Add password
                    Array.Copy(password, 0, input, inputPos, password.Length);
                    inputPos += password.Length;

                    // Add salt if provided
                    if (salt != null && salt.Length > 0)
                    {
                        Array.Copy(salt, 0, input, inputPos, salt.Length);
                    }

                    Console.WriteLine($"Input: {BytesToHex(input)}");

                    // Compute initial hash
                    hash = sha512.ComputeHash(input);
                    Console.WriteLine($"Hash after initial: {BytesToHex(hash)}");

                    // Apply iterations
                    for (int i = 1; i < count; i++)
                    {
                        hash = sha512.ComputeHash(hash);
                        if (i <= 3 || i == count - 1)
                        {
                            Console.WriteLine($"Hash after iteration {i + 1}: {BytesToHex(hash)}");
                        }
                        else if (i == 4)
                        {
                            Console.WriteLine("...");
                        }
                    }

                    // Copy as much as we can from this hash
                    int copyLen = Math.Min(hashLen, totalLen - resultPos);
                    Array.Copy(hash, 0, result, resultPos, copyLen);
                    resultPos += copyLen;

                    Console.WriteLine($"Copied {copyLen} bytes to result");
                    round++;
                }

                // Extract key and IV from result
                byte[] key = new byte[keyLen];
                byte[] iv = new byte[ivLen];
                Array.Copy(result, 0, key, 0, keyLen);
                Array.Copy(result, keyLen, iv, 0, ivLen);

                Console.WriteLine($"\nFinal result: {BytesToHex(result)}");
                Console.WriteLine($"Extracted key (32 bytes): {BytesToHex(key)}");
                Console.WriteLine($"Extracted IV (16 bytes): {BytesToHex(iv)}");
            }
        }

        static void Main(string[] args)
        {
            try
            {
                RunTests();

                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Application error: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                Console.ReadKey();
            }
        }
    }
}