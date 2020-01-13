using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Overby.Extensions.AsyncBinaryReaderWriter;

namespace EncryptBlob
{


    /// <summary>
    /// Summary description for CryptoHelper.
    /// </summary>
    public class CryptoHelper
    {
        /// <summary>
        /// Tag to make sure this file is readable/decryptable by this class
        /// </summary>
        private const ulong FC_TAG = 0xFC010203040506CF;

        /// <summary>
        /// The amount of bytes to read from the file
        /// </summary>
        private const int BUFFER_SIZE = 128 * 1024;

        /// <summary>
        /// Checks to see if two byte array are equal
        /// </summary>
        /// <param name="b1">the first byte array</param>
        /// <param name="b2">the second byte array</param>
        /// <returns>true if b1.Length == b2.Length and each byte in b1 is
        /// equal to the corresponding byte in b2</returns>
        private static bool CheckByteArrays(byte[] b1, byte[] b2)
        {
            if (b1.Length == b2.Length)
            {
                for (int i = 0; i < b1.Length; ++i)
                {
                    if (b1[i] != b2[i])
                        return false;
                }
                return true;
            }
            return false;
        }

        /// <summary>
        /// Creates a Rijndael SymmetricAlgorithm for use in EncryptFile and DecryptFile
        /// </summary>
        /// <param name="password">the string to use as the password</param>
        /// <param name="salt">the salt to use with the password</param>
        /// <returns>A SymmetricAlgorithm for encrypting/decrypting with Rijndael</returns>
        private static SymmetricAlgorithm CreateRijndael(string password, byte[] salt)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, salt, "SHA256", 1000);

            SymmetricAlgorithm sma = Rijndael.Create();
            sma.KeySize = 256;
            sma.Key = pdb.GetBytes(32);
            sma.Padding = PaddingMode.PKCS7;
            return sma;
        }

        /// <summary>
        /// Crypto Random number generator for use in EncryptFile
        /// </summary>
        private static RandomNumberGenerator rand = new RNGCryptoServiceProvider();

        /// <summary>
        /// Generates a specified amount of random bytes
        /// </summary>
        /// <param name="count">the number of bytes to return</param>
        /// <returns>a byte array of count size filled with random bytes</returns>
        private static byte[] GenerateRandomBytes(int count)
        {
            byte[] bytes = new byte[count];
            rand.GetBytes(bytes);
            return bytes;
        }

        /// <summary>
        /// This takes an input file and encrypts it into the output file
        /// </summary>
        /// <param name="outStream"></param>
        /// <param name="password">the password for use as the key</param>
        /// <param name="fileStream"></param>
        public static async Task EncryptFileAsync(Stream fileStream, Stream outStream, string password)
        {


            long lSize = fileStream.Length; // the size of the input file for storing
            byte[] bytes = new byte[BUFFER_SIZE]; // the buffer
            int read = -1; // the amount of bytes read from the input file
            int value = 0; // the amount overall read from the input file for progress

            // generate IV and Salt
            byte[] IV = GenerateRandomBytes(16);
            byte[] salt = GenerateRandomBytes(16);

            // create the crypting object
            SymmetricAlgorithm sma = CryptoHelper.CreateRijndael(password, salt);
            sma.IV = IV;

            // write the IV and salt to the beginning of the file
            await outStream.WriteAsync(IV, 0, IV.Length);
            await outStream.WriteAsync(salt, 0, salt.Length);

            // create the hashing and crypto streams
            HashAlgorithm hasher = SHA256.Create();
            await using var cout = new CryptoStream(outStream, sma.CreateEncryptor(), CryptoStreamMode.Write);
            await using (var chash = new CryptoStream(Stream.Null, hasher, CryptoStreamMode.Write))
            {



                // write the size of the file to the output file
                var bw = new AsyncBinaryWriter(cout);
                await bw.WriteAsync(lSize);

                // write the file cryptor tag to the file
                await bw.WriteAsync(FC_TAG);

                // read and the write the bytes to the crypto stream in BUFFER_SIZEd chunks
                while ((read = await fileStream.ReadAsync(bytes, 0, bytes.Length)) != 0)
                {
                    await cout.WriteAsync(bytes, 0, read);
                    await chash.WriteAsync(bytes, 0, read);
                    value += read;
                }

                // flush and close the hashing object
            }

            // read the hash
            byte[] hash = hasher.Hash;

            // write the hash to the end of the file
            await cout.WriteAsync(hash, 0, hash.Length);
        }


    
    }

}
