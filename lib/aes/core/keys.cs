using System;
using System.Security.Cryptography;

namespace DotNetAES
{
    public static partial class AES
    {
        //######################################################
        //#######     Key and IV Generating Functions    #######
        //######################################################

        /// <summary>
        /// Generates an IV and returns it in base64 string format
        /// </summary>
        /// <returns></returns>
        public static string CreateStringIV()
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = theKeySize;
                aes.Mode = cipherMode;
                aes.GenerateIV();
                return Convert.ToBase64String(aes.IV);
            }
        }

        /// <summary>
        /// Generates an IV and returns it in a byte array format
        /// </summary>
        /// <returns></returns>
        public static byte[] CreateByteIV()
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = theKeySize;
                aes.Mode = cipherMode;
                aes.GenerateIV();
                return aes.IV;
            }
        }

        /// <summary>
        /// Generates a 256 key and returns it in base64 string format
        /// </summary>
        /// <returns></returns>
        public static string CreateStringKey()
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = theKeySize;
                aes.Mode = cipherMode;
                aes.GenerateKey();
                return Convert.ToBase64String(aes.Key);
            }
        }

        /// <summary>
        /// Generates a 256 key and returns it in a byte array format
        /// </summary>
        /// <returns></returns>
        public static byte[] CreateByteKey()
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = theKeySize;
                aes.Mode = cipherMode;
                aes.GenerateKey();
                return aes.Key;
            }
        }
    }    
}