using System;
using System.Security.Cryptography;

namespace DotNetAES
{
    public static partial class AESHMAC512
    {
        //######################################################
        //#######     Key and IV Generating Functions    #######
        //######################################################

		/// <summary>
        /// Generates the HMACSHA512 key and returns it in base64 string format
        /// </summary>
        /// <returns></returns>
        public static string CreateStringAuthenticationKey()
        {
            using (HMACSHA512 hmac = new HMACSHA512())
            {
                byte[] key = hmac.Key;

                //Returns the key in a base64 string format
                return Convert.ToBase64String(key);
            }
        }

		/// <summary>
        /// Generates the HMACSHA512 key and returns it in a byte array format
        /// </summary>
        /// <returns></returns>
        public static byte[] CreateByteAuthenticationKey()
        {
            using (HMACSHA512 hmac = new HMACSHA512())
            {
                //returns a random generate HMACSHA512 key
                return hmac.Key;
            }
        }

		
        /// <summary>
        /// Generates an IV and returns it in a byte array format
        /// </summary>
        /// <returns></returns>
        private static byte[] CreateByteIV()
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
        /// Generates an AES 256 key and returns it in base64 string format
        /// </summary>
        /// <returns></returns>
        public static string CreateStringAESKey()
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
        /// Generates an AES 256 key and returns it in a byte array format
        /// </summary>
        /// <returns></returns>
        public static byte[] CreateByteAESKey()
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