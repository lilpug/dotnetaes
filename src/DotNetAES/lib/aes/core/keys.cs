using System;
using System.Security.Cryptography;

namespace DotNetAES.Engines
{
    public partial class AES
    {
        //######################################################
        //#######     Key and IV Generating Functions    #######
        //######################################################

        /// <summary>
        /// Generates an IV and returns it in base64 string format
        /// </summary>
        /// <returns></returns>
        public string CreateAESStringIV()
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
        public byte[] CreateAESByteIV()
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
        public string CreateAESStringKey()
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
        public byte[] CreateAESByteKey()
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