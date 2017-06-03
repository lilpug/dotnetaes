using System;
using System.Security.Cryptography;

namespace DotNetAES
{
    public static partial class AES
    {
        //######################################################
        //#######     Key and IV Generating Functions    #######
        //######################################################

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