using System.IO;
using System.Security.Cryptography;

namespace DotNetAES.Engines
{
    public partial class AES
    {
        //##########################################################
        //#######  Core Encryption And Decryption Functions  #######
        //##########################################################

        /// <summary>
        /// Encrypts a passed string into a byte array using AES CBC Mode
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        private byte[] Encrypt(byte[] data, byte[] key, byte[] IV)
        {
            //Validates the supplied data
            helpers.CoreValidation(data, key, IV);

            //Compresses the supplied data with GZIP before we encrypt it
            data = helpers.GZIPCompress(data);

            //Stores the results of the encrypted bytes
            byte[] encrypted;

            //Creates an AesCryptoServiceProvider object ready for encrypting     
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                //Sets the requirements for the AES Crypto
                aes.KeySize = theKeySize;
                aes.Mode = cipherMode;

                //Puts the passed Key and IV into place
                aes.Key = key;
                aes.IV = IV;

                //Creates a encryptor to perform the stream transform
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                //Create the streams used for encryption
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        //Writes the data to the cryptoStream so that the end result is encrypted using the supplied ICryptoTransform
                        csEncrypt.Write(data, 0, data.Length);
                    }

                    //Puts the byte array from the memory stream which is now encrypted into the variable
                    encrypted = memoryStream.ToArray();
                }
            }

            // Return the encrypted bytes
            return encrypted;
        }

        /// <summary>
        /// Decrypts a passed encrypted byte array using AES CBC Mode
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        private byte[] Decrypt(byte[] encryptedData, byte[] key, byte[] IV)
        {
            //Validates the supplied data
            helpers.CoreValidation(encryptedData, key, IV);

            //Used to store the results of the decrypted byte array
            byte[] decryptedData = null;

            //Creates an AesCryptoServiceProvider object ready for decrypting
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                //Sets the requirements for the AES Crypto
                aes.KeySize = theKeySize;
                aes.Mode = cipherMode;

                //Puts the passed Key and IV into place
                aes.Key = key;
                aes.IV = IV;

                //Creates a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                //Create the streams used for decryption.
                using (MemoryStream memoryStream = new MemoryStream(encryptedData))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        //Writes the encrypted data to the cryptoStream so that the end result is decrypted using the supplied ICryptoTransform
                        csDecrypt.Write(encryptedData, 0, encryptedData.Length);
                    }

                    //Puts the byte array from the memory stream which is now decrypted into the variable
                    decryptedData = memoryStream.ToArray();
                }
            }

            //Decompress the supplied data with GZIP after its been decrypted
            decryptedData = helpers.GZIPDecompress(decryptedData);

            //Returns the decrypted data
            return decryptedData;
        }
    }
    
}