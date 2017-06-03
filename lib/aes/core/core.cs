using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

namespace DotNetAES
{
    public static partial class AES
    {
        //##################################################################
        //#######  Core Serialization And Deserialization Functions  #######
        //##################################################################

        //This function serializes an object to byte array
        private static byte[] SerializeToBytes(object data)
        {
            //Loads a memory stream
            using (MemoryStream stream = new MemoryStream())
            {
                //Initialises the formatter
                IFormatter formatter = new BinaryFormatter();

                //Uses the formatter to serialize the object type into a byte array
                formatter.Serialize(stream, data);

                //Returns the byte array
                return stream.ToArray();
            }
        }

        //This function deserialize a byte array to a specified type
        public static T DerializeFromBytes<T>(byte[] data)
        {            
            //Checks if any data has been supplied
            if (data != null && data.Length > 0)
            {
                try
                {
                    //Stores the data types
                    T newDataType;

                    //Initialises the binary formatter
                    BinaryFormatter binaryFormatter = new BinaryFormatter();

                    //Loads a memory stream with the supplied data byte array
                    using (MemoryStream memoryStream = new MemoryStream(data))
                    {
                        //Reads the byte array from the memory stream
                        memoryStream.Seek(0, SeekOrigin.Begin);

                        //Uses the binary formatter to deserialise it back into the specified type
                        newDataType = (T)binaryFormatter.Deserialize(memoryStream);
                    }

                    //returns the data
                    return newDataType;
                }
                catch
                {
                    throw new InvalidCastException("The data type is not the same data type that was encrypted.");
                }
            }
            return default(T);
        }

        
        //##########################################################
        //#######  Core Encryption And Decryption Functions  #######
        //##########################################################

        //This function encrypts a passed string into a byte array using AES CBC Mode
        private static byte[] Encrypt(byte[] data, byte[] key, byte[] IV)
        {
            //Validates the supplied data
            CoreValidation(data, key, IV);

            //Compresses the supplied data with GZIP before we encrypt it
            data = Compress(data);

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
        
        //This function decrypts a passed encrypted byte array using AES CBC Mode
        private static byte[] Decrypt(byte[] encryptedData, byte[] key, byte[] IV)
        {
            //Validates the supplied data
            CoreValidation(encryptedData, key, IV);

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
            decryptedData = Decompress(decryptedData);

            //Returns the decrypted data
            return decryptedData;
        }
    }
    
}