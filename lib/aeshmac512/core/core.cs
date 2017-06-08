using System;
using System.IO;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace DotNetAES
{
    public static partial class AESHMAC512
    {
        //##########################################################
        //#######  Core Encryption And Decryption Functions  #######
        //##########################################################

        /// <summary>
        /// Core encryption function that deals with GZIP compression, AES CBC Encryption and HMAC SHA512 authentication wrapping
        /// </summary>
        /// <param name="data"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        private static byte[] CoreEncrypt(byte[] data, byte[] cryptKey, byte[] authKey)
        {
            //Compresses the supplied data with GZIP before we encrypt it
            data = Tools.GZIPCompress(data);

            //Generates a new IV for this data encryption
            byte[] IV = CreateByteIV();

            //Encrypts the data using AES CBC
            data = EncryptAESCBC(data, cryptKey, IV);

            //Wraps the encrypted AES data in HMAC512 for authentication integrity
            data = EncryptHMACSHA512(data, authKey, IV);

            //Returns the new HMAC SHA512 -> AES CBC encrypted data
            return data;
        }


        /// <summary>
        /// Core decryption function that deals with GZIP compression, AES CBC Encryption and HMAC SHA512 authentication wrapping
        /// </summary>
        /// <param name="data"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <param name="maxSecondsDifference"></param>
        /// <returns></returns>
        private static byte[] CoreDecrypt(byte[] data, byte[] cryptKey, byte[] authKey, int maxSecondsDifference = 0)
        {
            //Checks the authenticity of the encrypted data supplied, if valid will return the encrypted data and IV
            var calculatedData = DecryptHMACSHA512(data, authKey, maxSecondsDifference);
            //Item1 = IV
            //Item2 = encrypted data

            //Checks Authentication validation went ok and we have the data and IV supplied back
            if (calculatedData != null)
            {
                //Decrypts the data using the key and IV supplied
                data = DecryptAESCBC(calculatedData.Item2, cryptKey, calculatedData.Item1);

                //Decompress the supplied data with GZIP after its been decrypted
                data = Tools.GZIPDecompress(data);

                //Returns the unwrapped and decrypted data
                return data;
            }

            return null;
        }


        //#############################################################
        //#######  AES CBC Encryption And Decryption Functions  #######
        //#############################################################

        /// <summary>
        /// Encrypts a passed string into a byte array using AES CBC Mode
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        private static byte[] EncryptAESCBC(byte[] data, byte[] key, byte[] IV)
        {
            //Validates the supplied data
            Tools.CoreValidation(data, key, IV);

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
        private static byte[] DecryptAESCBC(byte[] encryptedData, byte[] key, byte[] IV)
        {
            //Validates the supplied data
            Tools.CoreValidation(encryptedData, key, IV);

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

            //Returns the decrypted data
            return decryptedData;
        }


        //#################################################################
        //#######  HMAC SHA512 Encryption And Decryption Functions  #######
        //#################################################################

        /// <summary>
        /// Encrypts a passed encrypted byte array using HMAC SHA512
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        private static byte[] EncryptHMACSHA512(byte[] encryptedData, byte[] key, byte[] iv)
        {
            using (var hmac = new HMACSHA512(key))
            {
                using (var encryptionStream = new MemoryStream())
                {
                    using (var binaryWriter = new BinaryWriter(encryptionStream))
                    {
                        //Sets up the current timestamp
                        double timestamp = Tools.DateTimeToUnixTimestamp(DateTime.Now);

                        //Converts it to a byte array
                        byte[] timestampBytes = Tools.ConvertDoubleToByteArray(timestamp);

                        //Prepends a timestamp to the start
                        binaryWriter.Write(timestampBytes);

                        //Prepends the IV
                        binaryWriter.Write(iv);

                        //Adds the encrypted data
                        binaryWriter.Write(encryptedData);

                        //Flushes it to the stream
                        binaryWriter.Flush();

                        //Calculates the new hash tag for authenticating all data
                        var tag = hmac.ComputeHash(encryptionStream.ToArray());

                        //Postpends the tag
                        binaryWriter.Write(tag);
                    }

                    //Returns the calculated byte array from the memory stream
                    return encryptionStream.ToArray();
                }
            }
        }

        /// <summary>
        /// Decrypts a passed byte array using HMAC SHA512
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="authKey"></param>
        /// <param name="maxSecondsDifference"></param>
        /// <returns></returns>
        private static Tuple<byte[], byte[]> DecryptHMACSHA512(byte[] encryptedData, byte[] authKey, int maxSecondsDifference = 0)
        {
            //The HMAC512 data is created in the following order IV -> encrypted data -> authentication tag
            using (var hmac = new HMACSHA512(authKey))
            {
                //Calculates the tag length *divides by 8 to go from bits to bytes*
                int tagLength = hmac.HashSize / 8;

                //Calculates the length of the encrypted data
                int dataLength = (encryptedData.Length - timestampSize - ivSize - tagLength);

                //Throws an exception if the size is to low
                if (encryptedData.Length < (tagLength + timestampSize + ivSize))
                {
                    throw new AuthenticationException("The Authentication check does not match the original calculation");
                }

                //Checks the authentication tag validates and matches correctly, if not will throw authentication exception
				//Note: If this does not throw an exception then its been validated
                AuthenticationTagValidation(authKey, encryptedData, tagLength);

                //Checks if an expiration has been set, if so checks if the HMAC is still valid
                if (maxSecondsDifference > 0)
                {
                    //Extracts the timestamp from the HMAC data
                    byte[] timestampBytes = new byte[timestampSize];
                    Array.Copy(encryptedData, 0, timestampBytes, 0, timestampSize);

                    //Gets the timestamp
                    double timestamp = Tools.ConvertByteArrayToDouble(timestampBytes);

                    //Converts it to DateTime so we can check
                    DateTime dt = Tools.UnixTimeStampToDateTime(timestamp);

                    //Adds the additional time allowance check
                    dt = dt.AddSeconds(maxSecondsDifference);
                    
                    //Gets the current timestamp for right now
                    double currentTimestamp = Tools.DateTimeToUnixTimestamp(DateTime.Now);

                    //Converts this back into a DateTime object using the Unix timestamp
                    DateTime currentDT = Tools.UnixTimeStampToDateTime(currentTimestamp);
                    
                    //Checks if the time difference is out between the two
                    if (dt < currentDT)
                    {
                        throw new AuthenticationException("The Authentication check failed due to the expiration time.");
                    }
                }                

                //Extracts the IV from the HMAC data
                byte[] theIV = new byte[ivSize];
				Array.Copy(encryptedData, timestampSize, theIV, 0, ivSize);

				//Extracts the encrypted data fro the HMAC data
				byte[] data = new byte[dataLength];
				Array.Copy(encryptedData, timestampSize + ivSize, data, 0, dataLength);

				//Returns the IV and data as the authentication tag is valid
				return Tuple.Create(theIV, data);
            }
        }

        /// <summary>
        /// Checks the validitiy of the authentication tag for the HMAC SHA512 function
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="tagLength"></param>
        private static void AuthenticationTagValidation(byte[] key, byte[] data, int tagLength)
        {
            using (var hmac = new HMACSHA512(key))
            {
                //Creates a fresh new tag variable with the calculated length
                byte[] theTag = new byte[tagLength];

                //Copies the supplied authentication tag inside the encrypted data into theTag variable
                Array.Copy(data, data.Length - tagLength, theTag, 0, tagLength);

                //Calculates what the size is for just the IV and data without the authentication tag
                int lengthWithoutTag = data.Length - tagLength;

                //Calculates a new authentication tag using the supplied key, IV and data
                //Note: This is done so we can check if it matches what has been received
                byte[] newTag = hmac.ComputeHash(data, 0, lengthWithoutTag);

                //Checks if the supplied and calculated authentication tags do not match and if so throws an exception
                if(!theTag.SequenceEqual(newTag))
                {
                    throw new AuthenticationException("The Authentication check does not match the original calculation");
                }
            }
        }
        
    }
}