using System;
using System.IO;
using System.Threading;

namespace DotNetAES
{
    public static partial class AESHMAC512
    {
        //######################################################
        //#######           Encryption Functions         #######
        //######################################################
        

		/// <summary>
        /// Encrypts the data specified and returns it in a base64 string format
        /// </summary>
        /// <param name="data"></param>
        /// <param name="cryptKey"></param>
		/// <param name="authKey"></param>
        /// <returns></returns>
        public static string EncryptToString(object data, object cryptKey, object authKey)
        {
            byte[] normalKey = Tools.KeyValidation(cryptKey);
            byte[] authenticationKey = Tools.KeyValidation(authKey);

            //Serialises the data into a byte[]
            byte[] theData = Tools.SerializeToBytes(data);

            //Encrypts the serialised data
            byte[] returnData = CoreEncrypt(theData, normalKey, authenticationKey);

            //Returns a base64 string as its an encrypted byte[]
            return Convert.ToBase64String(returnData);
        }

		/// <summary>
        /// Encrypts the data specified and returns it in a byte array format
        /// </summary>
        /// <param name="data"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        public static byte[] EncryptToBytes(object data, object cryptKey, object authKey)
        {
            byte[] normalKey = Tools.KeyValidation(cryptKey);
            byte[] authenticationKey = Tools.KeyValidation(authKey);

            //Serialises the data into a byte[]
            byte[] theData = Tools.SerializeToBytes(data);

            //Encrypts the serialised data
            byte[] returnData = CoreEncrypt(theData, normalKey, authenticationKey);

            
            return returnData;
        }


        /// <summary>
        /// Encrypts a file and saves it to the specified path
        /// </summary>
        /// <param name="path"></param>
        /// <param name="fileData"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        public static bool SaveEncryptedFile(string path, byte[] fileData, object cryptKey, object authKey)
        {
            //Encrypts the file data
            byte[] encrypted = EncryptToBytes(fileData, cryptKey, authKey);

            int maxWait = 10000;
            int count = 0;

            //creates the file
            File.WriteAllBytes(path, encrypted);

            //waits a little bit before continuing to ensure the file has been created.
            //Note: this function does not wait permanently max of 10 seconds then it loops out
            while (count < maxWait && !File.Exists(path))
            {
                Thread.Sleep(1);
                count++;
            }

            //Checks if the file now exists
            if (File.Exists(path))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Loads a file from the specified path and encrypts it
        /// </summary>
        /// <param name="path"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        public static byte[] LoadEncryptedFile(string path, object cryptKey, object authKey)
        {
            //Stores the file data when loaded
            byte[] file = null;

            //Checks the file path actually exists before trying to read it
            if (File.Exists(path))
            {
                //Reads the file data
                file = File.ReadAllBytes(path);

                //Returns the encrypted file data
                return EncryptToBytes(file, cryptKey, authKey);
            }

            return null;
        }
    }    
}