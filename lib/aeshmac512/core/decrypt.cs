using System.IO;
using System.Threading;

namespace DotNetAES
{
    public static partial class AESHMAC512
    {
        //######################################################
        //#######           Decryption Functions         #######
        //######################################################

        /// <summary>
        /// Decrypts the data and returns it in a format which has been specified
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        public static T DecryptToType<T>(object data, object cryptKey, object authKey)
        {
            //Checks we have the valid data for decrypting
            byte[] encryptedData = Tools.EncryptedDataValidation(data);
            byte[] normalKey = Tools.KeyValidation(cryptKey);
            byte[] authenticationKey = Tools.KeyValidation(authKey);
            
            //Decrypts the data and puts it into the variable
            byte[] decryptedData = CoreDecrypt(encryptedData, normalKey, authenticationKey);
            
            //Returns the deserialised byte[] back into the object type it was originally
            return Tools.DerializeFromBytes<T>(decryptedData);
        }

        /// <summary>
        /// Decrypts the data and returns it in a format which has been specified
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <param name="maxSecondsDifference"></param>
        /// <returns></returns>
        public static T DecryptToType<T>(object data, object cryptKey, object authKey, int maxSecondsDifference)
        {
            //Checks we have the valid data for decrypting
            byte[] encryptedData = Tools.EncryptedDataValidation(data);
            byte[] normalKey = Tools.KeyValidation(cryptKey);
            byte[] authenticationKey = Tools.KeyValidation(authKey);

            //Decrypts the data and puts it into the variable
            byte[] decryptedData = CoreDecrypt(encryptedData, normalKey, authenticationKey, maxSecondsDifference);

            //Returns the deserialised byte[] back into the object type it was originally
            return Tools.DerializeFromBytes<T>(decryptedData);
        }

        /// <summary>
        /// Decrypts a file and saves it to the specified path
        /// </summary>
        /// <param name="path"></param>
        /// <param name="fileData"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        public static bool SaveDecryptedFile(string path, byte[] fileData, object cryptKey, object authKey)
        {
            //Decrypts the file data
            byte[] decrypted = DecryptToType<byte[]>(fileData, cryptKey, authKey);

            int maxWait = 10000;
            int count = 0;

            //creates the file
            File.WriteAllBytes(path, decrypted);

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
        /// Decrypts a file and saves it to the specified path
        /// </summary>
        /// <param name="path"></param>
        /// <param name="fileData"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <param name="maxSecondsDifference"></param>
        /// <returns></returns>
        public static bool SaveDecryptedFile(string path, byte[] fileData, object cryptKey, object authKey, int maxSecondsDifference)
        {
            //Decrypts the file data
            byte[] decrypted = DecryptToType<byte[]>(fileData, cryptKey, authKey, maxSecondsDifference);

            int maxWait = 10000;
            int count = 0;

            //creates the file
            File.WriteAllBytes(path, decrypted);

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
        /// Loads a file from the specified path and decrypts it
        /// </summary>
        /// <param name="path"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        public static byte[] LoadDecryptedFile(string path, object cryptKey, object authKey)
        {
            //Stores the file data when loaded
            byte[] file = null;

            //Checks the file path actually exists before trying to read it
            if (File.Exists(path))
            {
                //Reads the file data
                file = File.ReadAllBytes(path);

                //Returns the decrypted file data
                return DecryptToType<byte[]>(file, cryptKey, authKey);
            }

            return null;
        }

        /// <summary>
        /// Loads a file from the specified path and decrypts it
        /// </summary>
        /// <param name="path"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <param name="maxSecondsDifference"></param>
        /// <returns></returns>
        public static byte[] LoadDecryptedFile(string path, object cryptKey, object authKey, int maxSecondsDifference)
        {
            //Stores the file data when loaded
            byte[] file = null;

            //Checks the file path actually exists before trying to read it
            if (File.Exists(path))
            {
                //Reads the file data
                file = File.ReadAllBytes(path);

                //Returns the decrypted file data
                return DecryptToType<byte[]>(file, cryptKey, authKey);
            }

            return null;
        }
    }    
}