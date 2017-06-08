using System;
using System.Data;

namespace DotNetAES
{
    public static partial class Tools
    {
        //######################################################
        //#######           Validation Functions         #######
        //######################################################
        
        /// <summary>
        /// Validates the primary data required for the core AES encryption and decryption functions
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="IV"></param>
        public static void CoreValidation(byte[] data, byte[] key, byte[] IV)
        {
            //Checks the validation of the supplied arguments
            if (data == null || data.Length <= 0)
            {
                throw new ArgumentNullException("No data has been supplied");
            }
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("No key has been supplied");
            }
            if (IV == null || IV.Length <= 0)
            {
                throw new ArgumentNullException("No IV has been supplied");
            }
        }

        /// <summary>
        /// Validates the supplied encrypted data format for the decryption functions
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] EncryptedDataValidation(object data)
        {
            byte[] encryptedData = null;
            if (data != null)
            {
                if (data.GetType() == typeof(byte[]))
                {
                    encryptedData = (byte[])data;
                }
                else if (data.GetType() == typeof(string))
                {
                    string temp = (string)data;
                    encryptedData = Convert.FromBase64String(temp);
                }
                else
                {
                    throw new InvalidCastException("The file format for the encrypted data can only be a string or byte[].");
                }
            }
            else
            {
                throw new InvalidConstraintException("The data has not been supplied.");
            }
            return encryptedData;
        }

        /// <summary>
        /// Validates the supplied key format for encryption and decryption functions
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] KeyValidation(object key)
        {
            byte[] theKey = null;
            if (key != null)
            {
                if (key.GetType() == typeof(byte[]))
                {
                    theKey = (byte[])key;
                }
                else if (key.GetType() == typeof(string))
                {
                    string temp = (string)key;
                    theKey = Convert.FromBase64String(temp);
                }
                else
                {
                    throw new InvalidCastException("The file format for the key can only be a string or byte[].");
                }
            }
            else
            {
                throw new InvalidConstraintException("The key has not been supplied.");
            }
            return theKey;
        }

        /// <summary>
        /// Validates the supplied IV format for encryption and decryption functions
        /// </summary>
        /// <param name="IV"></param>
        /// <returns></returns>
        public static byte[] IVValidaton(object IV)
        {
            byte[] theIV = null;
            if (IV != null)
            {
                if (IV.GetType() == typeof(byte[]))
                {
                    theIV = (byte[])IV;
                }
                else if (IV.GetType() == typeof(string))
                {
                    string temp = (string)IV;
                    theIV = Convert.FromBase64String(temp);
                }
                else
                {
                    throw new InvalidCastException("The file format for the IV can only be a string or byte[].");
                }
            }
            else
            {
                throw new InvalidConstraintException("The IV has not been supplied.");
            }
            return theIV;
        }
    }
}