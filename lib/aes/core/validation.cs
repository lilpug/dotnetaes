using System;
using System.Data;
using System.Text;

namespace DotNetAES
{
    public static partial class AES
    {
        //######################################################
        //#######           Validation Functions         #######
        //######################################################

        //This function is used in the core encryption and decryption functions to validate the data before continueing
        private static void CoreValidation(byte[] data, byte[] key, byte[] IV)
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

        private static byte[] EncryptedDataValidation(object data)
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
                    throw new InvalidCastException("The file format for the encrypted AES data can only be a string or byte[].");
                }
            }
            else
            {
                throw new InvalidConstraintException("The data has not been supplied.");
            }
            return encryptedData;
        }

        private static byte[] KeyValidation(object key)
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

        private static byte[] IVValidaton(object IV)
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