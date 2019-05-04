using System.IO;
using System.Threading;

namespace DotNetAES.Engines
{
    public partial class AESHMAC512
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
        public new T DecryptToType<T>(object data, object cryptKey, object authKey)
        {
            //Checks we have the valid data for decrypting
            byte[] encryptedData = helpers.EncryptedDataValidation(data);
            byte[] normalKey = helpers.KeyValidation(cryptKey);
            byte[] authenticationKey = helpers.KeyValidation(authKey);
            
            //Decrypts the data and puts it into the variable
            byte[] decryptedData = CoreDecrypt(encryptedData, normalKey, authenticationKey);
            
            //Returns the deserialised byte[] back into the object type it was originally
            return helpers.DerializeFromBytes<T>(decryptedData);
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
        public T DecryptToType<T>(object data, object cryptKey, object authKey, int maxSecondsDifference)
        {
            //Checks we have the valid data for decrypting
            byte[] encryptedData = helpers.EncryptedDataValidation(data);
            byte[] normalKey = helpers.KeyValidation(cryptKey);
            byte[] authenticationKey = helpers.KeyValidation(authKey);

            //Decrypts the data and puts it into the variable
            byte[] decryptedData = CoreDecrypt(encryptedData, normalKey, authenticationKey, maxSecondsDifference);

            //Returns the deserialised byte[] back into the object type it was originally
            return helpers.DerializeFromBytes<T>(decryptedData);
        }
    }    
}