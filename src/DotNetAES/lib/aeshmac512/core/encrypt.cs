using System;
using System.IO;
using System.Threading;

namespace DotNetAES.Engines
{
    public partial class AESHMAC512
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
        public new string EncryptToString(object data, object cryptKey, object authKey)
        {
            byte[] normalKey = helpers.KeyValidation(cryptKey);
            byte[] authenticationKey = helpers.KeyValidation(authKey);

            //Serialises the data into a byte[]
            byte[] theData = helpers.SerializeToBytes(data);

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
        public new byte[] EncryptToBytes(object data, object cryptKey, object authKey)
        {
            byte[] normalKey = helpers.KeyValidation(cryptKey);
            byte[] authenticationKey = helpers.KeyValidation(authKey);

            //Serialises the data into a byte[]
            byte[] theData = helpers.SerializeToBytes(data);

            //Encrypts the serialised data
            byte[] returnData = CoreEncrypt(theData, normalKey, authenticationKey);

            
            return returnData;
        }      
    }    
}