using System;
using System.IO;
using System.Threading;

namespace DotNetAES.Engines
{
    public partial class AES
    {
        //######################################################
        //#######           Encryption Functions         #######
        //######################################################
        
        /// <summary>
        /// Encrypts the data specified and returns it in a base64 string format
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        public string EncryptToString(object data, object key, object IV)
        {
            //Checks we have the valid data for encrypting            
            byte[] theKey = helpers.KeyValidation(key);
            byte[] theIV = helpers.IVValidaton(IV);

            //Serialises the data into a byte[]
            byte[] theData = helpers.SerializeToBytes(data);

            //Encrypts the serialised data
            byte[] returnData = Encrypt(theData, theKey, theIV);

            //Returns a base64 string as its an encrypted byte[]
            return Convert.ToBase64String(returnData);
        }

        /// <summary>
        /// Encrypts the data specified and returns it in a byte array format
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        public byte[] EncryptToBytes(object data, object key, object IV)
        {
            //Checks we have the valid data for encrypting
            byte[] theKey = helpers.KeyValidation(key);
            byte[] theIV = helpers.IVValidaton(IV);

            //Serialises the data into a byte[]
            byte[] theData = helpers.SerializeToBytes(data);

            //Encrypts the data and returns it as a byte[]
            return Encrypt(theData, theKey, theIV);
        }
    }    
}