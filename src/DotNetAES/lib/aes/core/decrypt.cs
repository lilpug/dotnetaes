using System.IO;
using System.Threading;

namespace DotNetAES.Engines
{
    public partial class AES
    {
        //######################################################
        //#######           Decryption Functions         #######
        //######################################################
           
         /// <summary>
         /// Decrypts the data and returns it in a format which has been specified
         /// </summary>
         /// <typeparam name="T"></typeparam>
         /// <param name="data"></param>
         /// <param name="key"></param>
         /// <param name="IV"></param>
         /// <returns></returns>
        public T DecryptToType<T>(object data, object key, object IV)
        {
            //Checks we have the valid data for decrypting
            byte[] encryptedData = helpers.EncryptedDataValidation(data);
            byte[] theKey = helpers.KeyValidation(key);
            byte[] theIV = helpers.IVValidaton(IV);
            
            //Decrypts the data and puts it into the variable
            byte[] decryptedData = Decrypt(encryptedData, theKey, theIV);

            //Returns the deserialised byte[] back into the object type it was originally
            return helpers.DerializeFromBytes<T>(decryptedData);
        }
    }    
}