using System.Data;

namespace DotNetAES.Extensions
{
    public static class DataTableExtensions
    {
        //######################################################
        //#######           Encryption Functions         #######
        //######################################################

        public static DataTable AESEncrypt(this DataTable data, string ivColumnName, object key)
        {   
            return AES.EncryptData(data, ivColumnName, key);
        }

        public static DataTable AESEncryptIgnore(this DataTable data, string ivColumnName, object key, params string[] ignoreColumns)
        {
            return AES.EncryptDataIgnore(data, ivColumnName, key, ignoreColumns);
        }

        public static DataTable AESEncryptOnly(this DataTable data, string ivColumnName, object key, params string[] onlyColumns)
        {
            return AES.EncryptDataOnly(data, ivColumnName, key, onlyColumns);
        }


        //######################################################
        //#######           Decryption Functions         #######
        //######################################################

        public static DataTable AESDecrypt(this DataTable data, string ivColumnName, object key)
        {
            return AES.DecryptData(data, ivColumnName, key);
        }

        public static DataTable AESDecryptIgnore(this DataTable data, string ivColumnName, object key, params string[] ignoreColumns)
        {
            return AES.DecryptDataIgnore(data, ivColumnName, key, ignoreColumns);
        }

        public static DataTable AESDecryptOnly(this DataTable data, string ivColumnName, object key, params string[] onlyColumns)
        {
            return AES.DecryptDataOnly(data, ivColumnName, key, onlyColumns);
        }
    }
}