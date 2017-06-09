using DotNetAES;
using DotNetAES.Extensions;
using System;
using System.Data;
using System.IO;
using System.Text;

namespace testing
{
    public static class AESTesting
    {
        /// <summary>
        /// Checks the validation of the file encryption and decryption funcctions
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public static bool FileEncryptionValidation(string filePath)
        {
            //Generates a key and IV for testing purposes
            string key = AES.CreateStringKey();
            string IV = AES.CreateStringIV();
            
            string directory = Path.GetDirectoryName(filePath);

            //Reads the first file data like normal
            byte[] file = File.ReadAllBytes(filePath);
            
            //Saves the loaded file data as an encrypted file
            var encryptedCheck = AES.SaveEncryptedFile($@"{directory}\1_encrypted.{Path.GetExtension(filePath)}", file, key, IV);

            //Loads the encrypted files data
            byte[] encryptedFile = File.ReadAllBytes($@"{directory}\1_encrypted.{Path.GetExtension(filePath)}");

            //Saves the loaded encrypted data into a decrypted file
            var decryptedCheck = AES.SaveDecryptedFile($@"{directory}\2_decrypted.{Path.GetExtension(filePath)}", encryptedFile, key, IV);

            return (encryptedCheck && decryptedCheck);
        }

        /// <summary>
        /// Checks the validation of the general encryption functions using a string
        /// </summary>
        /// <returns></returns>
        public static bool StringEncryptionValidation()
        {
            string exampleString = "this is a test string.";

            //Generates a key and IV for testing purposes
            string key = AES.CreateStringKey();
            string IV = AES.CreateStringIV();

            //Encrypts the string
            var encryptedString = AES.EncryptToString(exampleString, key, IV);

            //Decrypts the string
            var decryptedString = AES.DecryptToType<string>(encryptedString, key, IV);

            //Encrypts the string into bytes
            var encryptedBytes = AES.EncryptToBytes(exampleString, key, IV);

            //Decrypts the string
            var decryptedBytesString = AES.DecryptToType<string>(encryptedBytes, key, IV);
            
            //Check if both version are the same as the original inputs
            return (decryptedString == exampleString && decryptedBytesString == exampleString);
        }

        /// <summary>
        /// Checks the validation of the general encryption functions using bytes
        /// </summary>
        /// <returns></returns>
        public static bool StringByteEncryptionValidation()
        {
            string exampleString = "this is a test string2.";

            //Generates a key and IV for testing purposes
            string key = AES.CreateStringKey();
            string IV = AES.CreateStringIV();

            //Gets the bytes for the string
            byte[] stringBytes = Encoding.ASCII.GetBytes(exampleString);

            //Encrypts the string
            var encryptedString = AES.EncryptToString(stringBytes, key, IV);

            //Decrypts the string
            var decryptedStringBytes = AES.DecryptToType<byte[]>(encryptedString, key, IV);
            
            //Decodes the bytes back into a string
            var decodedStringbytes = Encoding.ASCII.GetString(decryptedStringBytes);
            

            //Encrypts the bytes to a string
            var encryptedBytes = AES.EncryptToBytes(stringBytes, key, IV);

            //Decrypts the bytes to bytes
            var decryptedBytes = AES.DecryptToType<byte[]>(encryptedBytes, key, IV);

            //Decodes the bytes back into a string
            var decodedString = Encoding.ASCII.GetString(decryptedBytes);

            //Check if both version are the same as the original inputs
            return (decodedStringbytes == exampleString && decodedString == exampleString);
        }

        /// <summary>
        /// Checks the validation of the DataTable extension methods
        /// </summary>
        /// <returns></returns>
        public static bool DataTableEncryptionValidation()
        {
            //Generates a key and IV for testing purposes
            string key = AES.CreateStringKey();
            string IV = AES.CreateStringIV();

            //Generates random data in a table
            DataTable dt = new DataTable()
            {
                Columns =
                {
                    "column_one","column_two", "column_three", "column_four", "column_five", "column_iv",
                },
                Rows =
                {
                    { "one", "two", "three", "four", "five" },
                    { "one2", "two2", "three2", "four2", "five2" },
                    { "3one", "t3wo", "three3", "four3", "five3" },
                    { 2, 3, 4, 5, 6 },
                    { DateTime.Now, 2, 3 },
                }
            };

            //Checks if the DataTable ignore functions work correctly
            bool ignoreCheck = false;

            //Checks encryption
            dt = dt.AESEncryptIgnore("column_iv", key, "column_two");
            if(dt.Rows[0]["column_one"].ToString() != "one" && dt.Rows[0]["column_two"].ToString() == "two" && dt.Columns.Contains("column_iv"))
            {
                ignoreCheck = true;
            }

            //Checks decryption
            dt = dt.AESDecryptIgnore("column_iv", key, "column_two");
            if (!ignoreCheck || dt.Rows[0]["column_one"].ToString() != "one" || dt.Rows[0]["column_two"].ToString() != "two" || !dt.Columns.Contains("column_iv"))
            {
                ignoreCheck = false;
            }

            //Removes the column ready for the next test
            if (ignoreCheck)
            {
                dt.Columns.Remove("column_iv");
            }



            //Checks if the DataTable only functions work correctly
            bool onlyCheck = false;

            //Checks encryption
            dt = dt.AESEncryptOnly("column_iv", key, "column_two");
            if (dt.Rows[0]["column_one"].ToString() == "one" && dt.Rows[0]["column_two"].ToString() != "two" && dt.Columns.Contains("column_iv"))
            {
                onlyCheck = true;
            }

            //Checks decryption
            dt = dt.AESDecryptOnly("column_iv", key, "column_two");
            if (!onlyCheck || dt.Rows[0]["column_one"].ToString() != "one" || dt.Rows[0]["column_two"].ToString() != "two" || !dt.Columns.Contains("column_iv"))
            {
                onlyCheck = false;
            }

            //Removes the column ready for the next test
            if (ignoreCheck || onlyCheck)
            {
                dt.Columns.Remove("column_iv");
            }



            //Checks if the DataTable only functions work correctly
            bool normalCheck = false;

            //Checks encryption
            dt = dt.AESEncrypt("column_iv", key);
            if (dt.Rows[0]["column_one"].ToString() != "one" && dt.Rows[0]["column_two"].ToString() != "two" && dt.Columns.Contains("column_iv"))
            {
                normalCheck = true;
            }

            //Checks decryption
            dt = dt.AESDecrypt("column_iv", key);
            if (!normalCheck || dt.Rows[0]["column_one"].ToString() != "one" || dt.Rows[0]["column_two"].ToString() != "two" || !dt.Columns.Contains("column_iv"))
            {
                normalCheck = false;
            }

            //returns the overall result of the tests
            return (ignoreCheck && onlyCheck && normalCheck);
        }

        //This function and class check the validation of the encryption when used on objects
        //NOTE: for a class object to be encrypted it has to have the Serializable flag on it as thats how we process the data before encryption
        [Serializable]
        public class TestUser
        {
            public string Name { get; set; }
            public int Age { get; set; }
        }

        /// <summary>
        /// Checks the validation of the encryption and decryption of objects
        /// </summary>
        /// <returns></returns>
        public static bool ObjectEncryptionValidation()
        {
            //Generates a key and IV for testing purposes
            string key = AES.CreateStringKey();
            string IV = AES.CreateStringIV();

            //Creates an object that we will use to test the encryption
            TestUser user = new TestUser()
            {
                Name = "David",
                Age = 99
            };

            //Encrypts the user object into a string
            var encryptedString = AES.EncryptToString(user, key, IV);

            //Decrypts the it back into a user object
            var decryptedObject = AES.DecryptToType<TestUser>(encryptedString, key, IV);

            //Encrypts the user object into bytes
            var encryptedBytes = AES.EncryptToBytes(user, key, IV);

            //Decrypts it back into a user object
            var decryptedBytesObject = AES.DecryptToType<TestUser>(encryptedBytes, key, IV);

            //Check if both version are the same as the original inputs
            return (decryptedObject.Name == "David" && decryptedObject.Age == 99 && decryptedBytesObject.Name == "David" && decryptedBytesObject.Age == 99);
        }


        /// <summary>
        /// Core testing function
        /// </summary>
        public static void Core()
        {
            Console.WriteLine("AES testing starting...");
            Console.WriteLine("");

            string filePath = @"C:\logo.jpg";

            Console.WriteLine($"File Success: {FileEncryptionValidation(filePath)}");
            Console.WriteLine($"String Success: {StringEncryptionValidation()}");
            Console.WriteLine($"Bytes Success: {StringByteEncryptionValidation()}");
            Console.WriteLine($"DataTables Success: {DataTableEncryptionValidation()}");
            Console.WriteLine($"Object Success: {ObjectEncryptionValidation()}");

            Console.WriteLine("");
            Console.WriteLine("AES testing ended...");

            Console.ReadLine();
        }
    }
}
