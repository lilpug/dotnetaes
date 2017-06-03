using DotNetAES;
using DotNetAES.Extensions;
using System;
using System.Data;
using System.IO;
using System.Text;

namespace testing
{
    class Program
    {
        //This function checks the validation of the file encryption and decryption funcctions
        private static bool FileEncryptionValidation()
        {
            //Generates a key and IV for testing purposes
            string key = AES.CreateStringKey();
            string iv = AES.CreateStringIV();

            string firstFile = @"C:\logo.jpg";

            //Reads the first file data like normal
            byte[] file = File.ReadAllBytes(firstFile);
            
            //Saves the loaded file data as an encrypted file
            var encryptedCheck = AES.SaveEncryptedFile($@"C:\1_encrypted.{Path.GetExtension(firstFile)}", file, key, iv);

            //Loads the encrypted files data
            byte[] encryptedFile = File.ReadAllBytes($@"C:\1_encrypted.{Path.GetExtension(firstFile)}");

            //Saves the loaded encrypted data into a decrypted file
            var decryptedCheck = AES.SaveDecryptedFile($@"C:\2_decrypted.{Path.GetExtension(firstFile)}", encryptedFile, key, iv);

            return (encryptedCheck && decryptedCheck);
        }

        //This function checks the validation of the general encryption functions using a string
        private static bool StringEncryptionValidation()
        {
            string exampleString = "this is a test string.";

            //Generates a key and IV for testing purposes
            string key = AES.CreateStringKey();
            string iv = AES.CreateStringIV();

            //Encrypts the string
            var encryptedString = AES.EncryptToString(exampleString, key, iv);

            //Decrypts the string
            var decryptedString = AES.DecryptToType<string>(encryptedString, key, iv);

            //Encrypts the string into bytes
            var encryptedBytes = AES.EncryptToBytes(exampleString, key, iv);

            //Decrypts the string
            var decryptedBytesString = AES.DecryptToType<string>(encryptedBytes, key, iv);
            
            //Check if both version are the same as the original inputs
            return (decryptedString == exampleString && decryptedBytesString == exampleString);
        }

        //This function checks the validation of the general encryption functions using bytes
        private static bool StringByteEncryptionValidation()
        {
            string exampleString = "this is a test string2.";

            //Generates a key and IV for testing purposes
            string key = AES.CreateStringKey();
            string iv = AES.CreateStringIV();

            //Gets the bytes for the string
            byte[] stringBytes = Encoding.ASCII.GetBytes(exampleString);

            //Encrypts the string
            var encryptedString = AES.EncryptToString(stringBytes, key, iv);

            //Decrypts the string
            var decryptedStringBytes = AES.DecryptToType<byte[]>(encryptedString, key, iv);
            
            //Decodes the bytes back into a string
            var decodedStringbytes = Encoding.ASCII.GetString(decryptedStringBytes);
            

            //Encrypts the bytes to a string
            var encryptedBytes = AES.EncryptToBytes(stringBytes, key, iv);

            //Decrypts the bytes to bytes
            var decryptedBytes = AES.DecryptToType<byte[]>(encryptedBytes, key, iv);

            //Decodes the bytes back into a string
            var decodedString = Encoding.ASCII.GetString(decryptedBytes);

            //Check if both version are the same as the original inputs
            return (decodedStringbytes == exampleString && decodedString == exampleString);
        }

        private static bool DataTableEncryptionValidation()
        {
            //Generates a key and IV for testing purposes
            string key = AES.CreateStringKey();
            string iv = AES.CreateStringIV();

            //Generates random data in a table
            DataTable dt = new DataTable();
            dt.Columns.Add("column_one");
            dt.Columns.Add("column_two");
            dt.Columns.Add("column_three");
            dt.Columns.Add("column_four");
            dt.Columns.Add("column_five");
            dt.Columns.Add("column_iv");
            dt.Rows.Add("one", "two", "three", "four", "five");
            dt.Rows.Add("one2", "two2", "three2", "four2", "five2");
            dt.Rows.Add("3one", "t3wo", "three3", "four3", "five3");
            dt.Rows.Add(2, 3, 4, 5, 6);
            dt.Rows.Add(DateTime.Now, 2, 3);

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
        private static bool ObjectEncryptionValidation()
        {
            //Generates a key and IV for testing purposes
            string key = AES.CreateStringKey();
            string iv = AES.CreateStringIV();

            //Creates an object that we will use to test the encryption
            TestUser user = new TestUser()
            {
                Name = "David",
                Age = 99
            };

            //Encrypts the user object into a string
            var encryptedString = AES.EncryptToString(user, key, iv);

            //Decrypts the it back into a user object
            var decryptedObject = AES.DecryptToType<TestUser>(encryptedString, key, iv);

            //Encrypts the user object into bytes
            var encryptedBytes = AES.EncryptToBytes(user, key, iv);

            //Decrypts it back into a user object
            var decryptedBytesObject = AES.DecryptToType<TestUser>(encryptedBytes, key, iv);

            //Check if both version are the same as the original inputs
            return (decryptedObject.Name == "David" && decryptedObject.Age == 99 && decryptedBytesObject.Name == "David" && decryptedBytesObject.Age == 99);
        }

        static void Main(string[] args)
        {
            Console.WriteLine($"File Success: {FileEncryptionValidation()}");
            Console.WriteLine($"String Success: {StringEncryptionValidation()}");
            Console.WriteLine($"Bytes Success: {StringByteEncryptionValidation()}");
            Console.WriteLine($"DataTables Success: {DataTableEncryptionValidation()}");
            Console.WriteLine($"Object Success: {ObjectEncryptionValidation()}");

            Console.ReadLine();

        }
    }
}
