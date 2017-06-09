using DotNetAES;
using DotNetAES.Extensions;
using System;
using System.Data;
using System.IO;
using System.Text;
using System.Threading;

namespace testing
{
    public static class AESHMAC512Testing
    {
        /// <summary>
        /// Checks the validation for the expiration settings on the HMAC
        /// </summary>
        /// <returns></returns>
        public static bool ExpirationValidation()
        {
            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateStringAESKey();
            string authKey = AESHMAC512.CreateStringAuthenticationKey();
            
            string testingString = "testing string";

            //Checks if the expiration HMAC fails when its past a valid period of time
            //Note: Makes it expire after 5 seconds and we use a thread sleep to wait 6 seconds.
            bool failureCheck = false;
            try
            {
                var enc = AESHMAC512.EncryptToString(testingString, cryptKey, authKey);
                Thread.Sleep(6000);
                var de = AESHMAC512.DecryptToType<string>(enc, cryptKey, authKey, 5);
            }
            catch
            {
                failureCheck = true;
            }

            //Checks if the expiration HMAC works correctly when within the range specified
            //Note: Makes it expire after 60 seconds but only waits 6 so should be within range still.
            bool successCheck = true;
            try
            {
                var enc = AESHMAC512.EncryptToString(testingString, cryptKey, authKey);
                Thread.Sleep(6000);
                var de = AESHMAC512.DecryptToType<string>(enc, cryptKey, authKey, 60);
            }
            catch
            {
                successCheck = false;
            }
            
            //Returns the results
            return (failureCheck && successCheck);
        }
        
        /// <summary>
        /// Checks the validation of the file encryption and decryption funcctions
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public static bool FileEncryptionValidation(string filePath)
        {
            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateStringAESKey();
            string authKey = AESHMAC512.CreateStringAuthenticationKey();

            string directory = Path.GetDirectoryName(filePath);

            //Reads the first file data like normal
            byte[] file = File.ReadAllBytes(filePath);
            
            //Saves the loaded file data as an encrypted file
            var encryptedCheck = AESHMAC512.SaveEncryptedFile($@"{directory}\1_encrypted.{Path.GetExtension(filePath)}", file, cryptKey, authKey);

            //Loads the encrypted files data
            byte[] encryptedFile = File.ReadAllBytes($@"{directory}\1_encrypted.{Path.GetExtension(filePath)}");

            //Saves the loaded encrypted data into a decrypted file
            var decryptedCheck = AESHMAC512.SaveDecryptedFile($@"{directory}\2_decrypted.{Path.GetExtension(filePath)}", encryptedFile, cryptKey, authKey);

            return (encryptedCheck && decryptedCheck);
        }

        /// <summary>
        /// Checks the validation of the general encryption functions using a string
        /// </summary>
        /// <returns></returns>
        public static bool StringEncryptionValidation()
        {
            string exampleString = "this is a test string.";

            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateStringAESKey();
            string authKey = AESHMAC512.CreateStringAuthenticationKey();

            //Encrypts the string
            var encryptedString = AESHMAC512.EncryptToString(exampleString, cryptKey, authKey);

            //Decrypts the string
            var decryptedString = AESHMAC512.DecryptToType<string>(encryptedString, cryptKey, authKey);

            //Encrypts the string into bytes
            var encryptedBytes = AESHMAC512.EncryptToBytes(exampleString, cryptKey, authKey);

            //Decrypts the string
            var decryptedBytesString = AESHMAC512.DecryptToType<string>(encryptedBytes, cryptKey, authKey);
            
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

            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateStringAESKey();
            string authKey = AESHMAC512.CreateStringAuthenticationKey();

            //Gets the bytes for the string
            byte[] stringBytes = Encoding.ASCII.GetBytes(exampleString);

            //Encrypts the string
            var encryptedString = AESHMAC512.EncryptToString(stringBytes, cryptKey, authKey);

            //Decrypts the string
            var decryptedStringBytes = AESHMAC512.DecryptToType<byte[]>(encryptedString, cryptKey, authKey);
            
            //Decodes the bytes back into a string
            var decodedStringbytes = Encoding.ASCII.GetString(decryptedStringBytes);
            

            //Encrypts the bytes to a string
            var encryptedBytes = AESHMAC512.EncryptToBytes(stringBytes, cryptKey, authKey);

            //Decrypts the bytes to bytes
            var decryptedBytes = AESHMAC512.DecryptToType<byte[]>(encryptedBytes, cryptKey, authKey);

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
            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateStringAESKey();
            string authKey = AESHMAC512.CreateStringAuthenticationKey();

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
            dt = dt.AESHMAC512EncryptIgnore(cryptKey, authKey , "column_two");
            if(dt.Rows[0]["column_one"].ToString() != "one" && dt.Rows[0]["column_two"].ToString() == "two")
            {
                ignoreCheck = true;
            }

            //Checks decryption
            dt = dt.AESHMAC512DecryptIgnore(cryptKey, authKey, "column_two");
            if (!ignoreCheck || dt.Rows[0]["column_one"].ToString() != "one" || dt.Rows[0]["column_two"].ToString() != "two")
            {
                ignoreCheck = false;
            }


            //Checks if the DataTable only functions work correctly
            bool onlyCheck = false;

            //Checks encryption
            dt = dt.AESHMAC512EncryptOnly(cryptKey, authKey, "column_two");
            if (dt.Rows[0]["column_one"].ToString() == "one" && dt.Rows[0]["column_two"].ToString() != "two")
            {
                onlyCheck = true;
            }

            //Checks decryption
            dt = dt.AESHMAC512DecryptOnly(cryptKey, authKey, "column_two");
            if (!onlyCheck || dt.Rows[0]["column_one"].ToString() != "one" || dt.Rows[0]["column_two"].ToString() != "two")
            {
                onlyCheck = false;
            }


            //Checks if the DataTable only functions work correctly
            bool normalCheck = false;

            //Checks encryption
            dt = dt.AESHMAC512Encrypt(cryptKey, authKey);
            if (dt.Rows[0]["column_one"].ToString() != "one" && dt.Rows[0]["column_two"].ToString() != "two")
            {
                normalCheck = true;
            }

            //Checks decryption
            dt = dt.AESHMAC512Decrypt(cryptKey, authKey);
            if (!normalCheck || dt.Rows[0]["column_one"].ToString() != "one" || dt.Rows[0]["column_two"].ToString() != "two")
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
            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateStringAESKey();
            string authKey = AESHMAC512.CreateStringAuthenticationKey();

            //Creates an object that we will use to test the encryption
            TestUser user = new TestUser()
            {
                Name = "David",
                Age = 99
            };

            //Encrypts the user object into a string
            var encryptedString = AESHMAC512.EncryptToString(user,  cryptKey, authKey);

            //Decrypts the it back into a user object
            var decryptedObject = AESHMAC512.DecryptToType<TestUser>(encryptedString, cryptKey, authKey);

            //Encrypts the user object into bytes
            var encryptedBytes = AESHMAC512.EncryptToBytes(user, cryptKey, authKey);

            //Decrypts it back into a user object
            var decryptedBytesObject = AESHMAC512.DecryptToType<TestUser>(encryptedBytes, cryptKey, authKey);

            //Check if both version are the same as the original inputs
            return (decryptedObject.Name == "David" && decryptedObject.Age == 99 && decryptedBytesObject.Name == "David" && decryptedBytesObject.Age == 99);
        }


        /// <summary>
        /// Core testing function
        /// </summary>
        public static void Core()
        {
            Console.WriteLine("AES HMAC SHA512 testing starting...");
            Console.WriteLine("");

            string filePath = @"C:\logo.jpg";

            Console.WriteLine($"File Success: {FileEncryptionValidation(filePath)}");
            Console.WriteLine($"String Success: {StringEncryptionValidation()}");
            Console.WriteLine($"Bytes Success: {StringByteEncryptionValidation()}");
            Console.WriteLine($"DataTables Success: {DataTableEncryptionValidation()}");
            Console.WriteLine($"Object Success: {ObjectEncryptionValidation()}");

            Console.WriteLine($"HMAC Expiration Success: {ExpirationValidation()}");
            

            Console.WriteLine("");
            Console.WriteLine("AES HMAC SHA512 testing ended...");

            Console.ReadLine();
        }
    }
}
