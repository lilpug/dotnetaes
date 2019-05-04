using DotNetAES.Engines;
using NUnit.Framework;
using System;
using System.Text;
using System.Threading;

namespace Engine.Tests
{
    public class AESHMAC512Tests
    {
        private AESHMAC512 AESHMAC512;

        [SetUp]
        public void Setup()
        {
            AESHMAC512 = new AESHMAC512();
        }

        [Test]
        public void ByteKeyValidation()
        {   
            byte[] key = AESHMAC512.CreateAESByteKey();
            Assert.IsNotNull(key);
        }

        [Test]
        public void StringKeyValidation()
        {
            //Generates a key and IV for testing purposes
            string key = AESHMAC512.CreateAESStringKey();
            Assert.IsFalse(string.IsNullOrWhiteSpace(key));
        }

        [Test]
        public void StringIVValidation()
        {   
            string IV = AESHMAC512.CreateAESStringIV();
            Assert.IsFalse(string.IsNullOrWhiteSpace(IV));
        }

        [Test]
        public void ByteIVValidation()
        {
            byte[] IV = AESHMAC512.CreateAESByteIV();
            Assert.IsNotNull(IV);
        }

        [Test]
        public void ByteAuthenticationKeyValidation()
        {
            byte[] authKey = AESHMAC512.CreateHMACAuthenticationByteKey();
            Assert.IsNotNull(authKey);
        }

        [Test]
        public void StringAuthenticationKeyValidation()
        {
            string authKey = AESHMAC512.CreateHMACAuthenticationStringKey();
            Assert.IsNotNull(authKey);
        }
        
        [Test]
        public void ExpirationValidation()
        {
            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateAESStringKey();
            string authKey = AESHMAC512.CreateHMACAuthenticationStringKey();

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
            
            Assert.IsTrue(failureCheck && successCheck);
        }

        [Test]
        public void StringEncryptionValidation()
        {
            string exampleString = "this is a test string.";

            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateAESStringKey();
            string authKey = AESHMAC512.CreateHMACAuthenticationStringKey();

            //Encrypts the string
            var encryptedString = AESHMAC512.EncryptToString(exampleString, cryptKey, authKey);

            //Decrypts the string
            var decryptedString = AESHMAC512.DecryptToType<string>(encryptedString, cryptKey, authKey);

            Assert.IsTrue(decryptedString == exampleString);
        }

        [Test]
        public void StringEncryptionByteValidation()
        {
            string exampleString = "this is a test string.";

            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateAESStringKey();
            string authKey = AESHMAC512.CreateHMACAuthenticationStringKey();

            //Encrypts the string into bytes
            var encryptedBytes = AESHMAC512.EncryptToBytes(exampleString, cryptKey, authKey);

            //Decrypts the string
            var decryptedBytesString = AESHMAC512.DecryptToType<string>(encryptedBytes, cryptKey, authKey);
            
            Assert.IsTrue(decryptedBytesString == exampleString);
        }
        
        [Test]
        public void StringByteEncryptionValidation()
        {
            string exampleString = "this is a test string2.";

            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateAESStringKey();
            string authKey = AESHMAC512.CreateHMACAuthenticationStringKey();

            //Gets the bytes for the string
            byte[] stringBytes = Encoding.ASCII.GetBytes(exampleString);

            //Encrypts the string
            var encryptedString = AESHMAC512.EncryptToString(stringBytes, cryptKey, authKey);

            //Decrypts the string
            var decryptedStringBytes = AESHMAC512.DecryptToType<byte[]>(encryptedString, cryptKey, authKey);

            //Decodes the bytes back into a string
            var decodedStringbytes = Encoding.ASCII.GetString(decryptedStringBytes);

            Assert.IsTrue(decodedStringbytes == exampleString);
        }

        [Test]
        public void StringByteEncryptionByteValidation()
        {
            string exampleString = "this is a test string2.";

            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateAESStringKey();
            string authKey = AESHMAC512.CreateHMACAuthenticationStringKey();

            //Gets the bytes for the string
            byte[] stringBytes = Encoding.ASCII.GetBytes(exampleString);

            //Encrypts the bytes to a string
            var encryptedBytes = AESHMAC512.EncryptToBytes(stringBytes, cryptKey, authKey);

            //Decrypts the bytes to bytes
            var decryptedBytes = AESHMAC512.DecryptToType<byte[]>(encryptedBytes, cryptKey, authKey);

            //Decodes the bytes back into a string
            var decodedString = Encoding.ASCII.GetString(decryptedBytes);

            Assert.IsTrue(decodedString == exampleString);
        }
        
        [Test]
        public void ObjectEncryptionValidation()
        {
            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateAESStringKey();
            string authKey = AESHMAC512.CreateHMACAuthenticationStringKey();

            //Creates an object that we will use to test the encryption
            TestUser user = new TestUser()
            {
                Name = "David",
                Age = 99
            };

            //Encrypts the user object into a string
            var encryptedString = AESHMAC512.EncryptToString(user, cryptKey, authKey);

            //Decrypts the it back into a user object
            var decryptedObject = AESHMAC512.DecryptToType<TestUser>(encryptedString, cryptKey, authKey);

            Assert.IsTrue(decryptedObject.Name == "David" && decryptedObject.Age == 99);
        }

        [Test]
        public void ObjectEncryptionByteValidation()
        {
            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateAESStringKey();
            string authKey = AESHMAC512.CreateHMACAuthenticationStringKey();

            //Creates an object that we will use to test the encryption
            TestUser user = new TestUser()
            {
                Name = "David",
                Age = 99
            };

            //Encrypts the user object into bytes
            var encryptedBytes = AESHMAC512.EncryptToBytes(user, cryptKey, authKey);

            //Decrypts it back into a user object
            var decryptedBytesObject = AESHMAC512.DecryptToType<TestUser>(encryptedBytes, cryptKey, authKey);

            Assert.IsTrue(decryptedBytesObject.Name == "David" && decryptedBytesObject.Age == 99);
        }

    }
}