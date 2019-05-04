using DotNetAES.Engines;
using NUnit.Framework;
using System;
using System.Text;

namespace Engine.Tests
{
    public class AESTests
    {
        private AES AES;

        [SetUp]
        public void Setup()
        {
            AES = new AES();
        }

        [Test]
        public void ByteKeyValidation()
        {   
            byte[] key = AES.CreateAESByteKey();
            Assert.IsNotNull(key);
        }

        [Test]
        public void StringKeyValidation()
        {
            //Generates a key and IV for testing purposes
            string key = AES.CreateAESStringKey();
            Assert.IsFalse(string.IsNullOrWhiteSpace(key));
        }

        [Test]
        public void StringIVValidation()
        {   
            string IV = AES.CreateAESStringIV();
            Assert.IsFalse(string.IsNullOrWhiteSpace(IV));
        }

        [Test]
        public void ByteIVValidation()
        {
            byte[] IV = AES.CreateAESByteIV();
            Assert.IsNotNull(IV);
        }

        [Test]
        public void StringEncryptionValidation()
        {
            string exampleString = "this is a test string.";

            //Generates a key and IV for testing purposes
            string key = AES.CreateAESStringKey();
            string IV = AES.CreateAESStringIV();

            //Encrypts the string
            var encryptedString = AES.EncryptToString(exampleString, key, IV);

            //Decrypts the string
            var decryptedString = AES.DecryptToType<string>(encryptedString, key, IV);

            Assert.IsTrue(decryptedString == exampleString);
        }

        [Test]
        public void StringEncryptionByteValidation()
        {
            string exampleString = "this is a test string.";

            //Generates a key and IV for testing purposes
            string key = AES.CreateAESStringKey();
            string IV = AES.CreateAESStringIV();

            //Encrypts the string into bytes
            var encryptedBytes = AES.EncryptToBytes(exampleString, key, IV);

            //Decrypts the string
            var decryptedBytesString = AES.DecryptToType<string>(encryptedBytes, key, IV);

            Assert.IsTrue(decryptedBytesString == exampleString);
        }

        [Test]
        public void StringByteEncryptionValidation()
        {
            string exampleString = "this is a test string2.";

            //Generates a key and IV for testing purposes
            string key = AES.CreateAESStringKey();
            string IV = AES.CreateAESStringIV();

            //Gets the bytes for the string
            byte[] stringBytes = Encoding.ASCII.GetBytes(exampleString);

            //Encrypts the string
            var encryptedString = AES.EncryptToString(stringBytes, key, IV);

            //Decrypts the string
            var decryptedStringBytes = AES.DecryptToType<byte[]>(encryptedString, key, IV);

            //Decodes the bytes back into a string
            var decodedStringbytes = Encoding.ASCII.GetString(decryptedStringBytes);
            
            Assert.IsTrue(decodedStringbytes == exampleString);
        }

        [Test]
        public void StringByteEncryptionByteValidation()
        {
            string exampleString = "this is a test string2.";

            //Generates a key and IV for testing purposes
            string key = AES.CreateAESStringKey();
            string IV = AES.CreateAESStringIV();

            //Gets the bytes for the string
            byte[] stringBytes = Encoding.ASCII.GetBytes(exampleString);

            //Encrypts the bytes to a string
            var encryptedBytes = AES.EncryptToBytes(stringBytes, key, IV);

            //Decrypts the bytes to bytes
            var decryptedBytes = AES.DecryptToType<byte[]>(encryptedBytes, key, IV);

            //Decodes the bytes back into a string
            var decodedString = Encoding.ASCII.GetString(decryptedBytes);

            Assert.IsTrue(decodedString == exampleString);
        }

        [Test]
        public void ObjectEncryptionValidation()
        {
            //Generates a key and IV for testing purposes
            string key = AES.CreateAESStringKey();
            string IV = AES.CreateAESStringIV();

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

            Assert.IsTrue(decryptedObject.Name == "David" && decryptedObject.Age == 99);
        }

        [Test]
        public void ObjectEncryptionByteValidation()
        {
            //Generates a key and IV for testing purposes
            string key = AES.CreateAESStringKey();
            string IV = AES.CreateAESStringIV();

            //Creates an object that we will use to test the encryption
            TestUser user = new TestUser()
            {
                Name = "David",
                Age = 99
            };

            //Encrypts the user object into bytes
            var encryptedBytes = AES.EncryptToBytes(user, key, IV);

            //Decrypts it back into a user object
            var decryptedBytesObject = AES.DecryptToType<TestUser>(encryptedBytes, key, IV);

            Assert.IsTrue(decryptedBytesObject.Name == "David" && decryptedBytesObject.Age == 99);
        }

    }
}