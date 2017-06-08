using DotNetAES;
using System;
using System.Threading;

namespace testing
{
    class Program
    {

        private static bool ExpirationValidation()
        {
            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateStringAESKey();
            string authKey = AESHMAC512.CreateStringAuthenticationKey();

            bool failureCheck = false;

            string testingString = "testing string";
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

            return failureCheck;
        }

        static void Main(string[] args)
        {

            var cryptKey = AESHMAC512.CreateByteAESKey();
            var authKey = AESHMAC512.CreateByteAuthenticationKey();

            string testingString = "testing string";


            var enc = AESHMAC512.EncryptToString(testingString, cryptKey, authKey);
            var de = AESHMAC512.DecryptToType<string>(enc, cryptKey, authKey, 5);
                

            AESTesting.Core();

            AESHMAC512Testing.Core();
        }
    }
}
