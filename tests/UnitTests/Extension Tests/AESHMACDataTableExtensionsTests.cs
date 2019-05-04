using DotNetAES.Engines;
using DotNetAES.Extensions;
using NUnit.Framework;
using System;
using System.Data;
using System.Text;
using System.Threading;

namespace Extension.Tests
{
    public class AESHMACDataTableExtensionsTests
    {   
        private AESHMAC512 AESHMAC512;

        [SetUp]
        public void Setup()
        {
            AESHMAC512 = new AESHMAC512();
        }
        
        [Test]
        public void DataTableEncryptionValidation()
        {
            //Generates the keys for testing purposes
            string cryptKey = AESHMAC512.CreateAESStringKey();
            string authKey = AESHMAC512.CreateHMACAuthenticationStringKey();

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
            dt = dt.AESHMAC512EncryptIgnore(AESHMAC512, cryptKey, authKey, "column_two");
            if (dt.Rows[0]["column_one"].ToString() != "one" && dt.Rows[0]["column_two"].ToString() == "two")
            {
                ignoreCheck = true;
            }

            //Checks decryption
            dt = dt.AESHMAC512DecryptIgnore(AESHMAC512, cryptKey, authKey, "column_two");
            if (!ignoreCheck || dt.Rows[0]["column_one"].ToString() != "one" || dt.Rows[0]["column_two"].ToString() != "two")
            {
                ignoreCheck = false;
            }


            //Checks if the DataTable only functions work correctly
            bool onlyCheck = false;

            //Checks encryption
            dt = dt.AESHMAC512EncryptOnly(AESHMAC512, cryptKey, authKey, "column_two");
            if (dt.Rows[0]["column_one"].ToString() == "one" && dt.Rows[0]["column_two"].ToString() != "two")
            {
                onlyCheck = true;
            }

            //Checks decryption
            dt = dt.AESHMAC512DecryptOnly(AESHMAC512, cryptKey, authKey, "column_two");
            if (!onlyCheck || dt.Rows[0]["column_one"].ToString() != "one" || dt.Rows[0]["column_two"].ToString() != "two")
            {
                onlyCheck = false;
            }


            //Checks if the DataTable only functions work correctly
            bool normalCheck = false;

            //Checks encryption
            dt = dt.AESHMAC512Encrypt(AESHMAC512, cryptKey, authKey);
            if (dt.Rows[0]["column_one"].ToString() != "one" && dt.Rows[0]["column_two"].ToString() != "two")
            {
                normalCheck = true;
            }

            //Checks decryption
            dt = dt.AESHMAC512Decrypt(AESHMAC512, cryptKey, authKey);
            if (!normalCheck || dt.Rows[0]["column_one"].ToString() != "one" || dt.Rows[0]["column_two"].ToString() != "two")
            {
                normalCheck = false;
            }

            Assert.IsTrue(ignoreCheck && onlyCheck && normalCheck);
        }
    }
}