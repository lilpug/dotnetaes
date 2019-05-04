using DotNetAES.Engines;
using DotNetAES.Extensions;
using NUnit.Framework;
using System;
using System.Data;
using System.Text;

namespace Extension.Tests
{
    public class AESDataTableExtensionsTests
    {
        private AES AES;

        [SetUp]
        public void Setup()
        {
            AES = new AES();
        }

        [Test]
        public void DataTableEncryptionValidation()
        {
            //Generates a key and IV for testing purposes
            string key = AES.CreateAESStringKey();
            string IV = AES.CreateAESStringIV();

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
            dt = dt.AESEncryptIgnore(AES, "column_iv", key, "column_two");
            if (dt.Rows[0]["column_one"].ToString() != "one" && dt.Rows[0]["column_two"].ToString() == "two" && dt.Columns.Contains("column_iv"))
            {
                ignoreCheck = true;
            }

            //Checks decryption
            dt = dt.AESDecryptIgnore(AES, "column_iv", key, "column_two");
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
            dt = dt.AESEncryptOnly(AES, "column_iv", key, "column_two");
            if (dt.Rows[0]["column_one"].ToString() == "one" && dt.Rows[0]["column_two"].ToString() != "two" && dt.Columns.Contains("column_iv"))
            {
                onlyCheck = true;
            }

            //Checks decryption
            dt = dt.AESDecryptOnly(AES, "column_iv", key, "column_two");
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
            dt = dt.AESEncrypt(AES, "column_iv", key);
            if (dt.Rows[0]["column_one"].ToString() != "one" && dt.Rows[0]["column_two"].ToString() != "two" && dt.Columns.Contains("column_iv"))
            {
                normalCheck = true;
            }

            //Checks decryption
            dt = dt.AESDecrypt(AES, "column_iv", key);
            if (!normalCheck || dt.Rows[0]["column_one"].ToString() != "one" || dt.Rows[0]["column_two"].ToString() != "two" || !dt.Columns.Contains("column_iv"))
            {
                normalCheck = false;
            }

            Assert.IsTrue(ignoreCheck && onlyCheck && normalCheck);
        }

    }
}