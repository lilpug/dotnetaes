using System;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace DotNetAES
{
    public static partial class AES
    {
        //######################################################
        //#######           Encryption Functions         #######
        //######################################################
        
        public static string EncryptToString(object data, object key, object IV)
        {
            //Checks we have the valid data for encrypting            
            byte[] theKey = KeyValidation(key);
            byte[] theIV = IVValidaton(IV);

            //Serialises the data into a byte[]
            byte[] theData = SerializeToBytes(data);

            //Encrypts the serialised data
            byte[] returnData = Encrypt(theData, theKey, theIV);

            //Returns a base64 string as its an encrypted byte[]
            return Convert.ToBase64String(returnData);
        }

        public static byte[] EncryptToBytes(object data, object key, object IV)
        {
            //Checks we have the valid data for encrypting
            byte[] theKey = KeyValidation(key);
            byte[] theIV = IVValidaton(IV);

            //Serialises the data into a byte[]
            byte[] theData = SerializeToBytes(data);

            //Encrypts the data and returns it as a byte[]
            return Encrypt(theData, theKey, theIV);
        }

        public static DataTable EncryptData(DataTable data, string ivColumnName, object key)
        {
            //Checks the table even has values before continuing
            if (data != null && data.Rows.Count > 0)
            {
                //Checks if the column already exist for the IV column
                if (!data.Columns.Contains(ivColumnName))
                {
                    //adds the column as it does not exist yet
                    data.Columns.Add(ivColumnName);
                }

                //Clones the current table ready for the encrypted values
                DataTable newDT = data.Clone();

                //Loops over all the rows for the DataTable
                foreach (DataRow dr in data.Rows)
                {
                    //Creates the IV for that particular rows encryption method
                    var iv = CreateStringIV();

                    //Creates a new empty row ready for populating the encrypted values
                    DataRow newRow = newDT.NewRow();

                    //Loops over the columns for that particular row and processes the values
                    foreach (DataColumn col in data.Columns)
                    {
                        //Checks if its the IV column
                        if (col.ColumnName.ToLower() == ivColumnName.ToLower())
                        {
                            //places the IV in the new rows IV column
                            newRow[col.ColumnName] = iv;
                        }
                        else if (
                                    //Checks the column data is not empty before continuing
                                    dr[col] != DBNull.Value && !string.IsNullOrWhiteSpace(dr[col].ToString())
                                )
                        {
                            //Encrypts the data and puts it into the new rows column
                            newRow[col.ColumnName] = EncryptToString(dr[col].ToString(), key, iv);
                        }
                        else
                        {
                            //Transfers the original value as its in the ignore list or empty
                            newRow[col.ColumnName] = dr[col];
                        }
                    }

                    //Adds the newly processed row to the new DataTable
                    newDT.Rows.Add(newRow);
                }

                return newDT;

            }
            return data;
        }

        public static DataTable EncryptDataIgnore(DataTable data, string ivColumnName, object key, params string[] ignoreColumns)
        {
            //Checks the table even has values before continuing
            if (data != null && data.Rows.Count > 0)
            {
                //Validates the column names supplied
                foreach (string columnName in ignoreColumns)
                {
                    if (!data.Columns.Contains(columnName))
                    {
                        throw new ArgumentException("A column in the ignoreColumns does not exist in the supplied DataTable.");
                    }
                }

                //Checks if the column already exist for the IV column
                if (!data.Columns.Contains(ivColumnName))
                {
                    //adds the column as it does not exist yet
                    data.Columns.Add(ivColumnName);
                }

                //Clones the current table ready for the encrypted values
                DataTable newDT = data.Clone();

                //Loops over all the rows for the DataTable
                foreach (DataRow dr in data.Rows)
                {   
                    //Creates the IV for that particular rows encryption method
                    var iv = CreateStringIV();
                 
                    //Creates a new empty row ready for populating the encrypted values
                    DataRow newRow = newDT.NewRow();

                    //Loops over the columns for that particular row and processes the values
                    foreach (DataColumn col in data.Columns)
                    {
                        //Checks if its the IV column
                        if (col.ColumnName.ToLower() == ivColumnName.ToLower())
                        {
                            //places the IV in the new rows IV column
                            newRow[col.ColumnName] = iv;
                        }
                        else if (
                                    //Checks the column data is not empty before continuing
                                    dr[col] != DBNull.Value && !string.IsNullOrWhiteSpace(dr[col].ToString()) &&

                                    //Checks the column is not part of the ignore section before continuing
                                    ignoreColumns != null &&
                                    ignoreColumns.Length > 0 &&
                                    !ignoreColumns.Contains(col.ColumnName)
                                )
                        {
                            //Encrypts the data and puts it into the new rows column
                            newRow[col.ColumnName] = EncryptToString(dr[col].ToString(), key, iv);
                        }
                        else
                        {
                            //Transfers the original value as its in the ignore list or empty
                            newRow[col.ColumnName] = dr[col];
                        }
                    }

                    //Adds the newly processed row to the new DataTable
                    newDT.Rows.Add(newRow);
                }

                return newDT;
                
            }
            return data;
        }

        public static DataTable EncryptDataOnly(DataTable data, string ivColumnName, object key, params string[] onlyColumns)
        {
            //Checks the table even has values before continuing
            if (
                //Checks we have some form of data being supplied
                data != null && 
                data.Rows.Count > 0 && 
                
                //Checks we atleast have supplied onlyColumns as this is what we are encrypting
                onlyColumns != null && 
                onlyColumns.Length > 0)
            {
                //Validates the column names supplied
                foreach (string columnName in onlyColumns)
                {
                    if (!data.Columns.Contains(columnName))
                    {
                        throw new ArgumentException("A column in the onlyColumns that has been supplied does not exist in the DataTable supplied");
                    }
                }

                //Checks if the column already exist for the IV column
                if (!data.Columns.Contains(ivColumnName))
                {
                    //adds the column as it does not exist yet
                    data.Columns.Add(ivColumnName);
                }

                //Clones the current table ready for the encrypted values
                DataTable newDT = data.Clone();

                //Loops over all the rows for the DataTable
                foreach (DataRow dr in data.Rows)
                {
                    //Creates the IV for that particular rows encryption method
                    var iv = CreateStringIV();

                    //Creates a new empty row ready for populating the encrypted values
                    DataRow newRow = newDT.NewRow();
                    
                    //Loops over the columns for that particular row and processes the values
                    foreach (DataColumn col in data.Columns)
                    {
                        //Checks if its the IV column
                        if (col.ColumnName.ToLower() == ivColumnName.ToLower())
                        {
                            //places the IV in the new rows IV column
                            newRow[col.ColumnName] = iv;
                        }
                        else if (
                                    //Checks the column data is not empty before continuing
                                    dr[col] != DBNull.Value && !string.IsNullOrWhiteSpace(dr[col].ToString()) &&

                                    //Checks the column is part of the only accepted ones
                                    onlyColumns.Contains(col.ColumnName)
                                )
                        {
                            //Encrypts the data and puts it into the new rows column
                            newRow[col.ColumnName] = EncryptToString(dr[col].ToString(), key, iv);
                        }
                        else
                        {
                            //Transfers the original value as its in the ignore list or empty
                            newRow[col.ColumnName] = dr[col];
                        }
                    }

                    //Adds the newly processed row to the new DataTable
                    newDT.Rows.Add(newRow);
                }

                return newDT;

            }
            return data;
        }

        public static bool SaveEncryptedFile(string path, byte[] fileData, object key, object iv)
        {
            //Encrypts the file data
            byte[] encrypted = EncryptToBytes(fileData, key, iv);

            int maxWait = 10000;
            int count = 0;

            //creates the file
            File.WriteAllBytes(path, encrypted);

            //waits a little bit before continuing to ensure the file has been created.
            //Note: this function does not wait permanently max of 10 seconds then it loops out
            while (count < maxWait && !File.Exists(path))
            {
                Thread.Sleep(1);
                count++;
            }

            //Checks if the file now exists
            if (File.Exists(path))
            {
                return true;
            }

            return false;
        }

        public static byte[] LoadEncryptedFile(string path, object key, object iv)
        {
            //Stores the file data when loaded
            byte[] file = null;

            //Checks the file path actually exists before trying to read it
            if (File.Exists(path))
            {
                //Reads the file data
                file = File.ReadAllBytes(path);

                //Returns the encrypted file data
                return EncryptToBytes(file, key, iv);
            }

            return null;
        }
    }    
}