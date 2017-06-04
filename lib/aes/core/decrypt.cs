using System;
using System.Data;
using System.IO;
using System.Linq;
using System.Threading;

namespace DotNetAES
{
    public static partial class AES
    {
        //######################################################
        //#######           Decryption Functions         #######
        //######################################################
           
         
        public static T DecryptToType<T>(object data, object key, object IV)
        {
            //Checks we have the valid data for decrypting
            byte[] encryptedData = EncryptedDataValidation(data);
            byte[] theKey = KeyValidation(key);
            byte[] theIV = IVValidaton(IV);
            
            //Decrypts the data and puts it into the variable
            byte[] decryptedData = Decrypt(encryptedData, theKey, theIV);

            //Returns the deserialised byte[] back into the object type it was originally
            return DerializeFromBytes<T>(decryptedData);
        }

        /// <summary>
        /// Decrypts all the DataTable columns using the IV column and key supplied
        /// </summary>
        /// <param name="data"></param>
        /// <param name="ivColumnName"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static DataTable DecryptData(DataTable data, string ivColumnName, object key)
        {
            //Checks the table even has values before continuing
            if (
                //Checks we have some form of data being supplied
                data != null &&
                data.Rows.Count > 0 &&

                //Checks the IV column does exist as it needs to on decryption
                data.Columns.Contains(ivColumnName)
               )
            {
                //Clones the current table ready for the decrypted values
                DataTable newDT = data.Clone();

                //Loops over all the rows for the DataTable
                foreach (DataRow dr in data.Rows)
                {
                    //Creates a new empty row ready for populating the decrypted values
                    DataRow newRow = newDT.NewRow();

                    //Loops over the columns for that particular row and processes the values
                    foreach (DataColumn col in data.Columns)
                    {
                        //Checks to make so we do not encrypt a column which is either empty or has been marked as ignore
                        if (
                            //Checks its not the IV column
                            col.ColumnName.ToLower() != ivColumnName.ToLower() &&

                            //Checks the column data is not empty before continuing
                            dr[col] != DBNull.Value && !string.IsNullOrWhiteSpace(dr[col].ToString())
                           )
                        {
                            //Decrypts the data and puts it into the new rows column
                            newRow[col.ColumnName] = DecryptToType<string>(dr[col], key, dr[ivColumnName]);
                        }
                        else
                        {
                            //Transfers the original value as its either in the ignore list, empty or the IV value
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

        /// <summary>
        /// Decrypts all the DataTable columns that are not in the ignore list
        /// </summary>
        /// <param name="data"></param>
        /// <param name="ivColumnName"></param>
        /// <param name="key"></param>
        /// <param name="ignoreColumns"></param>
        /// <returns></returns>
        public static DataTable DecryptDataIgnore(DataTable data, string ivColumnName, object key, params string[] ignoreColumns)
        {
            //Checks the table even has values before continuing
            if (
                //Checks we have some form of data being supplied
                data != null &&
                data.Rows.Count > 0 &&

                //Checks the IV column does exist as it needs to on decryption
                data.Columns.Contains(ivColumnName)
               )
            {
                //Validates the column names supplied
                foreach (string columnName in ignoreColumns)
                {
                    if (!data.Columns.Contains(columnName))
                    {
                        throw new ArgumentException("A column in the ignoreColumns does not exist in the supplied DataTable.");
                    }
                }

                //Clones the current table ready for the decrypted values
                DataTable newDT = data.Clone();

                //Loops over all the rows for the DataTable
                foreach (DataRow dr in data.Rows)
                {
                    //Creates a new empty row ready for populating the decrypted values
                    DataRow newRow = newDT.NewRow();

                    //Loops over the columns for that particular row and processes the values
                    foreach (DataColumn col in data.Columns)
                    {
                        //Checks to make so we do not encrypt a column which is either empty or has been marked as ignore
                        if (
                            //Checks its not the IV column
                            col.ColumnName.ToLower() != ivColumnName.ToLower() &&

                            //Checks the column data is not empty before continuing
                            dr[col] != DBNull.Value && !string.IsNullOrWhiteSpace(dr[col].ToString()) &&

                            //Checks the column is not part of the ignore section before continuing
                            ignoreColumns != null &&
                            ignoreColumns.Length > 0 &&
                            !ignoreColumns.Contains(col.ColumnName)
                           )
                        {
                            //Decrypts the data and puts it into the new rows column
                            newRow[col.ColumnName] = DecryptToType<string>(dr[col], key, dr[ivColumnName]);
                        }
                        else
                        {
                            //Transfers the original value as its either in the ignore list, empty or the IV value
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

        /// <summary>
        ///  Decrypts only the DataTable columns that are specified
        /// </summary>
        /// <param name="data"></param>
        /// <param name="ivColumnName"></param>
        /// <param name="key"></param>
        /// <param name="onlyColumns"></param>
        /// <returns></returns>
        public static DataTable DecryptDataOnly(DataTable data, string ivColumnName, object key, params string[] onlyColumns)
        {
            //Checks the table even has values before continuing
            if (
                //Checks we have some form of data being supplied
                data != null && 
                data.Rows.Count > 0 && 

                //Checks the IV column does exist as it needs to on decryption
                data.Columns.Contains(ivColumnName) &&
                
                //Checks we have atleast 1 or more column supplied to check
                onlyColumns != null && 
                onlyColumns.Length > 0)
            {
                //Validates the column names supplied
                foreach(string columnName in onlyColumns)
                {
                    if(!data.Columns.Contains(columnName))
                    {
                        throw new ArgumentException("A column in the onlyColumns does not exist in the supplied DataTable.");
                    }
                }

                //Clones the current table ready for the decrypted values
                DataTable newDT = data.Clone();

                //Loops over all the rows for the DataTable
                foreach (DataRow dr in data.Rows)
                {
                    //Creates a new empty row ready for populating the decrypted values
                    DataRow newRow = newDT.NewRow();
                    
                    //Loops over the only acceptable columns
                    foreach (DataColumn col in data.Columns)
                    {
                        //Checks to make so we do not encrypt a column which is either empty or has been marked as ignore
                        if (
                            //Checks its not the IV column
                            col.ColumnName.ToLower() != ivColumnName.ToLower() &&
                            
                            //Checks the column data is not empty before continuing
                            dr[col] != DBNull.Value && !string.IsNullOrWhiteSpace(dr[col].ToString()) &&

                            //Checks the column is part of the only accepted ones
                            onlyColumns.Contains(col.ColumnName)
                           )
                        {
                            //Decrypts the data and puts it into the new rows column
                            newRow[col.ColumnName] = DecryptToType<string> (dr[col], key, dr[ivColumnName]);
                        }
                        else
                        {
                            //Transfers the original value as its either in the ignore list, empty or the IV value
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

        public static bool SaveDecryptedFile(string path, byte[] fileData, object key, object iv)
        {
            //Decrypts the file data
            byte[] decrypted = DecryptToType<byte[]>(fileData, key, iv);

            int maxWait = 10000;
            int count = 0;

            //creates the file
            File.WriteAllBytes(path, decrypted);

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

        public static byte[] LoadDecryptedFile(string path, object key, object iv)
        {
            //Stores the file data when loaded
            byte[] file = null;

            //Checks the file path actually exists before trying to read it
            if (File.Exists(path))
            {
                //Reads the file data
                file = File.ReadAllBytes(path);

                //Returns the decrypted file data
                return DecryptToType<byte[]>(file, key, iv);
            }

            return null;
        }
    }    
}