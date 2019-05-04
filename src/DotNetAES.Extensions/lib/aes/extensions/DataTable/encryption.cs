using DotNetAES.Engines;
using System;
using System.Data;
using System.Linq;

namespace DotNetAES.Extensions
{
    public static partial class AESDataTableExtensions
    {
        //######################################################
        //#######           Encryption Functions         #######
        //######################################################

        /// <summary>
        /// Encrypts all the DataTable columns using the IV column and key supplied
        /// </summary>
        /// <param name="data"></param>
        /// <param name="ivColumnName"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static DataTable AESEncrypt(this DataTable data, AES encryptionEngine, string ivColumnName, object key)
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
                /*NOTE: we do this instead of using Clone() just in case the DataTable schema has specified 
                        types for each column as were about to convert them all to string format.*/
                DataTable newDT = new DataTable();
                foreach (DataColumn col in data.Columns)
                {
                    newDT.Columns.Add(col.ColumnName);
                }

                //Loops over all the rows for the DataTable
                foreach (DataRow dr in data.Rows)
                {
                    //Creates the IV for that particular rows encryption method
                    var iv = encryptionEngine.CreateAESStringIV();

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
                            newRow[col.ColumnName] = encryptionEngine.EncryptToString(dr[col].ToString(), key, iv);
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

        /// <summary>
        /// Encrypts all the DataTable columns that are not in the ignore list
        /// </summary>
        /// <param name="data"></param>
        /// <param name="ivColumnName"></param>
        /// <param name="key"></param>
        /// <param name="ignoreColumns"></param>
        /// <returns></returns>
        public static DataTable AESEncryptIgnore(this DataTable data, AES encryptionEngine, string ivColumnName, object key, params string[] ignoreColumns)
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
                /*NOTE: we do this instead of using Clone() just in case the DataTable schema has specified 
                        types for each column as were about to convert them all to string format.*/
                DataTable newDT = new DataTable();
                foreach (DataColumn col in data.Columns)
                {
                    newDT.Columns.Add(col.ColumnName);
                }

                //Loops over all the rows for the DataTable
                foreach (DataRow dr in data.Rows)
                {
                    //Creates the IV for that particular rows encryption method
                    var iv = encryptionEngine.CreateAESStringIV();

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
                            newRow[col.ColumnName] = encryptionEngine.EncryptToString(dr[col].ToString(), key, iv);
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

        /// <summary>
        ///  Encrypts only the DataTable columns that are specified
        /// </summary>
        /// <param name="data"></param>
        /// <param name="ivColumnName"></param>
        /// <param name="key"></param>
        /// <param name="onlyColumns"></param>
        /// <returns></returns>
        public static DataTable AESEncryptOnly(this DataTable data, AES encryptionEngine, string ivColumnName, object key, params string[] onlyColumns)
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
                /*NOTE: we do this instead of using Clone() just in case the DataTable schema has specified 
                        types for each column as were about to convert them all to string format.*/
                DataTable newDT = new DataTable();
                foreach (DataColumn col in data.Columns)
                {
                    newDT.Columns.Add(col.ColumnName);
                }

                //Loops over all the rows for the DataTable
                foreach (DataRow dr in data.Rows)
                {
                    //Creates the IV for that particular rows encryption method
                    var iv = encryptionEngine.CreateAESStringIV();

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
                            newRow[col.ColumnName] = encryptionEngine.EncryptToString(dr[col].ToString(), key, iv);
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
        
    }
}