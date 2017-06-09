using System;
using System.Data;
using System.Linq;

namespace DotNetAES.Extensions
{
    /// <summary>
    /// AES CBC DataTable extensions
    /// </summary>
    public static partial class AESDataTableExtensions
    {
        //######################################################
        //#######           Decryption Functions         #######
        //######################################################

        /// <summary>
        /// Decrypts all the DataTable columns using the IV column and key supplied
        /// </summary>
        /// <param name="data"></param>
        /// <param name="ivColumnName"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static DataTable AESDecrypt(this DataTable data, string ivColumnName, object key)
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
                            newRow[col.ColumnName] = AES.DecryptToType<string>(dr[col], key, dr[ivColumnName]);
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
        public static DataTable AESDecryptIgnore(this DataTable data, string ivColumnName, object key, params string[] ignoreColumns)
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
                            newRow[col.ColumnName] = AES.DecryptToType<string>(dr[col], key, dr[ivColumnName]);
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
        public static DataTable AESDecryptOnly(this DataTable data, string ivColumnName, object key, params string[] onlyColumns)
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
                foreach (string columnName in onlyColumns)
                {
                    if (!data.Columns.Contains(columnName))
                    {
                        throw new ArgumentException("A column in the onlyColumns does not exist in the supplied DataTable.");
                    }
                }

                //Clones the current table ready for the decrypted values
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
                            newRow[col.ColumnName] = AES.DecryptToType<string>(dr[col], key, dr[ivColumnName]);
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
    }
}