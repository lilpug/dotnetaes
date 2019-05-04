using DotNetAES.Engines;
using System;
using System.Data;
using System.Linq;

namespace DotNetAES.Extensions
{    
    public static partial class AESHMAC512DataTableExtensions
    {
        //######################################################
        //#######           Decryption Functions         #######
        //######################################################

        /// <summary>
        /// Decrypts all the DataTable columns using the IV column and key supplied
        /// </summary>
        /// <param name="data"></param>
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        public static DataTable AESHMAC512Decrypt(this DataTable data, AESHMAC512 encryptionEngine, object cryptKey, object authKey)
        {
            //Checks the table even has values before continuing
            if (
                //Checks we have some form of data being supplied
                data != null &&
                data.Rows.Count > 0 
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
                            //Checks the column data is not empty before continuing
                            dr[col] != DBNull.Value && !string.IsNullOrWhiteSpace(dr[col].ToString())
                           )
                        {
                            //Decrypts the data and puts it into the new rows column
                            newRow[col.ColumnName] = encryptionEngine.DecryptToType<string>(dr[col], cryptKey, authKey);
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
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <param name="ignoreColumns"></param>
        /// <returns></returns>
        public static DataTable AESHMAC512DecryptIgnore(this DataTable data, AESHMAC512 encryptionEngine, object cryptKey, object authKey, params string[] ignoreColumns)
        {
            //Checks the table even has values before continuing
            if (
                //Checks we have some form of data being supplied
                data != null &&
                data.Rows.Count > 0
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
                            //Checks the column data is not empty before continuing
                            dr[col] != DBNull.Value && !string.IsNullOrWhiteSpace(dr[col].ToString()) &&

                            //Checks the column is not part of the ignore section before continuing
                            ignoreColumns != null &&
                            ignoreColumns.Length > 0 &&
                            !ignoreColumns.Contains(col.ColumnName)
                           )
                        {
                            //Decrypts the data and puts it into the new rows column
                            newRow[col.ColumnName] = encryptionEngine.DecryptToType<string>(dr[col], cryptKey, authKey);
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
        /// <param name="cryptKey"></param>
        /// <param name="authKey"></param>
        /// <param name="onlyColumns"></param>
        /// <returns></returns>
        public static DataTable AESHMAC512DecryptOnly(this DataTable data, AESHMAC512 encryptionEngine, object cryptKey, object authKey, params string[] onlyColumns)
        {
            //Checks the table even has values before continuing
            if (
                //Checks we have some form of data being supplied
                data != null &&
                data.Rows.Count > 0 &&
                
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
                            //Checks the column data is not empty before continuing
                            dr[col] != DBNull.Value && !string.IsNullOrWhiteSpace(dr[col].ToString()) &&

                            //Checks the column is part of the only accepted ones
                            onlyColumns.Contains(col.ColumnName)
                           )
                        {
                            //Decrypts the data and puts it into the new rows column
                            newRow[col.ColumnName] = encryptionEngine.DecryptToType<string>(dr[col], cryptKey, authKey);
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