using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

namespace DotNetAES
{
    public static partial class AES
    {
        //##################################################################
        //#######    GZIP Compression And Decompression Functions    #######
        //##################################################################

        public static byte[] Decompress(byte[] data)
        {
            //Opens a memorystream with the input data
            using (MemoryStream inputMS = new MemoryStream(data))
            {
                //Opens the GZIP stream in decompress mode using the input memorystream
                using (GZipStream zipStream = new GZipStream(inputMS, CompressionMode.Decompress))
                {
                    //Opens another memorystream for storing the output
                    using (MemoryStream outputMS = new MemoryStream())
                    {
                        //Processes the bytes through the GZIP decompression and copies them to the output memorystream
                        zipStream.CopyTo(outputMS);

                        //Returns the decompressed byte[] from the output memorystream
                        return outputMS.ToArray();
                    }
                }
            }
        }

        public static byte[] Compress(byte[] data)
        {   
            //Opens a memorystream
            using (MemoryStream memoryStream = new MemoryStream())
            {
                //Opens the GZIP stream in compression mode using the memorystream
                using (GZipStream zipStream = new GZipStream(memoryStream, CompressionMode.Compress))
                {
                    //Writes all the bytes of data to the GZIP stream
                    zipStream.Write(data, 0, data.Length);
                }

                //Returns the compressed byte array from the memorystream
                return memoryStream.ToArray();
            }
        }        
    }
}