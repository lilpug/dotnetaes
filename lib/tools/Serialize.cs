using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

namespace DotNetAES
{
    public static partial class Tools
    {
        //##################################################################
        //#######  Core Serialization And Deserialization Functions  #######
        //##################################################################

        /// <summary>
        /// Serializes an object to byte array
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] SerializeToBytes(object data)
        {
            //Loads a memory stream
            using (MemoryStream stream = new MemoryStream())
            {
                //Initialises the formatter
                IFormatter formatter = new BinaryFormatter();

                //Uses the formatter to serialize the object type into a byte array
                formatter.Serialize(stream, data);

                //Returns the byte array
                return stream.ToArray();
            }
        }

        /// <summary>
        /// Deserialize a byte array to a specified type
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        /// <returns></returns>
        public static T DerializeFromBytes<T>(byte[] data)
        {            
            //Checks if any data has been supplied
            if (data != null && data.Length > 0)
            {
                try
                {
                    //Stores the data types
                    T newDataType;

                    //Initialises the binary formatter
                    BinaryFormatter binaryFormatter = new BinaryFormatter();

                    //Loads a memory stream with the supplied data byte array
                    using (MemoryStream memoryStream = new MemoryStream(data))
                    {
                        //Reads the byte array from the memory stream
                        memoryStream.Seek(0, SeekOrigin.Begin);

                        //Uses the binary formatter to deserialise it back into the specified type
                        newDataType = (T)binaryFormatter.Deserialize(memoryStream);
                    }

                    //returns the data
                    return newDataType;
                }
                catch
                {
                    throw new InvalidCastException("The data type is not the same data type that was encrypted.");
                }
            }
            return default(T);
        }

    }
}