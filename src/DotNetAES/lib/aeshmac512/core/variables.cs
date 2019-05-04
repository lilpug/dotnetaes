using System.Security.Cryptography;
namespace DotNetAES.Engines
{
    /// <summary>
    /// AESHMAC512 is an encryption wrapper that utilises GZIP, AES CBC and HMAC SHA512
    /// </summary>
    public partial class AESHMAC512 : AES
    {   
		/// <summary>
        /// Stores the length of the IVs
        /// </summary>
		const int ivSize = 16;

        /// <summary>
        /// Timestamp length (is a double not a string)
        /// </summary>
        const int timestampSize = 8;
    }
}