using System.Security.Cryptography;
namespace DotNetAES
{
    /// <summary>
    /// AESHMAC512 is an encryption wrapper that utilises GZIP, AES CBC and HMAC SHA512
    /// </summary>
    public static partial class AESHMAC512
    {   
        /// <summary>
        /// Stores the length of the key requirement
        /// </summary>
        const int theKeySize = 256;
		
		/// <summary>
        /// Stores the length of the IVs
        /// </summary>
		const int ivSize = 16;

        /// <summary>
        /// Timestamp length (is a double not a string)
        /// </summary>
        const int timestampSize = 8;

        /// <summary>
        /// Stores the ciphermode to use in AES: CBC
        /// </summary>
        const CipherMode cipherMode = CipherMode.CBC;
    }
}