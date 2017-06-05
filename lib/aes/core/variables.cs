using System.Security.Cryptography;
namespace DotNetAES
{
    public static partial class AES
    {   
        /// <summary>
        /// Stores the length of the key requirement
        /// </summary>
        const int theKeySize = 256;
        
        /// <summary>
        /// Stores the ciphermode to use in AES: CBC
        /// </summary>
        const CipherMode cipherMode = CipherMode.CBC;
    }
}