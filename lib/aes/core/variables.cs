using System.Security.Cryptography;
namespace DotNetAES
{
    public static partial class AES
    {
        //Stores the length of the key requirement
        const int theKeySize = 256;

        //Stores the ciphermode to use in AES: CBC
        const CipherMode cipherMode = CipherMode.CBC;
    }
}