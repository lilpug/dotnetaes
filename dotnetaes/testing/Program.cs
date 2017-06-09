using DotNetAES;
using System;
using System.Threading;

namespace testing
{
    class Program
    {
        static void Main(string[] args)
        {
            AESTesting.Core();

            AESHMAC512Testing.Core();
        }
    }
}
