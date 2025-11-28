using System;
using System.Runtime.InteropServices;

class Program
{
    static void Main(string[] args)
    {
        using (var kc = new KCaller())
        {
            Console.WriteLine("Calling ExAllocatePoolWithTag...");

            ulong result = kc.ExAllocatePoolWithTag(
                poolType: 0,
                size: 0x1000,
                tag: 0xDEAD
            );

            Console.WriteLine("Allocated kernel memory at: 0x" + result.ToString("X"));
        }

    }
}
