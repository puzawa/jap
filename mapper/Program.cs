using PeWrapper;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

class Program
{

    static void Main(string[] args)
    {
        var pe = new PeFile(@"C:\Users\user\source\repos\jap\mapper\HelloWorld.sys");


        Console.WriteLine($"ImageBase: 0x{pe.NtHeaders.OptionalHeader.ImageBase:X}");
        Console.WriteLine($"EntryPoint: 0x{pe.NtHeaders.OptionalHeader.AddressOfEntryPoint:X}");

        Console.WriteLine("\nImports:");
        foreach (var imp in pe.Imports)
        {
            Console.WriteLine($"Module: {imp.ModuleName}");
            foreach (var f in imp.Functions)
                Console.WriteLine($"  {f.Name} -> 0x{f.ResolvedAddress:X}");
        }

        Console.WriteLine("\nRelocs:");
        foreach (var r in pe.Relocs)
            Console.WriteLine($"Block at 0x{r.Address:X} with {r.Items.Length} entries");

        return;
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
