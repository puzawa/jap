using System;
using System.Runtime.InteropServices;

class Program
{
    static void Main(string[] args)
    {
        using (var driver = VulnManager.EasyCreate())
        {
            if (driver == null)
            {
                Console.WriteLine("Failed to load driver");
                return;
            }

            var baseAddr = VulnManager.GetKernelModuleAddress("ntoskrnl.exe");
            Console.WriteLine("base: 0x" + baseAddr.ToString("X"));

            var exportAddr = driver.GetKernelModuleExport(baseAddr, "ExAllocatePoolWithTag");
            Console.WriteLine("export: 0x" + exportAddr.ToString("X"));
        }
    }
}
