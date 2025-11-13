using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("mylib.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void PrintMessage([MarshalAs(UnmanagedType.LPStr)] string msg);

    static void Main(string[] args)
    {
        Console.WriteLine("Hello!");
    }
}
