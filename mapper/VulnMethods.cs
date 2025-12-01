using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

internal static class NativeMethods
{
    private const string DllName = "jap.dll";

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern ulong eMMapKernelPeImage(IntPtr driverState, IntPtr image_in);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern IntPtr ePeGetNtHeaders(IntPtr image_base);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static extern bool eTryLoadVuln(string vulnDriverPath, string vulnDriverName, out IntPtr pDriverState);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static extern bool eUnloadVuln(IntPtr driverState);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern ulong eGetKernelModuleAddress(string moduleName);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern ulong eGetKernelModuleExport(IntPtr driverState, ulong kernelModuleBase, string functionName);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool eCallKernelFunction(
        IntPtr driverState,
        ulong functionAddress,
        out ulong returnOut,
        ulong argsCount,
        ulong[] args
    );
}

