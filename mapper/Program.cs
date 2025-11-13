using System;
using System.Runtime.InteropServices;

internal static class NativeMethods
{
    private const string DllName = "jap.dll";

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static extern bool eTryLoadVuln(string vulnDriverPath, string vulnDriverName, out IntPtr pDriverState);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static extern bool eUnloadVuln(IntPtr driverState);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern UIntPtr eGetKernelModuleAddress(string moduleName);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern UIntPtr eGetKernelModuleExport(IntPtr driverState, ulong kernelModuleBase, string functionName);
}

public sealed class DriverState : IDisposable
{
    private IntPtr _nativePtr;
    private bool _disposed;
    private readonly object _lock = new();

    private DriverState(IntPtr nativePtr) => _nativePtr = nativePtr;

    public static DriverState? Create(string driverPath, string driverName)
    {
        if (string.IsNullOrWhiteSpace(driverPath)) throw new ArgumentNullException(nameof(driverPath));
        if (string.IsNullOrWhiteSpace(driverName)) throw new ArgumentNullException(nameof(driverName));

        return NativeMethods.eTryLoadVuln(driverPath, driverName, out var ptr) && ptr != IntPtr.Zero
            ? new DriverState(ptr)
            : null;
    }

    public IntPtr NativePointer
    {
        get
        {
            ThrowIfDisposed();
            return _nativePtr;
        }
    }

    public static UIntPtr GetKernelModuleAddress(string moduleName)
    {
        if (string.IsNullOrWhiteSpace(moduleName)) throw new ArgumentNullException(nameof(moduleName));
        return NativeMethods.eGetKernelModuleAddress(moduleName);
    }

    public UIntPtr GetKernelModuleExport(UIntPtr kernelModuleBase, string functionName)
    {
        ThrowIfDisposed();
        if (string.IsNullOrWhiteSpace(functionName)) throw new ArgumentNullException(nameof(functionName));

        return NativeMethods.eGetKernelModuleExport(_nativePtr, kernelModuleBase.ToUInt64(), functionName);
    }

    public bool Unload()
    {
        lock (_lock)
        {
            if (_disposed || _nativePtr == IntPtr.Zero) return false;

            try
            {
                return NativeMethods.eUnloadVuln(_nativePtr);
            }
            finally
            {
                _nativePtr = IntPtr.Zero;
                _disposed = true;
            }
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(DriverState));
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (!_disposed)
            {
                if (_nativePtr != IntPtr.Zero)
                {
                    try { NativeMethods.eUnloadVuln(_nativePtr); } catch { }
                    _nativePtr = IntPtr.Zero;
                }
                _disposed = true;
            }
        }
        GC.SuppressFinalize(this);
    }

    ~DriverState() => Dispose();
}


class Program
{

    static void Main(string[] args)
    {
        using (var driver = DriverState.Create(@"C:\temp\vuln.sys", "vuln"))
        {
            if (driver == null)
            {
                Console.WriteLine("Failed to load driver");
                return;
            }

            var baseAddr = DriverState.GetKernelModuleAddress("ntoskrnl.exe");
            Console.WriteLine("base: 0x" + baseAddr.ToUInt64().ToString("X"));

            var exportAddr = driver.GetKernelModuleExport(baseAddr, "ExAllocatePoolWithTag");
            Console.WriteLine("export: 0x" + exportAddr.ToUInt64().ToString("X"));
        }
    }
}
