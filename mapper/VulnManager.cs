public sealed class VulnManager : IDisposable
{
    private IntPtr _nativePtr;
    private bool _disposed;
    private readonly object _lock = new();

    private VulnManager(IntPtr nativePtr) => _nativePtr = nativePtr;

    public static VulnManager? Create(string driverPath, string driverName)
    {
        if (string.IsNullOrWhiteSpace(driverPath)) throw new ArgumentNullException(nameof(driverPath));
        if (string.IsNullOrWhiteSpace(driverName)) throw new ArgumentNullException(nameof(driverName));

        return NativeMethods.eTryLoadVuln(driverPath, driverName, out var ptr) && ptr != IntPtr.Zero
            ? new VulnManager(ptr)
            : null;
    }

    public static ulong GetKernelModuleAddress(string moduleName)
    {

        if (string.IsNullOrWhiteSpace(moduleName)) throw new ArgumentNullException(nameof(moduleName));
        return NativeMethods.eGetKernelModuleAddress(moduleName);

    }

    public ulong GetKernelModuleExport(ulong kernelModuleBase, string functionName)
    {
        lock (_lock)
        {
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(functionName)) throw new ArgumentNullException(nameof(functionName));

            return NativeMethods.eGetKernelModuleExport(_nativePtr, kernelModuleBase, functionName);
        }
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

    ~VulnManager() => Dispose();

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(VulnManager));
    }
}
