using System;
using System.IO;

/// <summary>
/// VulnManager is a sealed, disposable class that manages the lifecycle of a vulnerable driver.
/// It wraps a native DriverState pointer, providing methods to load/unload the driver,
/// map PE images to kernel, call kernel functions, and get module exports.
/// All operations are thread-safe via locking, and it ensures proper disposal.
/// </summary>
public sealed class VulnManager : IDisposable
{
    private IntPtr _nativePtr;
    private bool _disposed;
    private readonly object _lock = new();

    /// <summary>
    /// Private constructor to initialize with a native pointer.
    /// </summary>
    /// <param name="nativePtr">The native DriverState* pointer.</param>
    private VulnManager(IntPtr nativePtr) => _nativePtr = nativePtr;

    /// <summary>
    /// Creates a VulnManager instance by loading the vulnerable driver.
    /// Validates inputs, calls native TryLoadVuln, and returns the manager if successful.
    /// </summary>
    /// <param name="driverPath">Full path to the driver file.</param>
    /// <param name="driverName">Name of the driver.</param>
    /// <returns>A VulnManager instance if loaded successfully, null otherwise.</returns>
    public static VulnManager? Create(string driverPath, string driverName)
    {
        if (string.IsNullOrWhiteSpace(driverPath)) throw new ArgumentNullException(nameof(driverPath));
        if (string.IsNullOrWhiteSpace(driverName)) throw new ArgumentNullException(nameof(driverName));
        return NativeMethods.eTryLoadVuln(driverPath, driverName, out var ptr) && ptr != IntPtr.Zero
            ? new VulnManager(ptr)
            : null;
    }

    /// <summary>
    /// Convenience method to create VulnManager using default paths.
    /// Assumes driver is in the same directory as the executable, named "vuln".
    /// Prints the drop path for debugging.
    /// </summary>
    /// <returns>A VulnManager instance if loaded successfully, null otherwise.</returns>
    public static VulnManager? EasyCreate()
    {
        string driverPath = Path.GetDirectoryName(Environment.ProcessPath);
        string driverName = "vuln";
        string fullDriverPath = Path.Combine(driverPath, driverName);
        Console.WriteLine("Dropping driver at: " + fullDriverPath);
        return Create(fullDriverPath, driverName);
    }

    /// <summary>
    /// Static method to get the base address of a kernel module.
    /// Wraps the native GetKernelModuleAddress.
    /// </summary>
    /// <param name="moduleName">Name of the module.</param>
    /// <returns>Base address as ulong.</returns>
    public static ulong GetKernelModuleAddress(string moduleName)
    {
        if (string.IsNullOrWhiteSpace(moduleName)) throw new ArgumentNullException(nameof(moduleName));
        return NativeMethods.eGetKernelModuleAddress(moduleName);
    }

    /// <summary>
    /// Maps a PE image into kernel memory.
    /// Locks for thread safety, validates state and inputs, calls native MMapKernelPeImage.
    /// </summary>
    /// <param name="imageIn">Pointer to the PE image bytes.</param>
    /// <returns>Kernel entry point address.</returns>
    public ulong MMapKernelPeImage(IntPtr imageIn)
    {
        lock (_lock)
        {
            ThrowIfDisposed();
            if (imageIn == IntPtr.Zero)
                throw new ArgumentException("imageIn cannot be zero.", nameof(imageIn));
            return NativeMethods.eMMapKernelPeImage(
                _nativePtr,
                imageIn
            );
        }
    }

    /// <summary>
    /// Calls a kernel function with arguments.
    /// Locks for safety, validates, prepares args, calls native CallKernelFunction.
    /// </summary>
    /// <param name="functionAddress">Kernel function address.</param>
    /// <param name="returnValue">Out return value.</param>
    /// <param name="arguments">Variable arguments as ulong[].</param>
    /// <returns>True if successful.</returns>
    public bool CallKernelFunction(ulong functionAddress, out ulong returnValue, params ulong[] arguments)
    {
        lock (_lock)
        {
            ThrowIfDisposed();
            if (functionAddress == 0)
                throw new ArgumentException("Invalid function address.", nameof(functionAddress));
            if (arguments == null)
                arguments = Array.Empty<ulong>();
            return NativeMethods.eCallKernelFunction(
                _nativePtr,
                functionAddress,
                out returnValue,
                (ulong)arguments.Length,
                arguments
            );
        }
    }

    /// <summary>
    /// Gets the address of a kernel module export.
    /// Locks, validates, calls native GetKernelModuleExport.
    /// </summary>
    /// <param name="kernelModuleBase">Module base address.</param>
    /// <param name="functionName">Export name.</param>
    /// <returns>Export address.</returns>
    public ulong GetKernelModuleExport(ulong kernelModuleBase, string functionName)
    {
        lock (_lock)
        {
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(functionName)) throw new ArgumentNullException(nameof(functionName));
            return NativeMethods.eGetKernelModuleExport(_nativePtr, kernelModuleBase, functionName);
        }
    }

    /// <summary>
    /// Unloads the driver.
    /// Locks, checks state, calls native UnloadVuln, sets disposed.
    /// </summary>
    /// <returns>True if successful.</returns>
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

    /// <summary>
    /// Disposes the manager, unloading if not already disposed.
    /// Suppresses finalizer.
    /// </summary>
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

    /// <summary>
    /// Finalizer to ensure disposal.
    /// </summary>
    ~VulnManager() => Dispose();

    /// <summary>
    /// Throws if object is disposed.
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(VulnManager));
    }
}