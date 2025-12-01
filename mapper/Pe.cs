using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PeWrapper
{
    internal static class PeDef
    {

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativePeRelocInfo
        {
            public ulong address;
            public IntPtr item; // USHORT*
            public uint count;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativePeRelocVec
        {
            public IntPtr relocs; // PeRelocInfo*
            public uint count;
            public uint capacity;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativePeImportFunctionInfo
        {
            public IntPtr name;    // char*
            public IntPtr address; // ULONG64*
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativePeImportInfo
        {
            public IntPtr module_name;              // char*
            public IntPtr function_datas;           // PeImportFunctionInfo*
            public uint function_count;
            public uint function_capacity;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativePeImportVec
        {
            public IntPtr imports; // PeImportInfo*
            public uint count;
            public uint capacity;
        }


    }

    #region Managed representations

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS64
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    public class PeReloc
    {
        public ulong Address { get; set; }
        public ushort[] Items { get; set; }
    }

    public class PeImportFunction
    {
        public string Name { get; set; }
        public IntPtr AddressPtr { get; set; }
        public ulong ResolvedAddress { get; set; }
    }

    public class PeImport
    {
        public string ModuleName { get; set; }
        public List<PeImportFunction> Functions { get; } = new List<PeImportFunction>();
    }

    #endregion

    public static class Pe
    {
        public static IMAGE_NT_HEADERS64? GetNtHeaders(IntPtr imageBase)
        {
            if (imageBase == IntPtr.Zero) return null;

            IntPtr pNt = NativeMethods.ePeGetNtHeaders(imageBase);
            if (pNt == IntPtr.Zero) return null;

            IMAGE_NT_HEADERS64 nt = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(pNt);

            if (nt.OptionalHeader.DataDirectory == null)
                nt.OptionalHeader.DataDirectory = new IMAGE_DATA_DIRECTORY[16];

            return nt;
        }

        public static List<PeReloc> GetRelocsAndFree(IntPtr imageBase)
        {
            var nativeVec = NativeMethods.ePeGetRelocs(imageBase);
            var result = new List<PeReloc>();

            try
            {
                if (nativeVec.relocs == IntPtr.Zero || nativeVec.count == 0)
                    return result;

                var sizeOfNativeReloc = Marshal.SizeOf<PeDef.NativePeRelocInfo>();

                for (uint i = 0; i < nativeVec.count; ++i)
                {
                    IntPtr cur = IntPtr.Add(nativeVec.relocs, (int)(i * sizeOfNativeReloc));
                    var nativeReloc = Marshal.PtrToStructure<PeDef.NativePeRelocInfo>(cur);

                    var managedReloc = new PeReloc
                    {
                        Address = nativeReloc.address
                    };

                    if (nativeReloc.item != IntPtr.Zero && nativeReloc.count > 0)
                    {
                        ushort[] items = new ushort[nativeReloc.count];
                        Marshal.Copy(nativeReloc.item, (short[])(object)items, 0, (int)nativeReloc.count);
                        for (uint k = 0; k < nativeReloc.count; ++k)
                        {
                            IntPtr itemPtr = IntPtr.Add(nativeReloc.item, (int)(k * sizeof(ushort)));
                            items[k] = (ushort)Marshal.ReadInt16(itemPtr);
                        }

                        managedReloc.Items = items;
                    }
                    else
                    {
                        managedReloc.Items = Array.Empty<ushort>();
                    }

                    result.Add(managedReloc);
                }
            }
            finally
            {
                NativeMethods.ePeFreeRelocs(ref nativeVec);
            }

            return result;
        }

        public static List<PeImport> GetImportsAndFree(IntPtr imageBase)
        {
            var nativeVec = NativeMethods.ePeGetImports(imageBase);
            var result = new List<PeImport>();

            try
            {
                if (nativeVec.imports == IntPtr.Zero || nativeVec.count == 0)
                    return result;

                int sizeOfNativeImportInfo = Marshal.SizeOf<PeDef.NativePeImportInfo>();

                for (uint i = 0; i < nativeVec.count; ++i)
                {
                    IntPtr curImport = IntPtr.Add(nativeVec.imports, (int)(i * (uint)sizeOfNativeImportInfo));
                    var nativeImport = Marshal.PtrToStructure<PeDef.NativePeImportInfo>(curImport);

                    var managedImport = new PeImport
                    {
                        ModuleName = nativeImport.module_name != IntPtr.Zero ? Marshal.PtrToStringAnsi(nativeImport.module_name) : null
                    };

                    if (nativeImport.function_datas != IntPtr.Zero && nativeImport.function_count > 0)
                    {
                        int sizeOfNativeFunc = Marshal.SizeOf<PeDef.NativePeImportFunctionInfo>();
                        for (uint f = 0; f < nativeImport.function_count; ++f)
                        {
                            IntPtr curFunc = IntPtr.Add(nativeImport.function_datas, (int)(f * (uint)sizeOfNativeFunc));
                            var nativeFunc = Marshal.PtrToStructure<PeDef.NativePeImportFunctionInfo>(curFunc);

                            string funcName = nativeFunc.name != IntPtr.Zero ? Marshal.PtrToStringAnsi(nativeFunc.name) : null;

                            ulong resolved = 0;
                            if (nativeFunc.address != IntPtr.Zero)
                            {
                                try
                                {
                                    long val = Marshal.ReadInt64(nativeFunc.address);
                                    resolved = unchecked((ulong)val);
                                }
                                catch
                                {
                                    resolved = 0;
                                }
                            }

                            managedImport.Functions.Add(new PeImportFunction
                            {
                                Name = funcName,
                                AddressPtr = nativeFunc.address,
                                ResolvedAddress = resolved
                            });
                        }
                    }

                    result.Add(managedImport);
                }
            }
            finally
            {
                NativeMethods.ePeFreeImports(ref nativeVec);
            }

            return result;
        }
    }
}
