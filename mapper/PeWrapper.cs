using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace PeWrapper
{
    public sealed class PeFile
    {
        private IntPtr _imageBase;

        public IMAGE_NT_HEADERS64 NtHeaders { get; private set; }
        public List<PeReloc> Relocs { get; private set; }
        public List<PeImport> Imports { get; private set; }

        public PeFile(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException("PE file not found.", path);

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            static extern IntPtr LoadLibrary(string lpFileName);

            var hModule = LoadLibrary(path);
            if (hModule == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            _imageBase = hModule;

            LoadHeaders();
            LoadRelocs();
            LoadImports();
        }

        private void LoadHeaders()
        {
            var headers = Pe.GetNtHeaders(_imageBase);
            if (headers == null)
                throw new InvalidOperationException("Failed to read NT headers.");
            NtHeaders = headers.Value;
        }

        private void LoadRelocs()
        {
            Relocs = Pe.GetRelocsAndFree(_imageBase);
        }

        private void LoadImports()
        {
            Imports = Pe.GetImportsAndFree(_imageBase);
        }
    }
}
