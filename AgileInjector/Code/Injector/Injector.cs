using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace AgileInjector
{
    public static class Injector
    {
        // ===== Configuration =====

        // ===== Process access =====
        private const uint PROCESS_CREATE_THREAD = 0x0002;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_VM_READ = 0x0010;

        // ===== Memory flags =====
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_RELEASE = 0x8000;
        private const uint PAGE_READWRITE = 0x04;

        private const uint INFINITE = 0xFFFFFFFF;
        private const uint LIST_MODULES_ALL = 0x03;

        // ===== Token privileges =====
        [StructLayout(LayoutKind.Sequential)]
        private struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privilege;
        }

        private const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
        private const uint TOKEN_QUERY = 0x0008;
        private const string SE_DEBUG_NAME = "SeDebugPrivilege";
        private const uint SE_PRIVILEGE_ENABLED = 0x2;

        // ===== advapi32 =====
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, uint BufferLength,
            IntPtr PreviousState, IntPtr ReturnLength);

        // ===== kernel32 =====
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProc, IntPtr baseAddr, byte[] buffer, uint size, out uint written);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProc, IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        // ===== psapi =====
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess, IntPtr[] lphModule, int cb, out int lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, StringBuilder lpBaseName, int nSize);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, int nSize);

        // ===== user32 (optional verify HWND owner) =====
        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        // ===== Helpers =====
        private static bool IsRunningElevated()
        {
            using (WindowsIdentity id = WindowsIdentity.GetCurrent())
            {
                if (id == null)
                {
                    return false;
                }

                WindowsPrincipal p = new WindowsPrincipal(id);
                return p.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private static bool EnableSeDebug(out string errMsg)
        {
            errMsg = null;
            IntPtr hToken = IntPtr.Zero;
            try
            {
                IntPtr hProc = GetCurrentProcess();
                if (!OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
                {
                    int e = Marshal.GetLastWin32Error();
                    errMsg = $"OpenProcessToken failed: {e} ({new Win32Exception(e).Message})";
                    return false;
                }

                if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out LUID luid))
                {
                    int e = Marshal.GetLastWin32Error();
                    errMsg = $"LookupPrivilegeValue failed: {e} ({new Win32Exception(e).Message})";
                    return false;
                }

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privilege = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
                };

                if (!AdjustTokenPrivileges(hToken, false, ref tp, (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero))
                {
                    int e = Marshal.GetLastWin32Error();
                    errMsg = $"AdjustTokenPrivileges failed: {e} ({new Win32Exception(e).Message})";
                    return false;
                }

                int last = Marshal.GetLastWin32Error();
                if (last != 0)
                {
                    errMsg = $"AdjustTokenPrivileges returned warning/error: {last} ({new Win32Exception(last).Message})";
                    return false;
                }

                return true;
            }
            finally
            {
                if (hToken != IntPtr.Zero)
                {
                    _ = CloseHandle(hToken);
                }
            }
        }

        private static string NormalizeFullPath(string p)
        {
            string full = Path.GetFullPath(p);
            full = full.Replace('/', '\\');
            return full.ToLowerInvariant();
        }

        private static IntPtr FindRemoteModuleBase(IntPtr hProc, string moduleNameNoExt)
        {
            if (string.IsNullOrWhiteSpace(moduleNameNoExt))
            {
                return IntPtr.Zero;
            }

            moduleNameNoExt = moduleNameNoExt.ToLowerInvariant();

            _ = EnumProcessModulesEx(hProc, null, 0, out int size, LIST_MODULES_ALL);
            int count = size / IntPtr.Size;
            if (count <= 0)
            {
                return IntPtr.Zero;
            }

            IntPtr[] mods = new IntPtr[count];
            if (!EnumProcessModulesEx(hProc, mods, size, out _, LIST_MODULES_ALL))
            {
                return IntPtr.Zero;
            }

            StringBuilder sb = new StringBuilder(260);
            for (int i = 0; i < count; i++)
            {
                _ = sb.Clear();
                _ = GetModuleBaseName(hProc, mods[i], sb, sb.Capacity);
                string baseName = sb.ToString();
                if (string.Equals(Path.GetFileNameWithoutExtension(baseName), moduleNameNoExt, StringComparison.OrdinalIgnoreCase))
                {
                    return mods[i];
                }
            }
            return IntPtr.Zero;
        }

        private static IntPtr FindRemoteModuleBaseByPath(IntPtr hProc, string fullPath)
        {
            try
            {
                string target = NormalizeFullPath(fullPath);

                _ = EnumProcessModulesEx(hProc, null, 0, out int size, LIST_MODULES_ALL);
                int count = size / IntPtr.Size;
                if (count <= 0)
                {
                    return IntPtr.Zero;
                }

                IntPtr[] mods = new IntPtr[count];
                if (!EnumProcessModulesEx(hProc, mods, size, out _, LIST_MODULES_ALL))
                {
                    return IntPtr.Zero;
                }

                StringBuilder sb = new StringBuilder(4096);
                for (int i = 0; i < count; i++)
                {
                    _ = sb.Clear();
                    _ = GetModuleFileNameEx(hProc, mods[i], sb, sb.Capacity);
                    string path = NormalizeFullPath(sb.ToString());
                    if (string.Equals(path, target, StringComparison.OrdinalIgnoreCase))
                    {
                        return mods[i];
                    }
                }
            }
            catch (Exception ex)
            {
                DebugLog.WriteLine("[Inject][WARN] FindRemoteModuleBaseByPath exception: " + ex);
            }
            return IntPtr.Zero;
        }

        private static IntPtr RetryFindInjectedModule(IntPtr hProc, string dllFullPath, int retries = 10, int delayMs = 50)
        {
            for (int i = 0; i < retries; i++)
            {
                IntPtr mod = FindRemoteModuleBaseByPath(hProc, dllFullPath);
                if (mod != IntPtr.Zero)
                {
                    return mod;
                }

                Thread.Sleep(delayMs);
            }

            string noExt = Path.GetFileNameWithoutExtension(dllFullPath);
            for (int i = 0; i < retries; i++)
            {
                IntPtr mod = FindRemoteModuleBase(hProc, noExt);
                if (mod != IntPtr.Zero)
                {
                    return mod;
                }

                Thread.Sleep(delayMs);
            }
            return IntPtr.Zero;
        }

        private static bool IsTarget64Bit(IntPtr hProc)
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                return false;
            }

            if (!IsWow64Process(hProc, out bool wow64))
            {
                int err = Marshal.GetLastWin32Error();
                DebugLog.WriteLine($"[Inject] IsWow64Process failed: {err} ({new Win32Exception(err).Message})");
                return Environment.Is64BitProcess;
            }
            return !wow64;
        }

        // compute remote proc address via RVA from local load
        private static IntPtr ComputeRemoteProcByRva(string dllFullPath, IntPtr hModRemote, string procName)
        {
            IntPtr hLocal = LoadLibraryW(dllFullPath);
            if (hLocal == IntPtr.Zero)
            {
                int errLL = Marshal.GetLastWin32Error();
                DebugLog.WriteLine($"[Inject][ERROR] LoadLibraryW(local) failed for RVA compute. {errLL} ({new Win32Exception(errLL).Message})");
                return IntPtr.Zero;
            }
            try
            {
                IntPtr pLocal = GetProcAddress(hLocal, procName);
                if (pLocal == IntPtr.Zero)
                {
                    DebugLog.WriteLine($"[Inject][ERROR] GetProcAddress(local, {procName}) failed.");
                    return IntPtr.Zero;
                }
                long rva = pLocal.ToInt64() - hLocal.ToInt64();
                return new IntPtr(hModRemote.ToInt64() + rva);
            }
            finally
            {
                _ = FreeLibrary(hLocal);
            }
        }

        [CLSCompliant(false)]

        public static bool Inject(uint pid, IntPtr hwndTarget, string dllName)
        {
            DebugLog.WriteLine($"[Inject] Start -> pid={pid}, hwnd=0x{hwndTarget.ToInt64():X}, dll={dllName}");

            // resolve dll path
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string dllFullPath = Path.Combine(baseDir, "x64", dllName);
            string dllFullPathNorm = NormalizeFullPath(dllFullPath);

            DebugLog.WriteLine("[Inject] Using co-located DLL: " + dllFullPath);

            if (!File.Exists(dllFullPath))
            {
                DebugLog.WriteLine("[Inject][ERROR] DLL file not found next to exe: " + dllFullPath);
                return false;
            }

            if (!IsRunningElevated())
            {
                DebugLog.WriteLine("[Inject][WARN] Injector is not elevated. Some targets may fail (ACCESS DENIED).");
            }

            if (!EnableSeDebug(out string enableErr))
            {
                DebugLog.WriteLine("[Inject][WARN] EnableSeDebug failed: " + enableErr);
            }
            else
            {
                DebugLog.WriteLine("[Inject] SeDebugPrivilege enabled.");
            }

            IntPtr hProc = IntPtr.Zero;
            IntPtr remoteBuf = IntPtr.Zero;
            IntPtr hThreadLoad = IntPtr.Zero;

            try
            {
                // open process
                hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, pid);
                if (hProc == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    DebugLog.WriteLine($"[Inject][ERROR] OpenProcess failed. GetLastError={err} ({new Win32Exception(err).Message})");
                    return false;
                }
                DebugLog.WriteLine($"[Inject] OpenProcess OK: hProc=0x{hProc.ToInt64():X}");

                bool targetIs64 = IsTarget64Bit(hProc);
                DebugLog.WriteLine($"[Inject] targetIs64={targetIs64}, injectorIs64={Environment.Is64BitProcess}");
                if (targetIs64 != Environment.Is64BitProcess)
                {
                    DebugLog.WriteLine("[Inject][ERROR] Bitness mismatch. Injector must match target process bitness (x86/x64).");
                    return false;
                }

                // 1) check already loaded
                IntPtr hModRemote = RetryFindInjectedModule(hProc, dllFullPathNorm, retries: 3, delayMs: 10);
                bool alreadyLoaded = hModRemote != IntPtr.Zero;
                if (alreadyLoaded)
                {
                    DebugLog.WriteLine($"[Inject] DLL already loaded in remote. hModRemote=0x{hModRemote.ToInt64():X} -> reuse");
                }
                else
                {
                    // 2) load library via remote LoadLibraryW
                    IntPtr remoteK32 = FindRemoteModuleBase(hProc, "kernel32");
                    if (remoteK32 == IntPtr.Zero)
                    {
                        DebugLog.WriteLine("[Inject][ERROR] kernel32.dll not found in remote process.");
                        return false;
                    }

                    ProcessModule localK32Module = Process.GetCurrentProcess().Modules
                        .Cast<ProcessModule>()
                        .FirstOrDefault(m => string.Equals(Path.GetFileNameWithoutExtension(m.ModuleName), "kernel32", StringComparison.OrdinalIgnoreCase));
                    if (localK32Module == null)
                    {
                        DebugLog.WriteLine("[Inject][ERROR] local kernel32 module not found.");
                        return false;
                    }

                    IntPtr localK32 = localK32Module.BaseAddress;
                    IntPtr localLLW = GetProcAddress(localK32, "LoadLibraryW");
                    if (localLLW == IntPtr.Zero)
                    {
                        DebugLog.WriteLine("[Inject][ERROR] GetProcAddress(local, LoadLibraryW) returned NULL.");
                        return false;
                    }

                    long llwOffset = localLLW.ToInt64() - localK32.ToInt64();
                    IntPtr remoteLLW = new IntPtr(remoteK32.ToInt64() + llwOffset);

                    byte[] pathBytes = Encoding.Unicode.GetBytes(dllFullPath + "\0");
                    uint size = (uint)pathBytes.Length;

                    remoteBuf = VirtualAllocEx(hProc, IntPtr.Zero, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (remoteBuf == IntPtr.Zero)
                    {
                        int err = Marshal.GetLastWin32Error();
                        DebugLog.WriteLine($"[Inject][ERROR] VirtualAllocEx failed. GetLastError={err} ({new Win32Exception(err).Message})");
                        return false;
                    }

                    if (!WriteProcessMemory(hProc, remoteBuf, pathBytes, size, out uint written) || written != size)
                    {
                        int err = Marshal.GetLastWin32Error();
                        DebugLog.WriteLine($"[Inject][ERROR] WriteProcessMemory failed. written={written}/{size} GetLastError={err} ({new Win32Exception(err).Message})");
                        _ = VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
                        return false;
                    }

                    hThreadLoad = CreateRemoteThread(hProc, IntPtr.Zero, 0, remoteLLW, remoteBuf, 0, out uint tid);
                    if (hThreadLoad == IntPtr.Zero)
                    {
                        int err = Marshal.GetLastWin32Error();
                        DebugLog.WriteLine($"[Inject][ERROR] CreateRemoteThread(LoadLibraryW) failed. GetLastError={err} ({new Win32Exception(err).Message})");
                        _ = VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
                        return false;
                    }

                    uint wait = WaitForSingleObject(hThreadLoad, 5000); // 5 seconds timeout
                    DebugLog.WriteLine($"[Inject] WaitForSingleObject(LoadLibrary) -> {wait}, tid={tid}");

                    if (!GetExitCodeThread(hThreadLoad, out uint exitRaw))
                    {
                        int ge = Marshal.GetLastWin32Error();
                        DebugLog.WriteLine($"[Inject][WARN] GetExitCodeThread(LoadLibrary) failed. {ge} ({new Win32Exception(ge).Message})");
                    }
                    else
                    {
                        DebugLog.WriteLine($"[Inject] LoadLibrary thread exit code: 0x{exitRaw:X}");
                        if (exitRaw == 0)
                        {
                             DebugLog.WriteLine("[Inject][ERROR] LoadLibraryW returned NULL in remote process. DLL might be missing dependencies or corrupted.");
                        }
                    }

                    try { if (hThreadLoad != IntPtr.Zero) { _ = CloseHandle(hThreadLoad); } } catch { }
                    hThreadLoad = IntPtr.Zero;

                    if (remoteBuf != IntPtr.Zero)
                    {
                        _ = VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
                        remoteBuf = IntPtr.Zero;
                    }

                    // rescan remote modules for loaded DLL
                    hModRemote = RetryFindInjectedModule(hProc, dllFullPathNorm, retries: 12, delayMs: 50);
                    if (hModRemote == IntPtr.Zero)
                    {
                        DebugLog.WriteLine("[Inject][ERROR] Could not locate injected DLL in remote modules after LoadLibrary.");
                        return false;
                    }

                    DebugLog.WriteLine($"[Inject] DLL loaded in remote. hModRemote=0x{hModRemote.ToInt64():X}");
                }

                DebugLog.WriteLine($"[Inject] into pid={pid} -> OK (alreadyLoaded={alreadyLoaded})");
                return true;
            }
            catch (Exception ex)
            {
                DebugLog.WriteLine("[Inject][FATAL] Exception: " + ex);
                return false;
            }
            finally
            {
                try { if (hThreadLoad != IntPtr.Zero) { _ = CloseHandle(hThreadLoad); } } catch { }
                try { if (remoteBuf != IntPtr.Zero) { _ = VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE); } } catch { }
                try { if (hProc != IntPtr.Zero) { _ = CloseHandle(hProc); DebugLog.WriteLine("[Inject] Closed process handle."); } } catch { }
            }
        }
    }
}
