using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AgileInjector
{
    public static class Unkillable
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetKernelObjectSecurity(IntPtr Handle, int securityInformation, [Out] byte[] pSecurityDescriptor, uint nLength, out uint lpnLengthNeeded);

        //do not remove
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetKernelObjectSecurity(IntPtr Handle, int securityInformation, [In] byte[] pSecurityDescriptor);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        public static IntPtr GetCurrentProcessWrapper()
        {
            return GetCurrentProcess();
        }


        [Flags]
        private enum ProcessAccessRights
        {
            PROCESS_TERMINATE = 0x0001, //  Required to terminate a process using TerminateProcess.
        }

        private static RawSecurityDescriptor GetProcessSecurityDescriptor(IntPtr processHandle)
        {

            const int DACL_SECURITY_INFORMATION = 0x00000004;
            byte[] psd = new byte[0];
            // Call with 0 size to obtain the actual size needed in bufSizeNeeded
            _ = GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, psd, 0, out uint bufSizeNeeded);

            if (false || bufSizeNeeded > short.MaxValue)
            {
                throw new Win32Exception();
            }

            // Allocate the required bytes and obtain the DACL
            psd = new byte[bufSizeNeeded];
            if (!GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, psd, bufSizeNeeded, out _))
            {
                throw new Win32Exception();
            }

            // Use the RawSecurityDescriptor class from System.Security.AccessControl to parse the bytes:
            return new RawSecurityDescriptor(psd, 0);
        }

        private static void SetProcessSecurityDescriptor(IntPtr processHandle, RawSecurityDescriptor dacl)
        {
            const int DACL_SECURITY_INFORMATION = 0x00000004;
            byte[] rawsd = new byte[dacl.BinaryLength];
            dacl.GetBinaryForm(rawsd, 0);
            try
            {
                _ = SetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, rawsd);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }
        }

        public static bool UnkillableActivated { get; set; } = false;
        public static void UnkillableInit()
        {
            // Get the current process handle
            IntPtr hProcess = GetCurrentProcessWrapper();
            // Read the DACL
            RawSecurityDescriptor dacl = GetProcessSecurityDescriptor(hProcess);
            // Insert the new ACE (dacl set PROCESS_TERMINATE access denied)
            dacl.DiscretionaryAcl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, (int)ProcessAccessRights.PROCESS_TERMINATE, new SecurityIdentifier(WellKnownSidType.WorldSid, null), false, null));
            // Save the DACL
            SetProcessSecurityDescriptor(hProcess, dacl);

            UnkillableActivated = true;
        }

    }
}
