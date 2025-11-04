using System;
using System.IO;
using System.Security.AccessControl;

namespace AgileInjector
{
    public static class DebugLog
    {
        public const string DateTimeFormat = "dd/MM/yy HH:mm:ss";
        private static StreamWriter StreamWriter;
        public static string Folder = "";
        private static bool CanWrite = true;


        public static void Init()
        {
            try
            {
                Folder = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + "\\AgileMark\\";
                _ = Directory.CreateDirectory(Folder);
                PerformFileTrim(Folder + "injectorlog.txt");
                ResetPermissionRoamingDirectory();

                FileStream filestream = new FileStream(Folder + "injectorlog.txt", FileMode.Append);
                StreamWriter = new StreamWriter(filestream)
                {
                    AutoFlush = true
                };
                //Console.SetOut(StreamWriter);
                Console.SetError(StreamWriter);

                DebugLog.CanWrite = true;
            }
            catch (Exception e)
            {
                //_ = MessageBox.Show(e.Message);
                //Console.WriteLine("UNABLE TO WRITE injectorlog.TXT");
                Console.WriteLine(e.Message);
                DebugLog.CanWrite = false;
            }

        }


        private static void PerformFileTrim(string filename)
        {
            FileInfo logfile = new FileInfo(filename);

            if (logfile.Exists == false)
            {
                Console.WriteLine("CANNOT FIND LOG.TXT");
                return;
            }

            decimal FileSize = Convert.ToDecimal(logfile.Length);

            if (FileSize > 5000000)
            {
                string[] OriginalFile = File.ReadAllLines(filename);

                int OriginalSize = OriginalFile.Length;
                int AmountToCull = (int)(OriginalSize * 0.33);
                int NewSize = OriginalSize - AmountToCull;

                string[] TrimmedFile = new string[NewSize];
                Array.Copy(OriginalFile, AmountToCull, TrimmedFile, 0, NewSize);
                File.WriteAllLines(filename, TrimmedFile);
            }
        }

        public static void Write(string message, bool timestamp = true)
        {
            if (DebugLog.CanWrite == false)
            {
                return;
            }

            Console.WriteLine(message);
            if (timestamp)
            {
                StreamWriter.Write(DateTime.Now.ToString(DateTimeFormat) + ":   ");
            }

            StreamWriter.WriteLine(message);
        }

        public static void WriteLine(string message, bool timestamp = true)
        {
            if (DebugLog.CanWrite == false)
            {
                return;
            }

            Console.WriteLine(message);
            if (timestamp)
            {
                StreamWriter.Write(DateTime.Now.ToString(DateTimeFormat) + ":   ");
            }

            StreamWriter.WriteLine(message);
        }
        public static void ResetPermissionOfFile(string fullFilename)
        {
            try
            {
                ResetPermissionFolder(Path.GetDirectoryName(fullFilename));
                if (!File.Exists(fullFilename))
                {
                    return;
                }

                FileSecurity fSecurity = File.GetAccessControl(fullFilename);
                // Get the file's authorization rules
                AuthorizationRuleCollection authRules = fSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));
                // Iterate through the authorization rules and remove any that deny access
                foreach (FileSystemAccessRule rule in authRules)
                {
                    if (rule.AccessControlType == AccessControlType.Deny)
                    {
                        _ = fSecurity.RemoveAccessRule(rule);
                    }
                }
                // Add the FileSystemAccessRule to the security settings.
                fSecurity.AddAccessRule(new FileSystemAccessRule(Environment.UserName.ToString(), FileSystemRights.FullControl, AccessControlType.Allow));

                File.SetAccessControl(fullFilename, fSecurity);
                File.SetAttributes(fullFilename, FileAttributes.Normal);
            }
            catch (Exception permEx)
            {
                // Log the permission reset error but continue execution
                Console.WriteLine("Failed to reset permissions: " + permEx.Message);
            }
        }

        public static void ResetPermissionRoamingDirectory()
        {
            string Folder = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\AgileMark\\";
            ResetPermissionFolder(Folder);
        }

        public static void ResetPermissionFolder(string folder)
        {
            try
            {
                // Get the folder's current access control list
                DirectorySecurity folderSecurity = Directory.GetAccessControl(folder);

                // Get the folder's authorization rules
                AuthorizationRuleCollection authRules = folderSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

                // Iterate through the authorization rules and remove any that deny access
                foreach (FileSystemAccessRule rule in authRules)
                {
                    if (rule.AccessControlType == AccessControlType.Deny)
                    {
                        _ = folderSecurity.RemoveAccessRule(rule);
                    }
                }
                folderSecurity.AddAccessRule(new FileSystemAccessRule(Environment.UserName.ToString(), FileSystemRights.FullControl, AccessControlType.Allow));

                // Set the modified access control list back to the folder
                Directory.SetAccessControl(folder, folderSecurity);
            }
            catch (Exception permEx)
            {
                // Log the permission reset error but continue execution
                Console.WriteLine("Failed to reset permissions: " + permEx.Message);
            }
        }
    }
}
