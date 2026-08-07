using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;

namespace AgileInjector
{
    public static class DebugLog
    {
        public const string DateTimeFormat = "dd/MM/yy HH:mm:ss";
        private static StreamWriter StreamWriter;
        public static string Folder = "";
        private static bool CanWrite = true;
        private static readonly ConcurrentDictionary<string, string> LastMessageByKey = new ConcurrentDictionary<string, string>();


        public static void Init()
        {
            try
            {
                Folder = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + "\\AgileMark\\";
                Directory.CreateDirectory(Folder);
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

        public static void PerformFileTrim(string filename)
        {
            try
            {
                var logfile = new FileInfo(filename);
                if (!logfile.Exists)
                {
                    Console.WriteLine("CANNOT FIND: " + filename);
                    return;
                }

                long fileSize = logfile.Length;

                if (fileSize <= 5000000) // 5MB
                {
                    return;
                }

                using (var fs = new FileStream(
                           filename,
                           FileMode.Open,
                           FileAccess.ReadWrite,
                           FileShare.ReadWrite | FileShare.Delete))
                using (var reader = new StreamReader(fs, Encoding.UTF8, true, 4096, leaveOpen: true))
                {
                    var lines = new List<string>();
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        lines.Add(line);
                    }

                    int originalSize = lines.Count;
                    int amountToCull = (int)(originalSize * 0.33);
                    int newSize = originalSize - amountToCull;

                    if (newSize <= 0)
                    {
                        fs.SetLength(0);
                        return;
                    }

                    fs.SetLength(0);
                    fs.Position = 0;

                    using (var writer = new StreamWriter(fs, Encoding.UTF8, 4096, leaveOpen: true))
                    {
                        for (int i = amountToCull; i < originalSize; i++)
                        {
                            writer.WriteLine(lines[i]);
                        }
                        writer.Flush();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION trimming " + filename + ": " + ex);
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

        // Only writes to the log if `message` differs from the last message logged under `key`.
        // Use this for IPC send/receive logging, which otherwise repeats identically on every poll/tick.
        public static void WriteLineIfChanged(string key, string message, bool timestamp = true)
        {
            if (DebugLog.CanWrite == false)
            {
                return;
            }

            if (LastMessageByKey.TryGetValue(key, out string last) && last == message) return;
            LastMessageByKey[key] = message;
            WriteLine(message, timestamp);
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
