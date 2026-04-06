using Newtonsoft.Json;
using System;
using System.IO.Pipes;
using System.Text;

namespace AgileInjector
{
    public static class AgileSharingConstants
    {
        public const string CMD_INJECT_DLL = "InjectDLL";
    }

    public class DLLMessageWrapper
    {
        public string CMD { get; set; }
        public int SenderProcessId { get; set; }
        public string TargetProcessId { get; set; }
        public IntPtr TargetHwnd { get; set; }
        public string DllName { get; set; }
        public bool IsBrowser { get; set; }
    }

    public class IpcHandler
    {
        #region Singleton
        public static IpcHandler Instance { get; set; }
        public IpcHandler()
        {
            Instance = this;
        }
        #endregion

        public int? AgileMarkProcessId { get; set; }

        public void StartServer()
        {
            const string pipeName = "agileinject64_qaKOab5VPyK4ar4A6sfm2VZ0";

            while (true)
            {
                using (NamedPipeServerStream pipeServer = new NamedPipeServerStream(
                    pipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Message,
                    PipeOptions.Asynchronous))
                {
                    try
                    {
                        DebugLog.WriteLine("[Injector64.StartServer] Waiting for client connection...");
                        pipeServer.WaitForConnection();
                        DebugLog.WriteLine("[Injector64.StartServer] Client connected.");

                        try { pipeServer.ReadMode = PipeTransmissionMode.Message; } catch { }

                        string received = ReadFullMessage(pipeServer);
                        DebugLog.WriteLine($"[Injector64.StartServer] Raw message: [{received}]");

                        if (string.IsNullOrWhiteSpace(received))
                        {
                            DebugLog.WriteLine("[Injector64.StartServer] Empty message.");
                            continue;
                        }

                        DLLMessageWrapper msg = null;
                        try
                        {
                            msg = JsonConvert.DeserializeObject<DLLMessageWrapper>(received);
                        }
                        catch (Exception ex)
                        {
                            DebugLog.WriteLine("[Injector64.StartServer][ERROR] Deserialize failed: " + ex.Message);
                            continue;
                        }

                        if (msg == null || string.IsNullOrWhiteSpace(msg.CMD))
                        {
                            DebugLog.WriteLine("[Injector64.StartServer][ERROR] Invalid message wrapper.");
                            continue;
                        }

                        if (!string.Equals(msg.CMD, AgileSharingConstants.CMD_INJECT_DLL, StringComparison.OrdinalIgnoreCase))
                        {
                            DebugLog.WriteLine($"[Injector64.StartServer] Unknown CMD: {msg.CMD}");
                            continue;
                        }

                        // remember sender pid if present
                        try { AgileMarkProcessId = msg.SenderProcessId; } catch { }

                        if (!uint.TryParse(msg.TargetProcessId, out uint targetPid))
                        {
                            DebugLog.WriteLine("[Injector64.StartServer][ERROR] Cannot parse TargetProcessId: " + msg.TargetProcessId);
                            continue;
                        }

                        // parse TargetHwnd if provided (supports decimal or hex "0x..." )
                        IntPtr hwndFilter = msg.TargetHwnd;

                        if (string.IsNullOrEmpty(msg.DllName))
                        {
                            DebugLog.WriteLine("[Injector64.StartServer][ERROR] dllName is empty, skipping inject.");
                            continue;
                        }

                        DebugLog.WriteLine($"[Injector64.StartServer] CMD_INJECT_DLL received -> targetPid={targetPid}, targetHwnd=0x{hwndFilter.ToInt64():X}, dll={msg.DllName}");

                        try
                        {
                            bool result;
                            if (msg.IsBrowser)
                            {
                                result = Injector.InjectBrowser(targetPid, hwndFilter, msg.DllName);
                            } else
                            {
                                result = Injector.Inject(targetPid, hwndFilter, msg.DllName);
                            }
                                DebugLog.WriteLine(result
                                    ? "[Injector64.StartServer] Inject OK."
                                    : "[Injector64.StartServer] Inject FAILED.");
                        }
                        catch (Exception ex)
                        {
                            DebugLog.WriteLine("[Injector64.StartServer][ERROR] Injector.Inject threw: " + ex);
                        }
                    }
                    catch (Exception ex)
                    {
                        DebugLog.WriteLine("[Injector64.StartServer] Exception: " + ex);
                    }
                    finally
                    {
                        try
                        {
                            if (pipeServer.IsConnected)
                            {
                                pipeServer.Disconnect();
                            }
                        }
                        catch { }
                    }
                }
            }
        }


        private static string ReadFullMessage(NamedPipeServerStream pipe)
        {
            StringBuilder sb = new StringBuilder();
            byte[] buffer = new byte[4096];

            do
            {
                int bytesRead;
                try
                {
                    bytesRead = pipe.Read(buffer, 0, buffer.Length);
                }
                catch
                {
                    break;
                }

                if (bytesRead <= 0)
                {
                    break;
                }

                _ = sb.Append(Encoding.UTF8.GetString(buffer, 0, bytesRead));
            }
            while (!pipe.IsMessageComplete);

            return sb.ToString().Trim();
        }
    }
}
