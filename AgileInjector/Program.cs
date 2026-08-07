using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace AgileInjector
{
    /// <summary>
    /// Windowless entry point. AgileInjector has no UI — it used to run as a WPF app hosting an
    /// invisible empty window whose only live work was starting the IPC server. WPF (and the
    /// WPF DispatcherTimer / WinForms version lookup) removed; Windows-subsystem exe = nothing shown.
    ///
    /// Note: the former MainWindow also constructed a DetectAgent DispatcherTimer and a
    /// LogRotate BackgroundTimer, but neither was ever Start()ed — they were dead. Dropped here;
    /// no runtime behaviour change.
    /// </summary>
    internal static class Program
    {
        private const bool ALLOW_KILLABLE = false;
        private static readonly ManualResetEvent _exit = new ManualResetEvent(false);

        private static readonly string[] TargetMeetingApps = { "zoom", "ms-teams", "ciscocollabhost" };
        private static readonly string[] TargetBrowserApps = { "chrome", "firefox", "msedge", "iexplore" };

        private static readonly BackgroundTimer DetectAgentTimer = new BackgroundTimer(HandleCheckAgentRunning, "DetectAgent");
        private static BackgroundTimer LogRotateTimer;

        [STAThread]
        private static void Main(string[] args)
        {
            try { DebugLog.Init(); } catch { }

            AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
            {
                try { DebugLog.WriteLine("===> UnhandledException when starting up: " + e.ExceptionObject, true); } catch { }
            };
            TaskScheduler.UnobservedTaskException += (sender, e) =>
            {
                try { DebugLog.WriteLine("===> UnobservedTaskException: " + e.Exception?.Message, true); } catch { }
                e.SetObserved();
            };

            try
            {
                bool killable = ALLOW_KILLABLE
                    || Array.Exists(args ?? Array.Empty<string>(), a => a.Equals("kill", StringComparison.OrdinalIgnoreCase));
                if (!killable)
                    Unkillable.UnkillableInit();

                DebugLog.Write("", false);
                DebugLog.Write("---------------------------------", false);
                var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "unknown";
                DebugLog.Write("AgileInjector Client Version " + version);

                LogRotateTimer = new BackgroundTimer(LogRotateTimerCallback, "log rotation");
                LogRotateTimer.Start((int)TimeSpan.FromHours(24).TotalSeconds);

                _ = new IpcHandler();
                Task.Run(() =>
                {
                    try { IpcHandler.Instance.StartServer(); }
                    catch (Exception ex) { try { DebugLog.WriteLine("[Injector] StartServer error: " + ex.Message); } catch { } }
                });

                DetectAgentTimer.Start(2);
            }
            catch (Exception ex)
            {
                try { DebugLog.WriteLine("[Injector] Startup error: " + ex.Message); } catch { }
            }

            _exit.WaitOne();
        }

        private static void LogRotateTimerCallback()
        {
            try
            {
                DebugLog.WriteLine("Log rotation interval hit");

                string folder = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + "\\AgileMark\\";
                Directory.CreateDirectory(folder);
                DebugLog.PerformFileTrim(folder + "injectorlog.txt");
            }
            catch (Exception ex)
            {
                DebugLog.WriteLine("Error in LogRotateTimerCallback: " + ex.Message);
            }
        }

        private static bool IsTargetMeetingAppRunning()
        {
            foreach (var appName in TargetMeetingApps)
            {
                if (Process.GetProcessesByName(appName).Length > 0) return true;
            }
            return false;
        }

        private static bool IsTargetBrowserRunning()
        {
            foreach (var appName in TargetBrowserApps)
            {
                if (Process.GetProcessesByName(appName).Length > 0) return true;
            }
            return false;
        }

        private static void HandleCheckAgentRunning()
        {
            if (IpcHandler.Instance.AgileMarkProcessId.HasValue)
            {
                try { Process.GetProcessById(IpcHandler.Instance.AgileMarkProcessId.Value); }
                catch
                {
                    DebugLog.Write("Not found AgileMark -> exit Injector64");
                    Environment.Exit(0);
                    return;
                }
            }
            else
            {
                bool any = Process.GetProcessesByName("AgileMark").Any();
                if (!any)
                {
                    DebugLog.Write("AgileMark not running -> exit Injector64");
                    Environment.Exit(0);
                    return;
                }
            }

            if (!IpcHandler.Instance.LastWebcamWithWatermark || (!IsTargetMeetingAppRunning() && !IsTargetBrowserRunning()))
            {
                DebugLog.Write("Webcam flag off or no meeting/browser app running -> exit Injector64");
                Environment.Exit(0);
            }
        }
    }
}
