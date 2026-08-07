using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace AgileInjector
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public IpcHandler IpcHandler { get; set; } = new IpcHandler();
        public const bool ALLOW_KILLABLE = false;
        private Timer Timer { get; set; } = new Timer(HandleCheckAgentRunning, "DetectAgent");
        private BackgroundTimer LogRotateTimer;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            Hide();

            if (!App.CheckCommandLineArgument("kill") && !ALLOW_KILLABLE)
            {
                Unkillable.UnkillableInit();
            }
            DebugLog.Write("", false); 
            DebugLog.Write("---------------------------------", false);
            DebugLog.Write("AgileInjector Client Version " + System.Windows.Forms.Application.ProductVersion);
            LogRotateTimer = new BackgroundTimer(LogRotateTimerCallback, "log rotation");

            Timer.StopIfRunning();
            Timer.Start(2);

            Task.Run(() => IpcHandler.Instance.StartServer());
        }
        private void LogRotateTimerCallback()
        {
            try
            {
                DebugLog.WriteLine("Log rotation interval hit");

                String folder = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + "\\AgileMark\\";
                Directory.CreateDirectory(folder);
                DebugLog.PerformFileTrim(folder + "injectorlog.txt");

                // reset 24h
                LogRotateTimer.Interval = new TimeSpan(24, 0, 0);
            }
            catch (Exception ex)
            {
                DebugLog.WriteLine("Error in LogRotateTimerCallback: " + ex.Message);
            }
        }


        private static readonly string[] TargetMeetingApps = { "zoom", "ms-teams", "ciscocollabhost" };

        private static bool IsTargetMeetingAppRunning()
        {
            foreach (var appName in TargetMeetingApps)
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
                    Application.Current.Shutdown();
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
                    Application.Current.Shutdown();
                    return;
                }
            }

            if (!IpcHandler.Instance.LastWebcamWithWatermark || !IsTargetMeetingAppRunning())
            {
                DebugLog.Write("Webcam flag off or no meeting app running -> exit Injector64");
                Application.Current.Shutdown();
                Environment.Exit(0);
            }
        }
    }
}
