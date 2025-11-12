using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

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

            Task.Run(() => IpcHandler.Instance.StartServer());
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
                }
            }
            else
            {
                bool any = Process.GetProcessesByName("AgileMark").Any();
                if (!any)
                {
                    DebugLog.Write("AgileMark not running -> exit Injector64");
                    Application.Current.Shutdown();
                }
            }
        }
    }
}
