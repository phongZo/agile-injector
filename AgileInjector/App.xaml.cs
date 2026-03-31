using System;
using System.Windows;

namespace AgileInjector
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {

        protected override void OnStartup(StartupEventArgs e)
        {
            DebugLog.Init();
            AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(CurrentDomain_UnhandledException);
            base.OnStartup(e);
        }

        // Catch the unhandledExceptions and write to log
        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            DebugLog.WriteLine("===> UnhandledException when starting up: " + e.ExceptionObject.ToString(), true);
        }


        public static bool CheckCommandLineArgument(string test)
        {
#if DIAGNOSTIC_DEBUG
                foreach (string s in CommandLineArguments)
                {
                    if (s.Equals(test, StringComparison.OrdinalIgnoreCase)) return true;
                }
                return false;
#else
            return false;
#endif
        }
    }
}
