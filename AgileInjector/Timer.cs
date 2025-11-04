using System;
using System.Windows.Threading;

namespace AgileInjector
{
    public class Timer
    {
        private readonly DispatcherTimer DTimer = new DispatcherTimer();
        private readonly Action Callback;
        private readonly string _functionName = string.Empty;

        public bool IsEnable => DTimer.IsEnabled;

        public TimeSpan Interval
        {
            get => DTimer.Interval; set => DTimer.Interval = value;
        }

        public Timer(Action callback, string functionName)
        {
            _functionName = functionName;
            Callback = callback;
            DTimer.Tick += new EventHandler(TimerUpdate);
        }

        public void Start(int interval_in_seconds)
        {
            DTimer.Interval = new TimeSpan(0, 0, interval_in_seconds);
            DTimer.Start();
        }

        private void TimerUpdate(object source, EventArgs e)
        {
            try
            {
                Callback();
            }
            catch (Exception exc)
            {
                DebugLog.WriteLine("Timer Exception: " + exc.Message);
                StopIfRunning();
            }

        }

        public void StopIfRunning()
        {
            if (DTimer.IsEnabled)
            {
                DebugLog.WriteLine($"STOP {_functionName} timer");
                DTimer.Stop();
            }
        }

        public void Stop()
        {
            DTimer.Stop();
        }
    }
}