using System;
using System.Threading;

namespace AgileInjector
{
    public class BackgroundTimer
    {
        private System.Threading.Timer Timer;
        private readonly Action Callback;
        private readonly string _functionName = string.Empty;
        private bool _isRunning;

        public TimeSpan Interval { get; set; }

        public BackgroundTimer(Action callback, string functionName)
        {
            Callback = callback;
            _functionName = functionName;
        }

        public void Start(int intervalInSeconds)
        {
            Interval = TimeSpan.FromSeconds(intervalInSeconds);
            Timer = new System.Threading.Timer(TimerCallback, null, TimeSpan.Zero, Interval);
            _isRunning = true;
        }

        public void StopIfRunning()
        {
            if (_isRunning)
            {
                DebugLog.WriteLine($"STOP {_functionName} timer");
                _ = (Timer?.Change(Timeout.Infinite, Timeout.Infinite));
                _isRunning = false;
            }
        }

        public void Stop()
        {
            _ = (Timer?.Change(Timeout.Infinite, Timeout.Infinite));
            _isRunning = false;
        }

        private void TimerCallback(object state)
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
            finally
            {
                if (_isRunning)
                {
                    _ = (Timer?.Change(Interval, Interval));
                }
            }
        }
    }
}