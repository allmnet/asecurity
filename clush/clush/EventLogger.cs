using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace dnsclush
{
    public static class EventLogger
    {
        private static readonly string source = "ClushDNS";
        private static readonly string logName = "Application";

        /// <summary>
        /// Writes the <paramref name="message"/> to the Application event log with the given severity (<paramref name="entryType"/>).
        /// </summary>
        /// <param name="message">The message text to log.</param>
        /// <param name="entryType">The severity of the message.</param>
        public static void LogEvent(string message, EventLogEntryType entryType)
        {
            try
            {
                if (Environment.UserInteractive)
                {
                    Console.WriteLine("ClushDNS Error: {0}", message);
                }
                else
                {
                    if (!EventLog.SourceExists(source))
                    {
                        EventLog.CreateEventSource(source, logName);
                    }

                    EventLog.WriteEntry(source, message, entryType);
                }
            }
            catch (Exception)
            {
                //Make sure no errors are thrown here to avoid application crash.
            }
        }
    }
}
