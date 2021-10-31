using System;
using System.Collections.Generic;
using System.Reflection;
using System.Linq;
using System.IO;
using System.Diagnostics;

namespace RouterProject
{
    public class Router
    {
        /*************************** ROUTER PARAMETERS ***************************/

        private static String IVsStr;
        private static String GlobDictStr;
        private static String MatrixStr;
        private static String PrecomputedHashesStr;
        /************************************************************************/


        /******************************* Constants ***********************************************************************************************************************************************/
        private const int DBG = 0;                                                  // when set to 1, the Router doesn't consider decryption nor solved hash correspondences
                                                                                    // therefore allowing developers to easily test their code with Router function call 
                                                                                    // replacing original source code statements. Such mode also allows to understand whether
                                                                                    // the replacement were made properly or not. 

        private const string ROUTER_PROJECT_NAME = "RouterProject";                 // Router project name
        private const int    TOT_METHODS_CACHED = 10;                               // the number of methods the user desires to cache
        /****************************************************************************************************************************************************************************************/

        private static List<MethodBase> MethodsCache = new List<MethodBase>(TOT_METHODS_CACHED);            // List used to implement a method cache mechanism,
                                                                                                            // preventing the overhead in retrieving the same method multiple times in a short period of time
        private static Dictionary<int, string> PrecomputedHashes;                                           // solved hashes computed during the init (i.e. init()) step, user-added base-64 encoded string to Router's code
        private static Dictionary<int, string> RuntimeComputedHashes = new Dictionary<int, string>();       // run-time computed solved hashes

        private static string DecompiledDstFolder;                                  // decompiled code destination folder
        private static Dictionary<Type, (string, string)> GlobClassDict;            // will contain <ClassType, (class.FullName, (class's absolute pathname, class's relative pathname)) (i.e. excluding the path to directory containing it)). 
        private static int[,] Matrix;                                               // matrix of integers (0 or 1) where each matrix[i,j] = 1 means the filename with index i has a dependency with file index j
        private static List<string> SortedFilenames;                                // the sorted filenames, used to define unique indices
        private static List<int> TopSorted;                                         // the topologically sorted vertices, represented by their corresponding integer value
        private static List<byte[]> IVs;                                            // set of 32-bytes IV, one for each file that needs encryption: each IV will be XOR-ed with the runtime computed symmetric encryption key

        private static int FWDCALL_COUNTER = 0;                                     // a simple counter used for testing purposes
        private static Assembly KeePassLibAsm;                                      // the Assembly object instance corresponding to the KeePassLib DLL
        private static string EncryptionKey;                                        // runtime computed encryption key


        /**
         * <summary>This must be first statement executed by the application intended to be secured. 
         * This initialization step compute the file dependencies graph, generate encryption key and all the required random IVs.
         * Then it encrypts the source file info regarding calls to Router functions and subsequently precompute the solved hashes. 
         * Finally, it outputs the Base64 encoded strings required to the Router at runtime, when it will have to forward calls.</summary>
         */
        public static void Init()
        {
            if (KeePassLibAsm == null)          // Load the KeePassLib DLL corresponding Assembly
                KeePassLibAsm = RouterUtils.LoadKeePassLibAsm(Process.GetCurrentProcess().MainModule.FileName);

            if (IsDebugging())                      // initialize nothing if you're debugging, just return
                return;

            RouterUtils.CheckDependencies();      // make sure ILSpy dependency is installed 


            // if init() step was run already and the user added all the required Base64 strings
            // within the Router's code then go on decoding such Base64 strings in corresponding object instances
            List<string> requiredVars = new List<string> { GlobDictStr, MatrixStr, PrecomputedHashesStr};           // the List of required base64 encoded string after the init step.
            if (requiredVars.Any(i => i != null)) {
                
                requiredVars.Add(IVsStr);

                // if any required variable is not defined, then quit
                if (requiredVars.Any(i => i == null))
                    RouterUtils.ShowErrorMsgBox("Some required base-64 encoded string not provided\nQuitting..", 3);

                // Parse required data from Base64 provided strings to corresponding C# objects
                Matrix = (int[,])RouterUtils.StringToObject(MatrixStr);
                GlobClassDict = (Dictionary<Type, (string, string)>)RouterUtils.StringToObject(GlobDictStr);
                SortedFilenames = RouterUtils.GetSortedFilenames(ref GlobClassDict);                    // retrieve sorted relative filenames
                IVs = (List<byte[]>)RouterUtils.StringToObject(IVsStr);                                  // decode Base64 IVsStr string
                Console.WriteLine($"[*] Decoded IVs {IVs.Count}");

                RouterUtils.BreakAnyCycle(ref Matrix, Enumerable.Range(0, SortedFilenames.Count).ToList());         // break cycles
                TopSorted = RouterUtils.GetTopologicalSort(ref Matrix);                                             // compute topological sort
                PrecomputedHashes = (Dictionary<int, string>)RouterUtils.StringToObject(PrecomputedHashesStr);        // compute solved hashes

                // Decompile the running executable file within the provided destination folder
                DecompiledDstFolder = RouterUtils.GetTempFolder();
                RouterUtils.DecompileApp(DecompiledDstFolder);

                return;
            }


            // Retrieve parent folder of the directory containing the project solution file
            string DstFolderName = "SEC-" + Path.GetFileName(Directory.GetParent(Directory.GetCurrentDirectory()).Parent.Parent.FullName);
            DecompiledDstFolder = Directory.GetParent(Directory.GetCurrentDirectory()).Parent.Parent.Parent.FullName + "\\" + DstFolderName;


            // Decompile code into the same folder the original project is contained into
            // clean directory content if it already exists, otherwise create such directory
            if (Directory.Exists(DecompiledDstFolder))
                RouterUtils.CleanDirectory(DecompiledDstFolder);
            else
                Directory.CreateDirectory(DecompiledDstFolder);

            RouterUtils.DecompileApp(DecompiledDstFolder);
            Console.WriteLine();

            var watch = Stopwatch.StartNew();                   // store init() start time (without considering de-compilation time -- about 5/6s more). 

            // Retrieve projects and their absolute pathnames -- therefore the root folders which will be used to retrieve the source code file corresponding to classes identified through reflection
            // then, for each project (referenced assembly), retrieve all the classes & their methods through reflection
            var projectList = RouterUtils.GetProjects().Where(p => !(p.ProjectName.Equals(ROUTER_PROJECT_NAME) || p.ProjectName.Equals("TrlUtil"))).ToList();
            List<string> projectNames = projectList.Select(p => p.ProjectName).ToList();

            // retrieve EXE absolute pathname and parent directory
            string exeAbsPathname = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;     
            string exeAbsDirectory = AppDomain.CurrentDomain.BaseDirectory;                                 
            Console.WriteLine($"[*] Tot Projects (RouterProject and TrlUtil excluded): {projectList.Count}");
            Console.WriteLine(String.Join(", ", projectList.Select(p => p.ProjectName).ToList()));  
            Console.WriteLine($"[*] EXE filename is '{exeAbsPathname}' -- dir '{exeAbsDirectory}'");

            
            // Retrieve all classes of running project Solution (i.e. classes of each C# Project)
            Dictionary<string, List<Type>> projectClasses = RouterUtils.GetProjectsClasses(projectNames);
            Console.WriteLine($"Tot Projects: {projectClasses.Count}");
            //projectClasses.Keys.ToList().ForEach(k => Console.WriteLine($"dict[{k}] = '{projectClasses[k].Count}'"));
            //Console.WriteLine($"Tot classes {projectClasses["KeePass"].Count + projectClasses["KeePassLib"].Count}");

            // Retrieve correspondences between Decompiled sources of Classes for running EXE (mixed, without considering project they belong to)
            GlobClassDict = RouterUtils.GetDecompiledCorrespondence(projectClasses, DecompiledDstFolder);
            Console.Write($"\nInitial dict ({GlobClassDict.Keys.Count} entries).");

            // Remove empty keys from Dictionary 
            RouterUtils.RemoveNullKeys(ref GlobClassDict);
            Console.Write($"\nNot-null keys Dict ({GlobClassDict.Keys.Count} entries).");

            // Sort Dictionary keys by Value.Item3 (i.e. the relative pathname)
            // NOTE: can't sort by abs pathname, the relative pathname will not change between different runtime decompilationS
            GlobClassDict = RouterUtils.SortByRelativePathname(GlobClassDict);
            Console.WriteLine($"\nOrdered Dict ({GlobClassDict.Keys.Count} entries).");
            //RouterUtils.printDictionary($"\nOrdered Dict computed ({globClassDict.Keys.Count} entries):", ref globClassDict);

            // Sort (decompiled) absolute filenames
            SortedFilenames = RouterUtils.GetSortedFilenames(ref GlobClassDict);

            int totSourceFiles = SortedFilenames.Count;
            Console.WriteLine($"[*] Tot identified classes {GlobClassDict.Keys.Count} --- tot files {totSourceFiles}\n");

            // Define File Dependency Matrix
            Matrix = new int[totSourceFiles, totSourceFiles];

            // Find dependencies
            RouterUtils.FindDependencies(SortedFilenames, ref Matrix, GlobClassDict, DecompiledDstFolder);
            /*Console.WriteLine("\n[*] Initial matrix: ");
            RouterUtils.InterpretMatrix(ref Matrix, SortedFilenames);*/

            // Break Cycles (if any)
            RouterUtils.BreakAnyCycle(ref Matrix, Enumerable.Range(0, totSourceFiles).ToList());
            /*Console.WriteLine("[*] No Cycle Matrix: ");
            RouterUtils.InterpretMatrix(ref Matrix, SortedFilenames);*/

            // Compute Topological Sort
            Console.WriteLine("[*] Computing Topological Order...");
            TopSorted = RouterUtils.GetTopologicalSort(ref Matrix);
            //RouterUtils.InterpretMatrix(ref Matrix, SortedFilenames);
            Console.WriteLine($"[*] Tot ordered nodes: {TopSorted.Count}");
            //Console.WriteLine($"[*] {String.Join(", ", topSorted)}");

            // Initialize pre-computed hashes data structure 
            PrecomputedHashes = new Dictionary<int, string>();

            // Compute Encryption Key
            EncryptionKey = RouterUtils.GetEncryptionKey(TopSorted, SortedFilenames, ref Matrix, ref PrecomputedHashes, DecompiledDstFolder);
            Console.WriteLine($"[*] Runtime computed encryption key {EncryptionKey}");

            // Compute a random IV for each file having dependencies, therefore for each file where info regarding forwarded calls have to be encrypted
            IVs = RouterUtils.ComputeIVs(ref Matrix, SortedFilenames, DecompiledDstFolder, Convert.FromBase64String(EncryptionKey));

            // Encrypt any "forwardCall" method call parameters found in source files 
            RouterUtils.EncryptRouterCalls(ref Matrix, DecompiledDstFolder, SortedFilenames, EncryptionKey, IVs);

            // Compute solved hashes
            RouterUtils.ComputeSolvedHashes(TopSorted, SortedFilenames, ref Matrix, DecompiledDstFolder, ref PrecomputedHashes);

            watch.Stop();
            var elapsedMs = watch.ElapsedMilliseconds;

            // Print Data to insert within Router's code
            Console.WriteLine($"\n[*] ----- Init() STEP TERMINATED in {elapsedMs}ms == {elapsedMs / 1000}s-----\n[*] Now just copy-paste the following String definitions in place of those you find at the very first lines of Router.cs class.\n[*] Then re-compile the software with modified source files");
            Console.WriteLine();
            Console.WriteLine($"[*] Generated IVs ({IVs.Count}):");
            Console.WriteLine($"private static String IVsStr = \"{RouterUtils.ObjectToString(IVs)}\";");

            Console.WriteLine($"[*] Last Dictionary is: ");
            Console.WriteLine($"private static String GlobDictStr = \"{RouterUtils.ObjectToString(GlobClassDict)}\";");

            Console.WriteLine("[*] Matrix is: ");
            Console.WriteLine($"private static String MatrixStr = \"{RouterUtils.ObjectToString(Matrix)}\";");

            Console.WriteLine($"[*] Solved hashes: ");
            Console.WriteLine($"private static String PrecomputedHashesStr = \"{RouterUtils.ObjectToString(PrecomputedHashes)}\";");       // Output precomputedHashes            
            Console.WriteLine();

            
            Environment.Exit(1);
        }


        /**
         * <summary>Publicly exposed method used to forward function calls through the Router class</summary>
         * <param name="encryptedParams">the Base64 encoded string representing the encrypted parameters</param>"
         * <param name="callingClass">the calling class full name</param>
         * <param name="objs">the optional list of object instance that cannot be encrypted at compile-time</param>
         * <returns>the object returned by the target method, explicit cast is required as it cannot be known in advance</returns>
         */
        static public object ForwardCall(string encryptedParams, string callingClass, params object[] objs)
        {
            FWDCALL_COUNTER++;          // increase forward call counter

            string decryptedParams;

            if (IsDebugging())   decryptedParams = encryptedParams;              // if debugging, then don't decrypt anything as method info have to be encrypted yet
            else {
                // ensures input string is a valid base-64 string
                if (!RouterUtils.IsBase64Str(encryptedParams))
                    RouterUtils.ShowErrorMsgBox("Plagiarism Attempt Detected.\nQuitting..", 5);             // PLAGIARISM ATTEMPT DETECTED

                // compute encryption key at run-time && decrypt input parameters
                if(EncryptionKey == null)
                    EncryptionKey = RouterUtils.GetEncryptionKey(TopSorted, SortedFilenames, ref Matrix, ref PrecomputedHashes, DecompiledDstFolder);
                //Console.WriteLine($"[*] Runtime computed encryption key: {EncryptionKey}");

                // retrieve the index of the corresponding IV to be used for decription 
                int ivIndex = RouterUtils.IndexInMatrix(callingClass, SortedFilenames, ref Matrix);
                //Console.WriteLine($"[*] ivIndex for class '{callingClass}': {ivIndex}   that is {Convert.ToBase64String(IVs[ivIndex])}");

                byte[] xorRes = RouterUtils.XorByteArrays(Convert.FromBase64String(EncryptionKey), IVs[ivIndex]);
                //Console.WriteLine($"IV xor key: {Convert.ToBase64String(xorRes)}");
                
                //Console.WriteLine($"[*] Encrypted value: {encryptedParams}");
                // XOR the unique IV with runtime computed key, preventing known-ciphertext attacks
                decryptedParams = RouterUtils.DecryptStringFromBytes(Convert.FromBase64String(encryptedParams), xorRes, IVs[0]);
                //Console.WriteLine($"[*] Decrypted value: \"{decryptedParams}\"");
            }

            return Forward(callingClass, decryptedParams, objs);                      // call private 'forward' method with decrypted parameters
        }

        /**
         * <summary>Private method used to parse decrypted parameters and redirect the function call if it is legit.</summary>
         * <param name="callingClass">calling classname</param>
         * <param name="decryptedStrParam">decrypted string containing function parameters</param>
         * <param name="objs">optional array of objects</param>
         * <returns>the object returned by the target method, explicit cast is required as it cannot be known in advance</returns>
         */
        static private object Forward(string callingClass, string decryptedStrParam, params object[] objs)
        {
            string[] args = decryptedStrParam.Replace("\"", "").Split('-');                 // Split decrypted parameters by the known separator '-'
            if (args.Length != 4) {
                Console.WriteLine($"descrypted params: {decryptedStrParam}");
                Console.WriteLine($"length: {args.Length}");

                RouterUtils.ShowErrorMsgBox("Plagiarism Attempt Detected.\nQuitting..", 6);        // PLAGIARISM ATTEMPT DETECTED
            }

            string dstClassStr = args[0];
            string methodName = args[1].Trim();
            string[] parameters = args[3].Split(',');
            Type[] paramsType = RouterUtils.ParseParamsType(args[2]);                           // parse parameters Types
            object[] inParams = RouterUtils.ParseParamsValues(args[3], paramsType, objs);       // parse parameters values
            Type dstClass;
            MethodBase method = null;

            Console.WriteLine($"[*] -- FORWARD N {FWDCALL_COUNTER} CALL STARTED (for class {callingClass}) on method {dstClassStr}.{methodName}(..) --\n");
            
            foreach (MethodBase mb in MethodsCache) 
                if (RouterUtils.MatchMethod(mb, methodName, dstClassStr, parameters, args))
                {
                    dstClass = mb.DeclaringType;
                    method = mb;

                    // ensure runtime computed solved hash of callee/caller corresponds to precomputed ones
                    string r = ValidForward(callingClass, dstClass);
                    if (r != null)
                        RouterUtils.ShowErrorMsgBox("Plagiarism Attempt Detected.\nQuitting..", 7);        // PLAGIARISM ATTEMPT DETECTED

                    return CustomInvoke(method, paramsType, inParams, objs);
                }

            dstClass = RouterUtils.GetTypeFromStr(dstClassStr);                // retrieve the Type corresponding to the dstClassStr string    
            if (dstClass == null)
                RouterUtils.ShowErrorMsgBox($"Cannot retrieve type {dstClassStr} -- called from {callingClass}. Make sure you specified the correct class full name", 3);
            
            // ensure runtime computed solved hash of callee/caller corresponds to precomputed ones
            string res = ValidForward(callingClass, dstClass);
            if (res != null)
                RouterUtils.ShowErrorMsgBox("Plagiarism Attempt Detected.\nQuitting..", 7);        // PLAGIARISM ATTEMPT DETECTED

           
            // retrieve MethodInfo regarding methodName and parameters types using Reflection
            method = dstClass.GetMethod(methodName, paramsType);
            // is it is still null, attempt to retrieve a Constructor
            if(method == null)
                method = dstClass.GetConstructor(paramsType);


            if (method == null) {
                // Retrieve method directly from the "external" assembly
                dstClass = KeePassLibAsm.GetType(dstClassStr);

                // retrieve MethodInfo regarding methodName and parameters types using Reflection
                List<MethodBase> methods = RouterUtils.GetClassMethods(dstClass);
                foreach(MethodBase mb in methods)
                    if (RouterUtils.MatchMethod(mb, methodName, dstClassStr, parameters, args))
                        method = mb;
            }

            if (method == null)
                RouterUtils.ShowErrorMsgBox($"Method {methodName} not found for class {dstClassStr}", 30);
            else             
                CacheMethod(method);            // add the method to cached ones 

            return CustomInvoke(method, paramsType, inParams, objs);
        }

        /**
         * <summary>Ensures the forwarded call is allowed</summary>
         * <param name="srcClassStr">the calling classname string</param>
         * <param name="dstClass">the Type corresponding to the destination class</param>
         * <returns>null if the call is valid, otherwise it returns the classname that made the call not-allowed</returns>
         */
        static private string ValidForward(string srcClassStr, Type dstClass)
        {
            if (IsDebugging())              // while debugging, then just skip this method returning null
                return null;

            string dstClassStr = dstClass.FullName;

            //Console.WriteLine($"[*] --- VALID FORWARD calling class '{srcClassStr}' to '{dstClass.FullName}' ---");

            // get Index of corresponding source file where calling Class was defined
            int callingClassIndex = -1;
            List<string> lastDictKeys = new List<string>();
            foreach (Type t in GlobClassDict.Keys)
                lastDictKeys.Add(t.FullName);
            lastDictKeys.Sort();
            foreach (string k in lastDictKeys)
                if (k.Equals(srcClassStr))
                    callingClassIndex = lastDictKeys.IndexOf(k);
            

            // Find calling class source file index
            int callClassFileIndex = -1;
            foreach (Type k in GlobClassDict.Keys)
                if (k.FullName.Equals(srcClassStr))
                    callClassFileIndex = SortedFilenames.IndexOf(GlobClassDict[k].Item2);


            string oldHash = PrecomputedHashes[callClassFileIndex];
            string newHash;

            if (RuntimeComputedHashes.Keys.Contains(callClassFileIndex))                // do not recompute already computed (runtime) hashes
                newHash = RuntimeComputedHashes[callClassFileIndex];
            else {
                RuntimeComputedHashes[callClassFileIndex] = RouterUtils.ComputeSingleHash(callClassFileIndex, TopSorted, SortedFilenames, ref Matrix, DecompiledDstFolder);
                newHash = RuntimeComputedHashes[callClassFileIndex];
            }

            /*Console.WriteLine($"\n[*] Checking solved hashes for call to {dstClassStr} made by '{srcClassStr}' --- {srcClassStr} ({callingClassIndex}) ---> {dstClassStr} ({lastDictKeys.IndexOf(dstClass.FullName)}) ");
            Console.WriteLine($"[*] Old hash is {oldHash} --- that is {RouterUtils.ByteArrayToString(Convert.FromBase64String(oldHash))}");
            Console.WriteLine($"[*] New hash is {newHash} --- that is {RouterUtils.ByteArrayToString(Convert.FromBase64String(newHash))}");
            Console.WriteLine();*/

            if (!newHash.Equals(oldHash))
                foreach (var k in GlobClassDict.Keys)
                    if (GlobClassDict[k].Item2.Equals(SortedFilenames[callClassFileIndex]))
                        return k.FullName;

            return null;
        }

        /**
         * <summary>Invokes the target method and returns its same output value</summary>
         * <param name="paramTypes">array of Type corresponding to input parameters</param>
         * <param name="inParams">array of input parameters values</param>
         * <param name="objs">optional list of objects, the first element is always considered as the instance exposing the target method (null if method is static)</param>
         * <returns>the object returned by the target method, explicit cast is required as it cannot be known in advance</returns>
         */
        static private object CustomInvoke(MethodBase method, Type[] paramTypes, object[] inParams, params object[] objs)
        {
            bool IsaConstructor = false;
            if (method.IsConstructor)
                IsaConstructor = true;

            if (objs.Length == 0)
            {                       // method needs no obj instance (i.e. it is a static method)              
                if(!IsaConstructor)
                    return method.Invoke(null, inParams);
                else
                    return Activator.CreateInstance(method.DeclaringType);
            }
            else if (objs.Length == 1)                  // invokes method on the input obj instance
                return method.Invoke(objs[0], inParams);
            else                                        // 
            {
                int additionalObjIndex = 1;         // It Must start from 1 as the first parameter (if any) will always represent the obj. on which the method has to be invoked
                for (int i = 0; i < inParams.Length; i++)
                {
                    object ip = inParams[i];

                    if (ip == null)
                    {
                        if (additionalObjIndex >= objs.Length)
                            RouterUtils.ShowErrorMsgBox("Bad redirection detected!!", 3);
                        else
                        {
                            inParams[i] = objs[additionalObjIndex];
                            additionalObjIndex++;
                        }
                    }
                }

                if (method == null)
                    RouterUtils.ShowErrorMsgBox($"[*] Method not found!! You either wrote a bad forward or the involved method signature doesn't exist.\nQuitting...", 3);

                return method.Invoke(objs[0], inParams);
            }
        }

        /**
         * <summary>Add the input method to the maintained method cache</summary>
         * <param name="method">the input method instance</param>
         */
        static private void CacheMethod(in MethodBase method)
        {
            if (MethodsCache.Count() == TOT_METHODS_CACHED)
                MethodsCache.Clear();
            if (method != null)
                MethodsCache.Add(method);
        }

        /**
         * <summary>Returns true if debugging flag is set, otherwise it returns false.</summary>
         */
        static private bool IsDebugging()
        {
            if (DBG != 0 && DBG.GetType().ToString().Equals("System.Int32") && DBG == 1)
                return true;
            return false;
        }
    }
}
