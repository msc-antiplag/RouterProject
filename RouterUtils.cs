using Microsoft.Build.Construction;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace RouterProject
{
    class RouterUtils
    {
        private const string ILSpyCmd = "ilspycmd";
        public const string RouterClassName = "Router";
        public const string RouterFrwdMtd = "ForwardCall";

        public static RandomNumberGenerator rnd;

        /**
         * <summary>
         * Returns the corresponding hex string of provided input byte array
         * </summary>
         * <param name="ba"> the input byte array </param>
         * <returns> the corresponding hex string </returns>
         */
        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        /**
         * <summary>
         * Print the input matrix 
         * </summary>
         * <param name="matrix"> input matrix to be printed </param>
         * 
         */
        static public void PrintMatrix(ref int[,] matrix)
        {
            //Console.WriteLine($"[*] Printing {matrix.GetLength(0)} x {matrix.GetLength(1)}");
            for (int r = 0; r < matrix.GetLength(0); r++)
            {
                for (int c = 0; c < matrix.GetLength(1); c++)
                    Console.Write(matrix[r, c]);
                Console.WriteLine();
            }

            Console.WriteLine();
        }

        /**
         * <summary>
         * Creates a temporary folder
         * </summary>
         * <returns>
         * The absolute pathname of the created folder
         * </returns>
         */
        static public string GetTempFolder()
        {
            string tmpDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(tmpDir);

            return tmpDir;
        }

        /**
         * <summary>
         * Deletes every file and directory found under input pathname
         * </summary>
         * <param name="pathname"> input pathname </param>"
         */
        static public void CleanDirectory(string pathname)
        {
            DirectoryInfo di = new DirectoryInfo(pathname);

            foreach (FileInfo file in di.GetFiles())
                file.Delete();
            foreach (DirectoryInfo dir in di.GetDirectories())
                dir.Delete(true);
        }

        /**
         * <summary> Deletes the input folder</summary>
         * <param name="pathname"> folder to delete </param>"
         */
        static public void DeleteDirectory(string pathname)
        {
            CleanDirectory(pathname);
            Directory.Delete(pathname);
        }

        /**
         * <summary>Decompiles the running EXE inside the input folder.</summary>
         * <param name="dstFolder">Destination folder</param>"
         */
        static public void DecompileApp(string dstFolder)
        {
            CleanDirectory(dstFolder);                  // clean destination folder before decompiling

            string exeAbsPathname = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            string exeAbsDirectory = AppDomain.CurrentDomain.BaseDirectory;

            string dstAssembly = exeAbsPathname;
            
            // run ilspycmd
            System.Diagnostics.ProcessStartInfo start = new System.Diagnostics.ProcessStartInfo();
            start.FileName = ILSpyCmd;
            start.Arguments = $"-p -o {dstFolder} {dstAssembly}";
            start.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;                   //Hides GUI
            start.CreateNoWindow = true;                                                        //Hides console
            Process p = Process.Start(start);

            p.WaitForExit();                                                                    // wait it's finished
        }

        /**
         * <summary>Ensure the ilspycmd is installed</summary>
         * <returns>True if it is installed, false otherwise. </returns>
         */
        static public bool CheckDependencies()
        {
            bool res = false;
            try
            {
                Process pc = System.Diagnostics.Process.Start(ILSpyCmd);               // run ilspycmd 
                pc.WaitForExit();
                res = true;
            }
            catch (Win32Exception e)
            {
                RouterUtils.ShowErrorMsgBox("This software depends on the ilspycmd tool", 3);
            }

            return res;
        }

        /**
         * <summary>Print the input string and then each dictionary key/value pairs.</summary>
         * <param name="msg">msg to be printed</param>
         * <param name="inDict">Dictionary to be printed</param>
         */
        static public void PrintDictionary(string msg, ref Dictionary<Type, (string, string, string)> inDict)
        {
            Console.WriteLine(msg);
            foreach (KeyValuePair<Type, (string, string, string)> kv in inDict)
                Console.WriteLine(kv.Key.Name + "   " + kv.Value.Item1 + "   " + kv.Value.Item2 + "    " + kv.Value.Item3);
        }

        /**
         * <summary>Shows a MessageBox with custom error string and terminates running program with provided error code</summary>
         * <param name="msg">the message string to display</param>
         * <param name="errCode">the integer errCode to return</param>
         */
        static public void ShowErrorMsgBox(string msg, int errCode)
        {
            MessageBox.Show(msg, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Environment.Exit(errCode);
        }

        /**
         * <summary>Returns true if the input string is a valid base-64 encoded string, false is returned otherwise.</summary>
         * <param name="str">input string to evaluate</param>
         * 
         */
        static public bool IsBase64Str(string str)
        {
            try
            {
                Convert.FromBase64String(str);
                return true;
            }
            catch (Exception exception)
            {
                return false;
            }
        }

        /**
         * <summary>Removes every null key in input dictionary</summary>
         * <param name="inDict">input dictionary</param>
         */
        static public void RemoveNullKeys(ref Dictionary<Type, (string, string)> inDict)
        {
            Dictionary<Type, (string, string)> outDict = new Dictionary<Type, (string, string)>();

            foreach (KeyValuePair<Type, (string, string)> kv in inDict)
                if (kv.Key != null)
                    outDict[kv.Key] = inDict[kv.Key];

            inDict = new Dictionary<Type, (string, string)>(outDict);
        }

        /**
         * <summary>Given the matrix and ordered list of filenames it prints the dependencies in a readable format.</summary>
         * <param name="matrix">the adjacency matrix containing file dependencies</param>
         * <param name="orderedKeys">the ordered list of corresponding file names.</param>
         */
        static public void InterpretMatrix(ref int[,] matrix, List<string> orderedKeys)
        {
            bool noDependencies = true;
            int totDep = 0;

            for (int r = 0; r < matrix.GetLength(0); r++)
                for (int c = 0; c < matrix.GetLength(1); c++)
                    if (matrix[r, c] == 1)
                    {
                        noDependencies = false;
                        string rClass = orderedKeys[r];
                        string cClass = orderedKeys[c];

                        Console.WriteLine($"[*] Dependency: {rClass} --> {cClass} --- {r} --> {c}");
                        totDep++;
                    }
            
            if (noDependencies)
                Console.WriteLine("[*] No Dependencies found");
            else
                Console.WriteLine($"[*] Tot dependencies: {totDep}");

            Console.WriteLine();
        }

        /**
         * <summary>Return the n-th index of char t in string s, if any. Otherwise it returns -1.</summary>
         * <param name="s">input string</param>
         * <param name="t">character to look for</param>
         * <param name="n">the n-th occurrence you looking for</param>
         * <returns> the index of the n-th occurrence if any, -1 otherwise.</returns>
         */
        static public int GetNthIndex(string s, char t, int n)
        {
            int count = 0;
            for (int i = 0; i < s.Length; i++)
                if (s[i] == t)
                {
                    count++;
                    if (count == n)
                    {
                        return i;
                    }
                }
            return -1;
        }

        /**
         * <summary>Compute the SHA-256 hash sum and returns its corresponding array of bytes.</summary>
         * <param name="pathName">the input filename</param>
         * <returns>the byte array of the SHA-256 computed hashsum</returns>
         */
        static byte[] ComputeSHAhash(string pathName)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(pathName))
                {
                    return sha256.ComputeHash(stream);
                }
            }
        }

        /**
         * <summary>Given a filename index and the matrix, returns the list of all the nodes IDs from which it depends.  </summary>
         * <param name="pathnameIndex">the file index</param>
         * <param name="matrix">the adjacency matrix containing the file dependencies</param>
         * <returns>a list of IDs for each file the input file depends onto</returns>
         */
        static private List<int> GetDependencies(int pathnameIndex, ref int[,] matrix)
        {
            List<int> dependencies = new List<int>();
            for (int c = 0; c < matrix.GetLength(1); c++)
            {
                if (matrix[pathnameIndex, c] == 1)
                    dependencies.Add(c);
            }

            return dependencies;
        }

        /**
         * <summary>Return the byte array corresponding to the input Hex string</summary>
         * <param name="hexStr">input Hex string</param>
         * <returns>corresponding byte array</returns>
         */
        public static byte[] StringToByteArray(string hexStr)
        {
            return Enumerable.Range(0, hexStr.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hexStr.Substring(x, 2), 16))
                             .ToArray();
        }

        /**
         * <summary>Encodes an Object with Base64 encoding scheme</summary>
         * <param name="obj">input object instance</param>
         * <returns>its corresponding base-64 encoded string</returns>
         */
        static public string ObjectToString(object obj)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                new BinaryFormatter().Serialize(ms, obj);
                return Convert.ToBase64String(ms.ToArray());
            }
        }

        /**
         * <summary>Decode a Base64 encoded string to an Object (needs explicit cast once returned)</summary>
         * <param name="base64String">the input base-64 encoded string</param>
         * <returns>the corresponding Object instance</returns>
         */
        static public object StringToObject(string base64String)
        {
            byte[] bytes = Convert.FromBase64String(base64String);
            using (MemoryStream ms = new MemoryStream(bytes, 0, bytes.Length))
            {
                ms.Write(bytes, 0, bytes.Length);
                ms.Position = 0;
                return new BinaryFormatter().Deserialize(ms);
            }
        }

        /**
         * <summary>Compute the XOR between two byte arrays</summary>
         * <param name="hash1">first input byte array</param>
         * <param name="hash2">second input byte array</param>
         * <returns>a byte array containing the result of the computed XOR operation</returns>
         */
        static public byte[] XorByteArrays(byte[] hash1, byte[] hash2)
        {
            byte[] res = new byte[hash1.Length];

            for (int i = 0; i < res.Length; i++)
                res[i] = (byte)(hash1[i] ^ hash2[i]);

            return res;
        }

        /**
         * <summary>Check if the input file index has any remaining dependency with input nodes</summary>
         * <param name="matrix">adjacency matrix containing file dependencies</param>
         * <param name="r">the input filename index</param>
         * <param name="remaining">the nodes for which the method check if any dependency exists</param>
         * <returns>True if any dependency exists, otherwise it returns False.</returns>
         */
        static private bool HasRemainingDependencies(ref int[,] matrix, int r, List<int> remaining)
        {
            foreach (int c in remaining)
            {
                if (matrix[r, c] == 1)
                    return true;
            }

            return false;
        }

        /**
         * <summary>Retrieves any method signature corresponding a Router-forwarded method calls</summary>
         * <param name="classPathname">the input (decompiled) source file to inspect</param>"
         * <returns>a Set of strings containing method calls signatures</returns>
         */
        static private SortedSet<string> GetCalledMethods(string classPathname)
        {
            List<string> res = new List<string>();


            var fileTxt = File.ReadAllText(classPathname);


            SyntaxTree tree = CSharpSyntaxTree.ParseText(fileTxt);
            CompilationUnitSyntax root = tree.GetCompilationUnitRoot();


            SortedSet<string> calledMethods = new SortedSet<string>();

            foreach (SyntaxNode v in root.DescendantNodes())
            {
                string kind = v.Kind().ToString();
                string text = v.GetText().ToString();

                if (kind.Equals("InvocationExpression") && (text.Contains(RouterFrwdMtd)) /*!kind.Equals("IdentifierName")*/)
                {
                    var txt = text.Trim();
                    calledMethods.Add(txt);
                }
            }

            return calledMethods;
        }

        /**
         * <summary>Returns a List of tuples (className, classAbsPathname)</summary>
         * <param name="absPathname">the source pathname used to find class declarations</param>
         * <returns>a List of tuples (className, classAbsPathname)</returns>
         */
        static public List<(string, string)> GetClassDeclarations(string absPathname)
        {
            string text = File.ReadAllText(absPathname);

            SyntaxTree tree = CSharpSyntaxTree.ParseText(text);
            CompilationUnitSyntax root = tree.GetCompilationUnitRoot();


            // The list contains a tuple (string, string, string) representing 
            // - class name declared (note: not the full name!!)
            // - the absolute pathname of the file the class declaration was found within
            // - it's relative pathname (i.e. excluding the decompiledDstFolder
            List<(string, string)> res = new List<(string, string)>();
            foreach (SyntaxNode v in root.DescendantNodes())
            {
                string kind = v.Kind().ToString();
                string txt = v.GetText().ToString();

                if (kind.Equals("ClassDeclaration") || kind.Equals("ClassDeclarationSyntax"))
                {
                    string className = ((ClassDeclarationSyntax)v).Identifier.ToString();
                    res.Add((className, absPathname));
                }
            }

            return res;
        }

        /**
         * <summary>Retrieve the list of classes for each running project</summary>
         * <param name="projectNames">the running project names</param>
         * <returns>a Dictionary<string, List<Type>> such that each project name is a key, each value the List of classes retrieved through Reflection</Type></returns>
         */
        static public Dictionary<string, List<Type>> GetProjectsClasses(List<string> projectNames)
        {
            // initialize empty List for each Dictionary key
            Dictionary<string, List<Type>> result = new Dictionary<string, List<Type>>();
            projectNames.ForEach(pName => result[pName] = new List<Type>());

            foreach (string pName in projectNames)
            {
                List<Assembly> assemblies = new List<Assembly>();
                string assemblyFolder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

                foreach (var path in Directory.GetFiles(assemblyFolder, "*.exe"))
                    assemblies.Add(Assembly.LoadFrom(path));


                foreach (Assembly exeAsm in assemblies)
                {
                    // ignore non-class Type(s)
                    List<Type> classes = (from cal in exeAsm.GetTypes() where cal.IsClass select cal).ToList();

                    // ignore compiler generated display classes
                    classes = classes.Where(x => !(x.FullName.Contains("+") || x.FullName.Contains("<") || x.FullName.Contains(">") || x.FullName.Contains("`"))).ToList();

                    // Add class to corresponding project key 
                    foreach (Type clss in classes)
                        if (clss.FullName.StartsWith(pName + ".") /*&& !clss.FullName.Contains("Delegates.")*/ )
                            result[pName].Add(clss);
                }
            }

            return result;
        }

        /**
         * <summary>Computes the Topological sort</summary>
         * <param name="matrix">adjacency matrix representing file dependencies</param>
         * <returns>A List of IDs representing the computed topological sort</returns>
         */
        static public List<int> GetTopologicalSort(ref int[,] matrix)
        {
            // resulting topological sort of vertices
            List<int> topOrder = new List<int>();

            // initially, every vertex has to be ordered
            List<int> remaining = Enumerable.Range(0, matrix.GetLength(0)).ToList();

            do
            {
                int ordered = -1;

                foreach (int r in remaining)
                {
                    // check if r has any dependency, considering only the non-ordered nodes
                    if (!HasRemainingDependencies(ref matrix, r, remaining))    
                    {
                        ordered = r;
                        break;
                    }
                }

                remaining.Remove(ordered);
                topOrder.Add(ordered);

            } while (remaining.Count > 0);             // repeat until there are elements to be ordered


            return topOrder;
        }

        static public Assembly LoadKeePassLibAsm(string ExePath)
        {
            Assembly res = Assembly.LoadFile(ExePath);

            return res;
        }

        /**
         * <summary>Retrieve all the methods for a given class, including constructors</summary>
         * <param name="className">the input Type</param>
         * <returns>a List<MethodInfo> for each method found</returns>
         */
        static public List<MethodBase> GetClassMethods(Type className)
        {
            if (className == null)
                RouterUtils.ShowErrorMsgBox("CLASSNAME IS NULL", 30);
            else if (className.GetMethods() == null)
                RouterUtils.ShowErrorMsgBox("METHODS IS NULL", 30);

            List<MethodBase> methodsList = className.GetMethods().ToList().Cast<MethodBase>().ToList();
            methodsList.AddRange(className.GetConstructors().ToList().Cast<MethodBase>().ToList());             // add Constructors too
            methodsList.AddRange(className.GetMethods(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Static));         // add non-public methods too

            List<MethodBase> resList = new List<MethodBase>(methodsList.Count);

            foreach (MethodBase mi in methodsList)
            {
                string classFullName = className.FullName;
                string declaringType = mi.DeclaringType.ToString();
                string methodName = mi.Name;

                if (declaringType.Equals(classFullName) && (!(methodName.Equals("Equals") || methodName.Equals("GetHashCode") || methodName.Equals("GetType") || methodName.Equals("ToString"))))
                    resList.Add(mi);                // add method to the list
            }

            return resList;
        }

        /**
         * <summary>Sort the input Dictionary by the relative pathname (i.e. dict[key].Item2)</summary>
         * <param name="inDict">the input dictionary</param>
         * <returns>the same dictionary ordered by relative pathname</returns>
         */
        static public Dictionary<Type, (string, string)> SortByRelativePathname(Dictionary<Type, (string, string)> inDict)
        {
            Dictionary<Type, (string, string)> sortedDict = new Dictionary<Type, (string, string)>();

            var items = from key in inDict.Keys orderby inDict[key].Item2 ascending select key;

            foreach (Type key in items)
                sortedDict[key] = inDict[key];

            return new Dictionary<Type, (string, string)>(sortedDict);
        }

        /**
         * <summary>Returns all the projects composing the solution (.sln)</summary>
         * <returns>a ReadOnlyList of ProjectInSolution objects</returns>
         */
        public static IReadOnlyList<ProjectInSolution> GetProjects()
        {
            string currProjName = Assembly.GetEntryAssembly().GetName().Name;

            string slnAbsPath = String.Format("{0}\\\\{1}", Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName, currProjName + ".sln");
            var solutionFile = SolutionFile.Parse(slnAbsPath);
            var projects = solutionFile.ProjectsInOrder;
            var projectNames = solutionFile.ProjectsInOrder.Select(p => p.ProjectName).ToList();

            return projects;
        }

        /**
         * <summary>Retrieves a List of sorted relative filenames</summary>
         * <param name="inDict">the input dictionary</param>
         * <returns>the ordered List of relative filenames</returns>
         */
        static public List<string> GetSortedFilenames(ref Dictionary<Type, (string, string)> inDict)
        {
            List<string> sortedFnames = new List<string>();

            var myList = inDict.ToList();
            myList.Sort((pair1, pair2) => pair1.Value.Item2.CompareTo(pair2.Value.Item2));

            foreach (var v in myList)
                sortedFnames.Add(v.Value.Item2);

            return sortedFnames;
        }

        /**
         * <summary>Identify dependencies between source files by looking for specific Router calls. </summary>
         * <param name="relPathnames">relative pathnames</param>
         * <param name="matrix">adjacency matrix</param>
         * <param name="classesDict">input dictionary containing classes info</param>
         * <param name="decompiledDstFolder">the decompilation dest. folder</param>
         */
        static public void FindDependencies(in List<string> relPathnames, ref int[,] matrix, in Dictionary<Type, (string, string)> classesDict, string decompiledDstFolder)
        {
            string rcStart = $"{RouterClassName}.{RouterFrwdMtd}(";

            foreach (string relPathname in relPathnames)
            {
                // retrieve each Router.ForwardCall(...) invocation expression string
                SortedSet<string> routerCalls = GetCalledMethods(decompiledDstFolder + relPathname);

                // foreach such Router call string
                foreach (var rc in routerCalls)
                {
                    // parse the method name
                    string sub1 = rc.Substring(rc.IndexOf(rcStart));
                    string sub2 = sub1.Substring(0, RouterUtils.GetNthIndex(sub1, ')', 1) +1);
                    string methodName = sub2.Split('-')[1].Trim().Replace("\"", "").Replace(")", "");     //.Split('-')[0];


                    // parse classname
                    string classname = sub2.Split('-')[0].Trim();
                    int i = classname.Length - 1;
                    for( ; i>0; i--)
                        if (classname[i] == '.')
                            break;
                    classname = classname.Substring(i + 1);

                    // Console.WriteLine($"Parsed classname is '{classname} -- Parsed method is '{methodName}'");
                    
                    bool found = false;
                    foreach (Type t in classesDict.Keys) { 
                        foreach (MethodBase method in GetClassMethods(t)) 
                            if (methodName.Equals(method.Name) && t.FullName.EndsWith(classname)) {

                                matrix[relPathnames.IndexOf(relPathname), relPathnames.IndexOf(classesDict[t].Item2)] = 1;
                                found = true;
                                break;
                            }

                        if (found)  break;
                        }
                    // If not found yet, then look for Constructors
                    if (!found)
                        foreach (Type t in classesDict.Keys)
                        {
                            foreach (MethodBase method in GetClassMethods(t))
                                if (method.IsConstructor && t.FullName.EndsWith(methodName))        // Constructor same name of the class
                                {
                                    matrix[relPathnames.IndexOf(relPathname), relPathnames.IndexOf(classesDict[t].Item2)] = 1;
                                    found = true;
                                    break;
                                }

                            if (found) break;
                        }
                }
            }
        }

        /**
         * <summary>Retrieve the name of the class that called the caller of such method.</summary>
         * <returns>the name of the calling class</returns>
         */
        static public string NameOfCallingClass()
        {
            /*string fullName;
            Type declaringType;
            int skipFrames = 2;
            do
            {
                MethodBase method = new StackFrame(skipFrames, false).GetMethod();
                declaringType = method.DeclaringType;
                if (declaringType == null)
                    return method.Name;
                
                skipFrames++;
                fullName = declaringType.FullName;
            }
            while (declaringType.Module.Name.Equals("mscorlib.dll", StringComparison.OrdinalIgnoreCase));

            return fullName;*/

            return new StackFrame(2, false).GetMethod().ReflectedType.Name;

        }

        /**
         * <summary>Returns the first 16 bytes of the input array</summary>
         * <returns>first a 16 bytes long array</returns>
         */
        static public byte[] First16Bytes(byte[] inBytes)
        {
            byte[] iv = new byte[16];
            for (int i = 0; i < 16; i++)
                iv[i] = inBytes[i];

            return iv;
        }

        /**
         * <summary>Encrypt the input ASCII string using AES-256 encryption scheme.</summary>
         * <param name="plainText">the plaintext ASCII string to encrypt</param>
         * <param name="Key">the 32-bytes encryption key</param>
         * <param name="IV">the 16-bytes initialization vector</param>
         * <returns>a byte array containing the ciphertext</returns>
         */
        static public byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        /**
         * <summary>Decrypt the input byte array using AES-256 encryption scheme.</summary>
         * <param name="cipherText">the ciphertext to decrypt</param>
         * <param name="Key">the 32-bytes enc/dec key</param>
         * <param name="IV16">the 16-bytes initialization vector</param>
         * <returns>a byte array containing the ciphertext</returns>
         */
        static public string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV16)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV16 == null || IV16.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV16;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            try
                            {
                                plaintext = srDecrypt.ReadToEnd();
                            }
                            catch (CryptographicException e)
                            {
                                RouterUtils.ShowErrorMsgBox("Plagiarism Attempt Detected.\nQuitting..", 8);
                            }
                        }
                    }
                }
            }

            return plaintext;
        }

        /**
         * <summary>Computes the solved hashes for each file</summary>
         * <param name="topSortedList">the topological sort of vertices</param>
         * <param name="sortedFilenames">the List of sorted filenames</param>
         * <param name="matrix">the matrix containing dependencies info</param>
         * <param name="decompiledDstFolder">the destination folder where decompiled code was stored</param>
         * <param name="solvedHashes">a dictionary<int, string> for saving the computed solved hashes</param>
         */
        static public void ComputeSolvedHashes(List<int> topSortedList, List<string> sortedFilenames, ref int[,] matrix, string decompiledDstFolder, ref Dictionary<int, string> solvedHashes)
        {
            foreach (int pathnameIndex in topSortedList)
            {
                if (!solvedHashes.ContainsKey(pathnameIndex))
                {
                    byte[] currentHash = ComputeSHAhash(decompiledDstFolder + sortedFilenames[pathnameIndex]);

                    List<int> dependencies = GetDependencies(pathnameIndex, ref matrix);
                    if (dependencies.Count != 0)
                        foreach (int depIndex in dependencies) {
                            /*if (pathnameIndex == 215)
                            {
                                if(GetDependencies(depIndex, ref matrix).Count == 0)
                                    Console.WriteLine($"[*] Xoring with dep {depIndex}  which is {sortedFilenames[depIndex]} = {ByteArrayToString(Convert.FromBase64String(solvedHashes[depIndex]))}  --- exact hash");
                                else
                                    Console.WriteLine($"[*] Xoring with dep {depIndex}  which is {sortedFilenames[depIndex]} = {ByteArrayToString(Convert.FromBase64String(solvedHashes[depIndex]))}  --- solved hash");
                            }*/

                            currentHash = XorByteArrays(currentHash, Convert.FromBase64String(solvedHashes[depIndex]));
                        }

                    solvedHashes[pathnameIndex] = Convert.ToBase64String(currentHash);
                }
            }
            Console.WriteLine($"[*] {solvedHashes.Keys.Count} solved hashes computed successfully");
        }

        /**
         * <summary>Computes the solved hash for the input pathname index.</summary>
         * <param name="targetPathIndex">the index corresponding to the pathname you are computing the solved hash</param>
         * <param name="topSortedList">the topological sort of vertices</param>
         * <param name="sortedFilenames">the sorted List of filenames</param>
         * <param name="matrix">adjacency matrix having file dependencies</param>
         * <param name="decompileDstFolder">the destination folder to store decompiled code</param>
         * <returns>the base-64 encoded string representing the solved hash.</returns>
         */
        static public string ComputeSingleHash(int targetPathIndex, List<int> topSortedList, List<string> sortedFilenames, ref int[,] matrix, string decompileDstFolder)
        {
            Dictionary<int, string> resDict = new Dictionary<int, string>();

            foreach (int pathnameIndex in topSortedList)
            {
                byte[] currentHash = ComputeSHAhash(decompileDstFolder + @"\" + sortedFilenames[pathnameIndex]);

                List<int> dependencies = GetDependencies(pathnameIndex, ref matrix);
                
                if (dependencies.Count != 0)
                    foreach (int dep in dependencies)
                        currentHash = XorByteArrays(currentHash, Convert.FromBase64String(resDict[dep]));

                // convert to Base64
                resDict[pathnameIndex] = Convert.ToBase64String(currentHash);
                
                if (targetPathIndex == pathnameIndex)
                    return resDict[targetPathIndex];
            }

            return null;
        }

        /**
         * <summary>Remove any cycle in the graph represented by the input adjacency matrix, considering vertices always in the same order (i.e. a deterministic computation)</summary>
         * <param name="matrix">the adjacency matrix</param>
         * <param name="nodesIDs">a List with containing nodes IDs</param>
         */
        static public void BreakAnyCycle(ref int[,] matrix, in List<int> nodesIDs)
        {
            List<List<int>> cycles = new List<List<int>>();
            foreach (int node in nodesIDs)
                DFSbreak(new List<int>(), node, ref matrix, ref cycles);
        }

        /**
         * <summary>subroutine used to remove any cycle from input graph</summary>
         */
        static public void DFSbreak(List<int> visitedNodes, int currNode, ref int[,] matrix, ref List<List<int>> cycles)
        {
            visitedNodes.Add(currNode);
            for (int c = 0; c < matrix.GetLength(1); c++)
            {
                if (matrix[currNode, c] == 1)        // found edge currNode --> c
                {
                    if (visitedNodes.Contains(c))       // this edge is a back-edge, therefore lead to a cycle
                        //Console.WriteLine($"edge {currNode} --> {c} lead to a cycle");
                        matrix[currNode, c] = 0;
                    else
                        DFSbreak(new List<int>(visitedNodes), c, ref matrix, ref cycles);
                }
            }
        }

        /**
         * <summary>Compute the encryption key at run-time</summary>
         * <param name="topSortedList"> the topological sort of vertices</param>
         * <param name="sortedFilenames">the List of sorted filenames</param>
         * <param name="matrix">adjacency matrix containing file dependencies info</param>
         * <param name="precomputedHashes">the hash computed during the init() step</param>
         * <param name="decompiledDstFolder">the folder where decompiled code was stored</param>
         * <returns>the base-64 string corresponding to the computed encryption key</returns>
         */
        static public string GetEncryptionKey(in List<int> topSortedList, in List<string> sortedFilenames, ref int[,] matrix, ref Dictionary<int, string> precomputedHashes, string decompiledDstFolder)
        {
            byte[] encryptionKey = null;

            foreach (int index in topSortedList)
                if (GetDependencies(index, ref matrix).Count == 0)
                {
                    byte[] currHash = ComputeSHAhash(decompiledDstFolder + sortedFilenames[index]);

                    precomputedHashes[index] = Convert.ToBase64String(currHash);

                    if (encryptionKey == null)
                        encryptionKey = currHash;
                    else
                        encryptionKey = XorByteArrays(encryptionKey, currHash);
                }

            return Convert.ToBase64String(encryptionKey);
        }

        /**
         * <summary>Encrypt every method call made through the Router in corresponding source files</summary>
         * <param name="dstFolder">decompiled code destination folder</param>
         * <param name="matrix">the adjacency matrix containing file dependencies</param>
         * <param name="SortedFnames">the List of sorted filenames</param>
         * <param name="EncryptionKey">the base-64 encoded 32-bytes encryption key</param>
         * <param name="IVs">the array containing all the IVs</param>
         */
        static public void EncryptRouterCalls(ref int[,] matrix, string dstFolder, List<string> SortedFnames, string EncryptionKey, List<byte[]> IVs)
        {
            string iv16 = Convert.ToBase64String(IVs[0]);
            Dictionary<int, int> seen = new Dictionary<int, int>();

            for (int r = 0; r < matrix.GetLength(0); r++)
                for (int c = 0; c < matrix.GetLength(1); c++)
                    if (matrix[r, c] == 1)
                    {
                        if (!seen.Keys.Contains(r))
                        {
                            int i = IndexInMatrix(SortedFnames[r], SortedFnames, ref matrix);
                            if (i == -1)
                                ShowErrorMsgBox($"Error: negative index for r={r} which is SortedFnames[r]", 30);

                            seen[r] = i;
                        }
                    }

            int index;
            foreach(int r in seen.Keys)
            {
                index = seen[r];

                string absPathname = dstFolder + SortedFnames[r];
                string fileTxt = File.ReadAllText(absPathname);


                SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(fileTxt);

                //Console.WriteLine($"Encrypting {absPathname} \nivIndex: {index}  --- {Convert.ToBase64String(IVs[index])}");
                string xoredKey = Convert.ToBase64String(XorByteArrays(Convert.FromBase64String(EncryptionKey), IVs[index]));       // compute the XOR with the unique IV generated for this file only

                SyntaxRewriter renameRouterCalls = new SyntaxRewriter(xoredKey, iv16);          // instantiates an object of a custom SyntaxRewriter, which just encrypts router calls info
                                                                                                // when the correspondig node is visited                                     
                
                SyntaxNode syntaxNode = renameRouterCalls.Visit(syntaxTree.GetRoot());          // encrypts syntax nodes 
                File.WriteAllText(absPathname, syntaxNode.ToFullString());                      // overwrites the modified source file
            }
        }

        /**
         * <summary>Return a dictionary with values (className, decompiledCorrespondentFname) given the input class names</summary>
         * <param name="projectClasses">dictionary containing string classname values indexed by project name</param>
         * <param name="decompiledDstFolder">folder where decompiled code was stored</param>
         * <returns>a similar dictionary with Type objects as keys and tuples (className, classSourceFile) as corresponding values</returns>
         */
        static public Dictionary<Type, (string, string)> GetDecompiledCorrespondence(Dictionary<string, List<Type>> projectClasses, string decompiledDstFolder)
        {
            Dictionary<Type, (string, string)> resDict = new Dictionary<Type, (string, string)>();

            foreach (string projectKey in projectClasses.Keys)
            {
                string decompProjDir = decompiledDstFolder + @"\" + projectKey + @"\";

                TraverseTree(decompProjDir, projectKey, decompiledDstFolder, ref projectClasses, ref resDict);
            }

            return resDict;
        }

        /**
         * <summary>Traverse the input pathname and for each C# source file (.cs) found check if it contains any input class declaration.</summary>
         * <param name="root">input pathname</param>
         * <param name="projectKey">project name</param>
         * <param name="decompiledDstFolder">decompiled code folder</param>
         * <param name="projectClasses">all the input classes, stored as a dictionary indexed by project name strings</param>
         * <param name="outDict">the modified output dictionary</param>
         */
        public static void TraverseTree(string root, string projectKey, string decompiledDstFolder, ref Dictionary<string, List<Type>> projectClasses, ref Dictionary<Type, (string, string)> outDict)
        {
            // Data structure to hold names of subfolders to be
            // examined for files.
            Stack<string> dirs = new Stack<string>(20);

            if (!System.IO.Directory.Exists(root))
            {
                throw new ArgumentException();
            }
            dirs.Push(root);

            while (dirs.Count > 0)
            {
                string currentDir = dirs.Pop();
                string[] subDirs;
                try
                {
                    subDirs = System.IO.Directory.GetDirectories(currentDir);
                }
                // An UnauthorizedAccessException exception will be thrown if we do not have
                // discovery permission on a folder or file. It may or may not be acceptable
                // to ignore the exception and continue enumerating the remaining files and
                // folders. It is also possible (but unlikely) that a DirectoryNotFound exception
                // will be raised. This will happen if currentDir has been deleted by
                // another application or thread after our call to Directory.Exists. The
                // choice of which exceptions to catch depends entirely on the specific task
                // you are intending to perform and also on how much you know with certainty
                // about the systems on which this code will run.
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e.Message);
                    continue;
                }
                catch (System.IO.DirectoryNotFoundException e)
                {
                    Console.WriteLine(e.Message);
                    continue;
                }

                string[] files = null;
                try
                {
                    files = System.IO.Directory.GetFiles(currentDir);
                } 
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine(e.Message); continue;
                }
                catch (System.IO.DirectoryNotFoundException e)
                {
                    Console.WriteLine(e.Message); continue;
                }

                // Perform the required action on each file here.
                // Modify this block to perform your required task.
                foreach (string absFname in files)
                {
                    try
                    {
                        // Perform whatever action is required in your scenario.
                        if (absFname.EndsWith(".cs"))
                        {
                            // Retrieve declared classes
                            List<(string, string)> declaredClasses = GetClassDeclarations(absFname);

                            // foreach identified Class Declaration
                            foreach ((string, string) val in declaredClasses)
                            {
                                // foreach known Class (found through Reflection) in the current project
                                foreach (Type clss2 in projectClasses[projectKey])
                                {
                                    if (clss2.FullName.EndsWith("." + val.Item1))
                                    {
                                        if (clss2 == null || clss2.FullName == null || val.Item1 == null || val.Item2 == null)
                                        {
                                            Console.WriteLine($"[*] Tot is {outDict.Keys.Count}");
                                            Console.WriteLine(clss2);
                                            System.Environment.Exit(3);
                                        }
                                        if (clss2 != null)
                                            outDict[clss2] = (clss2.FullName, val.Item2.Replace(decompiledDstFolder, ""));
                                    }
                                }
                            }
                        }
                    }
                    catch (System.IO.FileNotFoundException e)
                    {
                        // If file was deleted by a separate application or thread
                        // since the call to TraverseTree() then just continue.
                        Console.WriteLine(e.Message);
                        continue;
                    }
                }

                // Push the subdirectories onto the stack for traversal.
                // This could also be done before handing the files.
                foreach (string str in subDirs)
                    dirs.Push(str);
            }

        }

        /**
         * <summary>Generate a random IV of specified input bytes</summary>
         * <param name="bytes">IV size in bytes</param>
         * <returns>A random byte array of specified input bytes</returns>
         */
        private static byte[] GetRandomIV(int bytes)
        {
            if (rnd == null)
                rnd = RandomNumberGenerator.Create();

            byte[] iv = new byte[bytes];        // define an empty array of specified bytes
            rnd.GetBytes(iv);

            return iv;
        }

        /**
         * <summary>Concatenates provided byte arrays</summary>
         * <param name="arrays">Array of byte arrays to concatenate</param>
         * <returns>the result of concatenated input byte arrays</returns>
         */
        private static byte[] CombineByteArrays(params byte[][] arrays)
        {
            byte[] ret = new byte[arrays.Sum(x => x.Length)];
            int offset = 0;
            foreach (byte[] data in arrays)
            {
                Buffer.BlockCopy(data, 0, ret, offset, data.Length);
                offset += data.Length;
            }
            return ret;
        }

        /**
         * <summary>Compute an IV for each source file with at least one dependency</summary>
         * <param name="matrix">adjacency matrix containing depdendencies informatoin</param>
         * <param name="sortedFilenames">the list of sorted filenames</param>
         * <param name="dstFolder">the folder where the app was decompiled</param>
         * <returns>A List of byte arrays for each source file that has to be encrypted</returns>
         */
        public static List<byte[]> ComputeIVs(ref int[,] matrix, List<String> sortedFilenames, string dstFolder, byte[] EncKey)
        {
            List<byte[]> res = new List<byte[]>();
            res.Add(GetRandomIV(16));                       // generate the 16-bytes IV used to encrypt source files info

            List<int> seen = new List<int>();

            for (int r = 0; r < matrix.GetLength(0); r++)
                for (int c = 0; c < matrix.GetLength(1); c++)
                    if(matrix[r, c] == 1) {
                        if (!seen.Contains(r)) {
                            byte[] iv32 = GetRandomIV(32);
                            //Console.WriteLine($"[*] IV_index for {sortedFilenames[r]} is {res.Count}  that is {Convert.ToBase64String(iv32)}");
                            //Console.WriteLine($"[*] IV xor Key is {Convert.ToBase64String(XorByteArrays(EncKey, iv32))}");
                            seen.Add(r);
                            res.Add(iv32);           // this is the 32-bytes IV which will be XOR-ed with the runtime computed encryption key -- preventing known-cyphertext attacks
                        }
                    }

            Console.WriteLine($"[*] {res.Count} IVs computed successfully");
            return res;
        }

        /**
         * <summary>Checks whether the input method correspond to the parameters retrieved by decrypting the encrypted info about calls to Router</summary>
         * <param name="mtd">the input method, a MethodBase instance</param>
         * <param name="methodName">parsed method name</param>
         * <param name="dstClassStr">parsed destination classname</param>
         * <param name="parameters">parsed input string parameters</param>
         * <param name="args">the array containing the initial forward call arguments, each location a different kind of argument</param>
         * <returns>true if provided info matches the input method, otherwise it returns false</returns>
         */
        static public bool MatchMethod(MethodBase mtd, string methodName, string dstClassStr, string[] parameters, string[] args)
        {
            if (mtd.Name.Equals(methodName) && mtd.DeclaringType.ToString().Equals(dstClassStr) && ((mtd.GetParameters().Length == 0 && parameters[0].Equals("null")) || mtd.GetParameters().Length == args[3].Split(',').Length))
                return true;

            return false;
        }

        /**
         * <summary>Parses the portion of router call info regarding the parameter values</summary>
         * <param name="paramsStr">the hyphen separated list of parameter values</param>
         * <param name="paramsType">the list of corresponding Type objects regarding input parameters</param>
         * <param name="objs">the optional array of arbitrary objects which cannot be encrypted at compile-time, yet they can be passed to forwarded method calls</param>
         * <returns>the corresponding list of Object instances corresponding to the input string</returns>
         */
        static public object[] ParseParamsValues(string paramsStr, Type[] paramsType, params object[] objs)
        {
            Console.WriteLine("parsing params values...");
            object[] res = new object[0];
            string[] tmp = paramsStr.Split(',');

            string[] parameters = new string[tmp.Length];
            for (int i = 0; i < tmp.Length; i++)
                parameters[i] = tmp[i].Replace("_", "-");

            if (!paramsStr.Equals("null"))
            {
                int l = parameters.Length;
                if (objs.Length > 1)
                    l += objs.Length - 1;

                res = new object[l];

                int i;
                for (i = 0; i < parameters.Length; i++)
                {
                    if (parameters[i].Equals("{}"))
                    {
                        res[i] = null;
                        continue;
                    }

                    res[i] = Convert.ChangeType(parameters[i], paramsType[i]);

                    if (res[i] == null)
                    {
                        System.Environment.Exit(3);
                    }
                }

                for (int j = 1; j < objs.Length; j++)
                {
                    res[i++] = objs[j];
                }
            }

            return res;
        }

        /**
         * <summary>Parses the portion of router call info regarding the types of input parameters</summary>
         * <param name="paramsTypeStr">the hyphen separated list of parameter types</param>
         * <returns>the corresponding list of Type instances corresponding to the input string</returns>
         */
        static public Type[] ParseParamsType(string paramsTypeStr)
        {
            Type[] res = new Type[0];
            string[] types = paramsTypeStr.Split(',');

            if (!paramsTypeStr.Equals("null"))
            {
                res = new Type[types.Length];

                for (int i = 0; i < types.Length; i++)
                {
                    string str = types[i];
                    Type strType = GetTypeFromStr(str);

                    res[i] = strType;
                }
            }

            return res;
        }

        /**
         * <summary>Retrieve a Type instance from a class name string</summary>
         * <param name="dstClassStr">the string containing class name</param>
         * <returns>An instance of Type corresponding to the input string. If no correspondece is found then it returns null.</returns>
         */
        static public Type GetTypeFromStr(string dstClassStr)
        {
            Type dstClass = null;
            foreach (Assembly ass in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (ass.FullName.StartsWith("System."))
                    continue;
                dstClass = ass.GetType(dstClassStr);
                if (dstClass != null)
                    break;
            }

            return dstClass;
        }

        /**
         * <summary>Retrieves the corresponding IV index in IVs array given the calling class name</summary>
         * <param name="classFullName">the class full name</param>
         * <param name="sortedFnames">the list of sorted filenames</param>
         * <param name="matrix">the adjacency matrix representing the file dependency graph</param>
         * <returns>the IV index corresponding to the input classname</returns>
         */
        public static int IndexInMatrix(string classFullName, List<string> sortedFnames, ref int[,] matrix)
        {
            int res = -1;
            int ivCount = 1;
            Dictionary<int, int> seen = new Dictionary<int, int>();
            for (int r = 0; r < matrix.GetLength(0); r++)
                for (int c = 0; c < matrix.GetLength(1); c++)
                    if (matrix[r, c] == 1)
                    {
                        if (!seen.Keys.Contains(r)) {
                            seen[r] = ivCount;

                            if (!classFullName.EndsWith(".cs")) {                   // if it is a class fullname
                                string fname = sortedFnames[r].Replace(".cs", "");

                                string[] tmp = classFullName.Split('.');
                                string className = tmp[tmp.Length - 1].Trim();

                                if (fname.EndsWith(className))
                                    return ivCount;
                            }
                            else
                            {                                                  // if it is a pathname
                                string fname = sortedFnames[r];
                                if (fname.EndsWith(classFullName))
                                    return ivCount;
                            }

                            ivCount++;
                        }
                    }
            return res;
        }
    }


    public class SyntaxRewriter : CSharpSyntaxRewriter
    {
        readonly string key;
        readonly string IV;

        public SyntaxRewriter(string key, string IV)
        {
            this.key = key;
            this.IV = RouterUtils.ByteArrayToString(Convert.FromBase64String(IV));
        }
        
        private int GetNthGreaterThan(int val, string s, char t, int n) {
            while (true)
            {
                int index = RouterUtils.GetNthIndex(s, t, n);
                if (index > val)
                    return index;
                else if (index == -1)
                    return -1;

                n++;
            }
        } 

        public override SyntaxNode VisitInvocationExpression(InvocationExpressionSyntax node)
        {
            SyntaxNode syntaxNode = null;
            string nodeTxt = node.GetText().ToString().Trim();
            string reference = $"{RouterUtils.RouterClassName}.{RouterUtils.RouterFrwdMtd}";

            if (nodeTxt.Contains(RouterUtils.RouterFrwdMtd))
            {
                int refStartIndex = nodeTxt.IndexOf(reference);

                int startStringParam = GetNthGreaterThan(refStartIndex, nodeTxt, '"', 1);
                int endStringParam = GetNthGreaterThan(refStartIndex, nodeTxt, '"', 2);
                string plaintext = nodeTxt.Substring(startStringParam, endStringParam - startStringParam + 1);

                string remaining = nodeTxt.Substring(endStringParam + 1, nodeTxt.Length - endStringParam - 1);


                byte[] encryptedBytes = RouterUtils.EncryptStringToBytes(plaintext, Convert.FromBase64String(key), RouterUtils.First16Bytes(RouterUtils.StringToByteArray(IV)));
                string encryptedStrParam = Convert.ToBase64String(encryptedBytes);

                string newArgs = $"\"{encryptedStrParam}\"";
                newArgs += remaining.Remove(remaining.Length - 1);

                if (!nodeTxt.StartsWith(reference))
                {
                    int i = RouterUtils.GetNthIndex(nodeTxt, '(', 1);
                    string s = nodeTxt.Substring(i, startStringParam - i);
                    newArgs = s + newArgs;
                }

                syntaxNode = SyntaxFactory.InvocationExpression(node.Expression).WithArgumentList(SyntaxFactory.ParseArgumentList($"({newArgs})"));
                
            }
            else            // otherwise just don't modify the node
                syntaxNode = node;

            return syntaxNode;
        }
    }
}
