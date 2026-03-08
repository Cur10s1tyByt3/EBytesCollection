using System;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace CrossAssemblyExec
{
    internal class Program
    {
        static bool DetectReflectionLazy()
        {
            return Assembly.GetExecutingAssembly().Location.Length == 0;
        }

        static byte[] GetExecutingAssemblyBytes()
        {
            var executingAssembly = Assembly.GetExecutingAssembly();
            var fnGetRawBytes     = executingAssembly.GetType().GetMethod("GetRawBytes", BindingFlags.Instance | BindingFlags.NonPublic);
            return (byte[])fnGetRawBytes.Invoke(executingAssembly, null);
        }

        static void TargetFunction()
        {
            Console.WriteLine("> TargetFunction reached");
        }

        static void Main(string[] args)
        {
            if (DetectReflectionLazy())
            {
                Console.WriteLine("\n> Assembly entry point reached");

                object[] argsObjectArray  = args;
                Action   fnTargetFunction = (Action)argsObjectArray[0];
                fnTargetFunction();
                return;
            }
            
            byte[] assemblyBytes = GetExecutingAssemblyBytes();
            Console.WriteLine("> Fetched bytes from executing assembly (size: {0})", assemblyBytes.Length);

            Assembly asm = Assembly.Load(assemblyBytes);
            Console.WriteLine("> Loaded assembly bytes via reflection");

            string[] argsToPass = new string[1];
            Unsafe.As<string, object>(ref argsToPass[0]) = (Action)TargetFunction;

            Console.WriteLine("> Invoking assembly...");
            asm.EntryPoint.Invoke(null, new object[] { argsToPass });
        }
    }
}