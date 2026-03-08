using System;
using System.Reflection;

namespace Shillcode
{
    internal class Program
    {
        static void Main(string[] args)
        {
            ShillcodeContext dynAsm = new ShillcodeContext("DynamicAssembly");
            ModuleContext    dynMod = dynAsm.StartModuleDefinition("MainModule");

            // 17 | ldc.i4.1
            // 2A | ret
            dynMod.AddMethodToModule(
                "RetTrueStatic",
                new byte[] { 0x17, 0x2A },
                MethodAttributes.Public | MethodAttributes.Static,
                typeof(bool),
                Type.EmptyTypes
            );
            dynMod.AddMethodToModule(
                "RetTrue",
                new byte[] { 0x17, 0x2A },
                MethodAttributes.Public,
                typeof(bool),
                Type.EmptyTypes
            );
            dynMod.EndModuleDefinition();

            MethodInfo RetTrueStatic = dynMod.GetMethod("RetTrueStatic");
            MethodInfo RetTrue       = dynMod.GetMethod("RetTrue");

            Console.WriteLine(
                "Result (RetTrueStatic): {0}",
                RetTrueStatic.Invoke(null, null)
            );
            Console.WriteLine(
                "Result (RetTrue):       {0}",
                RetTrue.Invoke(Activator.CreateInstance(dynMod.dynamicType), null)
            );
        }
    }
}
