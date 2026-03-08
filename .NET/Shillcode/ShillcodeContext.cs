using System;
using System.Reflection;
using System.Reflection.Emit;
using System.Collections.Generic;

namespace Shillcode
{
    public class ShillcodeContext
    {
        public AssemblyBuilder assemblyBuilder;

        public ShillcodeContext(string assemblyName)
        {
            assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(new AssemblyName(assemblyName), AssemblyBuilderAccess.Run);
        }

        public ModuleContext StartModuleDefinition(string moduleName)
        {
            var moduleBuilder = assemblyBuilder.DefineDynamicModule(moduleName);
            var typeBuilder   = moduleBuilder.DefineType("DynamicType", TypeAttributes.Public);

            return new ModuleContext
            {
                moduleBuilder = moduleBuilder,
                typeBuilder   = typeBuilder,
                methods       = new List<MethodBuilder>()
            };
        }
    }

    public class ModuleContext
    {
        public ModuleBuilder moduleBuilder;
        public TypeBuilder typeBuilder;
        public List<MethodBuilder> methods;
        public Type dynamicType;

        public void EndModuleDefinition()
        {
            dynamicType = typeBuilder.CreateType();
        }

        public void AddMethodToModule(string name, byte[] ilCode, MethodAttributes attributes, Type returnType, Type[] parameterTypes)
        {
            MethodBuilder methodBuilder = typeBuilder.DefineMethod(name, attributes, returnType, parameterTypes);
            ILGenerator ilGenerator = methodBuilder.GetILGenerator();

            FieldInfo ilStream = typeof(ILGenerator).GetField("m_ILStream", BindingFlags.NonPublic | BindingFlags.Instance);
            FieldInfo ilLength = typeof(ILGenerator).GetField("m_length", BindingFlags.NonPublic | BindingFlags.Instance);
            FieldInfo maxStackSize = typeof(ILGenerator).GetField("m_maxStackSize", BindingFlags.NonPublic | BindingFlags.Instance);

            ilStream.SetValue(ilGenerator, ilCode);
            ilLength.SetValue(ilGenerator, ilCode.Length);
            maxStackSize.SetValue(ilGenerator, int.MaxValue);

            methods.Add(methodBuilder);
        }

        public MethodInfo GetMethod(string name)
        {
            return dynamicType.GetMethod(name);
        }
    }
}
