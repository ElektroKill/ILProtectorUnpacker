using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace ILProtectorUnpacker {
    public class Unpacker {
        private static ModuleDefMD _module;
        private static Assembly _assembly;
        private static readonly List<object> ToRemove = new List<object>();

        private static void Main(string[] args) {
            if (args.Length == 0) {
                Console.WriteLine("Please drag & drop the protected file");
                Console.WriteLine("Press any key to exit....");
                Console.ReadKey(true);
                return;
            }

			var asmResolver = new AssemblyResolver {
				EnableFrameworkRedirect = false
			};
			asmResolver.DefaultModuleContext = new ModuleContext(asmResolver);

            _module = ModuleDefMD.Load(args[0], asmResolver.DefaultModuleContext);
            _assembly = Assembly.LoadFrom(args[0]);
            RuntimeHelpers.RunModuleConstructor(_assembly.ManifestModule.ModuleHandle);

            var invokeField = _module.GlobalType.FindField("Invoke");
            var stringField = _module.GlobalType.FindField("String");

            var strInvokeMethodToken = stringField?.FieldType.ToTypeDefOrRefSig().TypeDef?.FindMethod("Invoke")?.MDToken.ToInt32();
            var invokeMethodToken = invokeField?.FieldType.ToTypeDefOrRefSig().TypeDef?.FindMethod("Invoke")?.MDToken.ToInt32();

            if (invokeMethodToken is null)
                throw new Exception("Cannot find Invoke field");

            var invokeInstance = _assembly.ManifestModule.ResolveField(invokeField.MDToken.ToInt32());
            var invokeMethod = _assembly.ManifestModule.ResolveMethod(invokeMethodToken.Value);

            FieldInfo strInstance = null;
            MethodBase strInvokeMethod = null;
            if (strInvokeMethodToken != null) {
                strInstance = _assembly.ManifestModule.ResolveField(stringField.MDToken.ToInt32());
                strInvokeMethod = _assembly.ManifestModule.ResolveMethod(strInvokeMethodToken.Value);
                ToRemove.Add(stringField);
            }

            ToRemove.Add(invokeField);
            Hooks.ApplyHook();
            foreach (var type in _module.GetTypes()) {
				foreach (var method in type.Methods) {
                    DecryptMethods(method, invokeMethod, invokeInstance.GetValue(invokeInstance));
                    if (strInstance != null)
                        DecryptStrings(method, strInvokeMethod, strInstance.GetValue(strInstance));
                }
			}

			foreach (var obj in ToRemove) {
				switch (obj) {
                    case FieldDef fieldDefinition:
                        var res = fieldDefinition.FieldType.ToTypeDefOrRefSig().TypeDef;
						if (res.DeclaringType != null)
							res.DeclaringType.NestedTypes.Remove(res);
						else
							_module.Types.Remove(res);
						fieldDefinition.DeclaringType.Fields.Remove(fieldDefinition);
                        break;
                    case TypeDef typeDefinition:
                        typeDefinition.DeclaringType.NestedTypes.Remove(typeDefinition);
                        break;
                }
			}

			foreach (var method in _module.GlobalType.Methods
                .Where(t => t.HasImplMap && t.ImplMap.Module.Name.Contains("Protect")).ToList())
                _module.GlobalType.Methods.Remove(method);

			var constructor = _module.GlobalType.FindStaticConstructor();

            if (constructor.Body != null) {
                var methodBody = constructor.Body;
                var startIndex = methodBody.Instructions.IndexOf(
                    methodBody.Instructions.FirstOrDefault(t =>
                        t.OpCode == OpCodes.Call && ((IMethodDefOrRef)t.Operand).Name ==
                        "GetIUnknownForObject")) - 2;

                var endIndex = methodBody.Instructions.IndexOf(methodBody.Instructions.FirstOrDefault(
                    inst => inst.OpCode == OpCodes.Call &&
                            ((IMethodDefOrRef)inst.Operand).Name == "Release")) + 2;

                methodBody.ExceptionHandlers.Remove(methodBody.ExceptionHandlers.FirstOrDefault(
                    exh => exh.HandlerEnd.Offset == methodBody.Instructions[endIndex + 1].Offset));

                for (var i = startIndex; i <= endIndex; i++)
                    methodBody.Instructions.Remove(methodBody.Instructions[startIndex]);
            }

            var extension = Path.GetExtension(args[0]);
            var path = args[0].Remove(args[0].Length - extension.Length, extension.Length) + "-unpacked" + extension;
            _module.Write(path);
        }

        private static void DecryptMethods(MethodDef methodDefinition, MethodBase invokeMethod,
            object fieldInstance) {
            if (methodDefinition.Body == null)
                return;
            var instructions = methodDefinition.Body.Instructions;
            if (instructions.Count < 9)
                return;
            if (instructions[0].OpCode != OpCodes.Ldsfld)
                return;
            if (((FieldDef)instructions[0].Operand).FullName != "i <Module>::Invoke")
                return;
            ToRemove.Add(instructions[3].Operand);
            Hooks.MethodBase = _assembly.ManifestModule.ResolveMethod(methodDefinition.MDToken.ToInt32());
            var index = instructions[1].GetLdcI4Value();

			var dynamicMethodBodyReader = new DynamicMethodBodyReader(_module, invokeMethod.Invoke(fieldInstance, new object[] { index }));
			dynamicMethodBodyReader.Read();

			methodDefinition.FreeMethodBody();
            methodDefinition.Body = dynamicMethodBodyReader.GetMethod().Body;
        }

        private static void DecryptStrings(MethodDef methodDefinition, MethodBase invokeMethod,
            object fieldInstance) {
            if (methodDefinition.Body == null)
                return;
            var instructions = methodDefinition.Body.Instructions;
            if (instructions.Count < 3)
                return;
            for (var i = 2; i < instructions.Count; i++) {
                if (instructions[i].OpCode != OpCodes.Callvirt)
                    continue;
                if (instructions[i].Operand.ToString() != "System.String s::Invoke(System.Int32)")
                    continue;
                var index = instructions[i - 1].GetLdcI4Value();
                instructions[i].OpCode = OpCodes.Ldstr;
                instructions[i - 1].OpCode = OpCodes.Nop;
                instructions[i - 2].OpCode = OpCodes.Nop;
                instructions[i].Operand = invokeMethod.Invoke(fieldInstance, new object[] { index });
            }
        }
    }
}