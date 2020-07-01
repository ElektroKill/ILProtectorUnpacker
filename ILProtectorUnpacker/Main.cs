using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace ILProtectorUnpacker {
    public class Unpacker {
        private static readonly List<object> ToRemove = new List<object>();

        private static void Main(string[] args) {
            Console.WriteLine("ILProtectorUnpacker 1.1" + Environment.NewLine);


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

            Console.WriteLine("Loading Module...");

            var _module = ModuleDefMD.Load(args[0], asmResolver.DefaultModuleContext);
            var _assembly = Assembly.LoadFrom(args[0]);

            Console.WriteLine("Running global constructor...");
            RuntimeHelpers.RunModuleConstructor(_assembly.ManifestModule.ModuleHandle);

            Console.WriteLine("Resolving fields...");

            var invokeField = _module.GlobalType.FindField("Invoke");
            var stringField = _module.GlobalType.FindField("String");

            var strInvokeMethodToken = stringField?.FieldType.ToTypeDefOrRefSig().TypeDef?.FindMethod("Invoke")?.MDToken.ToInt32();
            var invokeMethodToken = invokeField?.FieldType.ToTypeDefOrRefSig().TypeDef?.FindMethod("Invoke")?.MDToken.ToInt32();

            if (invokeMethodToken is null)
                throw new Exception("Cannot find Invoke field");

            var invokeInstance = _assembly.ManifestModule.ResolveField(invokeField.MDToken.ToInt32());
            var invokeMethod = _assembly.ManifestModule.ResolveMethod(invokeMethodToken.Value);
            var invokeFieldInst = invokeInstance.GetValue(invokeInstance);

            MethodBase strInvokeMethod = null;
            object strFieldInst = null;
            if (strInvokeMethodToken != null) {
                var strInstance = _assembly.ManifestModule.ResolveField(stringField.MDToken.ToInt32());
                strInvokeMethod = _assembly.ManifestModule.ResolveMethod(strInvokeMethodToken.Value);
                strFieldInst = strInstance.GetValue(strInstance);
                ToRemove.Add(stringField);
            }

            ToRemove.Add(invokeField);

            Console.WriteLine("Applying hook...");
            Hooks.ApplyHook();

            Console.WriteLine("Processing methods...");
            foreach (var type in _module.GetTypes()) {
                foreach (var method in type.Methods) {
                    if (!method.HasBody)
                        continue;

                    Hooks.SpoofedMethod = _assembly.ManifestModule.ResolveMethod(method.MDToken.ToInt32());

                    DecryptMethods(method, invokeMethod, invokeFieldInst);

                    if (strFieldInst != null)
                        DecryptStrings(method, strInvokeMethod, strFieldInst);
                }
            }

            Console.WriteLine("Cleaning junk...");
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
										  .Where(t => t.HasImplMap && t.ImplMap.Name == "P0").ToList()) {
                _module.GlobalType.Remove(method);
            }

            var constructor = _module.GlobalType.FindStaticConstructor();

            if (constructor.Body != null) {
                var methodBody = constructor.Body;
                int startIndex = methodBody.Instructions.IndexOf(
                    methodBody.Instructions.FirstOrDefault(t =>
                        t.OpCode == OpCodes.Call && ((IMethodDefOrRef)t.Operand).Name ==
                        "GetIUnknownForObject")) - 2;

                int endIndex = methodBody.Instructions.IndexOf(methodBody.Instructions.FirstOrDefault(
                    inst => inst.OpCode == OpCodes.Call &&
                            ((IMethodDefOrRef)inst.Operand).Name == "Release")) + 2;

                methodBody.ExceptionHandlers.Remove(methodBody.ExceptionHandlers.FirstOrDefault(
                    exh => exh.HandlerEnd.Offset == methodBody.Instructions[endIndex + 1].Offset));

                for (int i = startIndex; i <= endIndex; i++)
                    methodBody.Instructions.Remove(methodBody.Instructions[startIndex]);
            }

            Console.WriteLine("Writing module...");

            string newFilePath =
                $"{Path.GetDirectoryName(args[0])}{Path.DirectorySeparatorChar}{Path.GetFileNameWithoutExtension(args[0])}-Unpacked{Path.GetExtension(args[0])}";

            ModuleWriterOptionsBase modOpts;

            if (!_module.IsILOnly || _module.VTableFixups != null)
                modOpts = new NativeModuleWriterOptions(_module, true);
            else
                modOpts = new ModuleWriterOptions(_module);

            if (modOpts is NativeModuleWriterOptions nativeOptions)
                _module.NativeWrite(newFilePath, nativeOptions);
            else
                _module.Write(newFilePath, (ModuleWriterOptions)modOpts);

            Console.WriteLine("Done!");
            Console.ReadKey(true);
        }

        private static void DecryptMethods(MethodDef methodDef, MethodBase invokeMethod, object fieldInstance) {
            var instructions = methodDef.Body.Instructions;
            if (instructions.Count < 9)
                return;
            if (instructions[0].OpCode != OpCodes.Ldsfld)
                return;
            if (((FieldDef)instructions[0].Operand).FullName != "i <Module>::Invoke")
                return;

            ToRemove.Add(instructions[3].Operand);

            int index = instructions[1].GetLdcI4Value();

            var dynamicMethodBodyReader = new DynamicMethodBodyReader(methodDef.Module, invokeMethod.Invoke(fieldInstance, new object[] { index }));
            dynamicMethodBodyReader.Read();

            methodDef.FreeMethodBody();
            methodDef.Body = dynamicMethodBodyReader.GetMethod().Body;
        }

        private static void DecryptStrings(MethodDef methodDefinition, MethodBase invokeMethod, object fieldInstance) {
            var instructions = methodDefinition.Body.Instructions;
            if (instructions.Count < 3)
                return;
            for (int i = 2; i < instructions.Count; i++) {
                if (instructions[i].OpCode != OpCodes.Callvirt)
                    continue;
                if (instructions[i].Operand.ToString() != "System.String s::Invoke(System.Int32)")
                    continue;
                int index = instructions[i - 1].GetLdcI4Value();
                instructions[i].OpCode = OpCodes.Ldstr;
                instructions[i - 1].OpCode = OpCodes.Nop;
                instructions[i - 2].OpCode = OpCodes.Nop;
                instructions[i].Operand = invokeMethod.Invoke(fieldInstance, new object[] { index });
            }
        }
    }
}