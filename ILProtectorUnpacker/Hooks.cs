using System;
using System.Linq;
using System.Reflection;
using HarmonyLib;

namespace ILProtectorUnpacker {
	internal class Hooks {
		private static readonly Harmony harmony = new Harmony("(Washo/Watasho)(1337)");
		internal static MethodBase SpoofedMethod;

		internal static void ApplyHook() {
			var runtimeType = typeof(Type).Assembly.GetType("System.RuntimeType");

			var getMethod = runtimeType.GetMethods(BindingFlags.NonPublic | BindingFlags.Static).First(m =>
				m.Name == "GetMethodBase" && m.GetParameters().Length == 2 &&
				m.GetParameters()[0].ParameterType == runtimeType &&
				m.GetParameters()[1].ParameterType.Name == "IRuntimeMethodInfo");

			harmony.Patch(getMethod, null, new HarmonyMethod(typeof(Hooks).GetMethod(nameof(PostFix), BindingFlags.NonPublic | BindingFlags.Static)));
		}

		private static void PostFix(ref MethodBase __result) {
			if (__result.Name == "InvokeMethod" && __result.DeclaringType == typeof(RuntimeMethodHandle))
				__result = SpoofedMethod;
		}
	}
}