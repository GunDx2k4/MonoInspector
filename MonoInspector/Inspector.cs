using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace MonoInspector
{
    /*
    Author (original): warbler
    Github (original): https://github.com/warbler/SharpMonoInjector

    Modified by: GunDx2k4
    Description: 
    This project is based on SharpMonoInjector, originally designed for injecting DLLs into Mono processes.
    It has been modified and extended into MonoInspector, focusing on inspecting Mono applications by
    extracting information about Assemblies, Classes, and Fields rather than performing injection.
    */

    public class Inspector
    {
        private const string string_null = "\0";

        private const string mono_get_root_domain = "mono_get_root_domain";

        private const string mono_thread_attach = "mono_thread_attach";

        private const string mono_domain_assembly_open = "mono_domain_assembly_open";

        private const string mono_assembly_get_image = "mono_assembly_get_image";

        private const string mono_class_from_name = "mono_class_from_name";

        private const string mono_object_get_class = "mono_object_get_class";

        private const string mono_class_get_field_from_name = "mono_class_get_field_from_name";

        private const string mono_field_get_value_object = "mono_field_get_value_object";

        private const string mono_field_get_offset = "mono_field_get_offset";

        private const string mono_string_to_utf8 = "mono_string_to_utf8";

        private const string mono_class_get = "mono_class_get";

        private const string mono_runtime_invoke = "mono_runtime_invoke";

        private const string mono_class_get_name = "mono_class_get_name";

        private const string mono_class_get_method_from_name = "mono_class_get_method_from_name";

        private const string mono_get_method = "mono_get_method";

        private const string mono_class_vtable = "mono_class_vtable";

        private const string mono_field_static_get_value = "mono_field_static_get_value";

        private const string mono_field_from_token = "mono_field_from_token";

        private const string mono_method_get_token = "mono_method_get_token";

        private readonly Dictionary<string, IntPtr> Exports = new Dictionary<string, IntPtr>
    {
        { mono_get_root_domain, IntPtr.Zero },
        { mono_thread_attach, IntPtr.Zero },
        { mono_domain_assembly_open, IntPtr.Zero },
        { mono_assembly_get_image, IntPtr.Zero },
        { mono_class_from_name, IntPtr.Zero },
        { mono_object_get_class, IntPtr.Zero },
        { mono_class_get_field_from_name, IntPtr.Zero },
        { mono_field_get_value_object, IntPtr.Zero },
        { mono_field_get_offset, IntPtr.Zero },
        { mono_string_to_utf8, IntPtr.Zero },
        { mono_class_get, IntPtr.Zero },
        { mono_runtime_invoke, IntPtr.Zero },
        { mono_class_get_name, IntPtr.Zero },
        { mono_class_get_method_from_name, IntPtr.Zero },
        { mono_class_vtable, IntPtr.Zero },
        { mono_field_static_get_value, IntPtr.Zero },
        { mono_field_from_token, IntPtr.Zero },
        { mono_get_method, IntPtr.Zero },
        { mono_method_get_token, IntPtr.Zero }
    };

        private readonly IntPtr _handle;

        private IntPtr _rootDomain;

        private IntPtr _imageAssembly;

        private bool _attach;

        private IntPtr _mono;

        public Memory Memory { get; private set; }
        public bool Is64Bit { get; private set; }

        public Inspector(Process process)
        {
            if ((_handle = Native.OpenProcess(ProcessAccessRights.PROCESS_ALL_ACCESS, false, process.Id)) == IntPtr.Zero)
                throw new Exception("Failed to open process", new Win32Exception(Marshal.GetLastWin32Error()));

            Is64Bit = ProcessUtils.Is64BitProcess(_handle);
            Memory = new Memory(_handle);

        }

        public async Task<bool> IsMonoModuleLoaded()
        {
            const int maxAttempts = 100;
            int attempts = 0;
            while (_mono == IntPtr.Zero && attempts < maxAttempts)
            {
                await Task.Delay(100);
                if (ProcessUtils.GetMonoModule(_handle, out _mono))
                {
                    if (_mono != IntPtr.Zero)
                    {
                        ObtainMonoExports();
                        break;
                    }
                }
                attempts++;
            }

            await Task.Delay(1000);
            attempts = 0;

            while (_imageAssembly == IntPtr.Zero && attempts < maxAttempts)
            {
                await Task.Delay(100);
                try
                {
                    _imageAssembly = GetImageAssembly();
                }
                catch
                {

                }
                if (_imageAssembly != IntPtr.Zero)
                    return true;
                attempts++;
            }

            return false;
        }

        private static void ThrowIfNull(IntPtr ptr, string methodName)
        {
            if (ptr == IntPtr.Zero)
                throw new Exception($"{methodName}() returned NULL");
        }

        private void ObtainMonoExports()
        {
            foreach (ExportedFunction ef in ProcessUtils.GetExportedFunctions(_handle, _mono))
                if (Exports.ContainsKey(ef.Name))
                    Exports[ef.Name] = ef.Address;
            foreach (var kvp in Exports)
                if (kvp.Value == IntPtr.Zero)
                    throw new Exception($"Failed to obtain the address of {kvp.Key}()");
        }

        private byte[] Assemble(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args)
        {
            return Is64Bit ? Assemble64(functionPtr, retValPtr, args) : Assemble86(functionPtr, retValPtr, args);
        }

        private byte[] Assemble86(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args)
        {
            Assembler asm = new Assembler();

            if (_attach)
            {
                asm.Push(_rootDomain);
                asm.MovEax(Exports[mono_thread_attach]);
                asm.CallEax();
                asm.AddEsp(4);
            }

            for (int i = args.Length - 1; i >= 0; i--)
                asm.Push(args[i]);

            asm.MovEax(functionPtr);
            asm.CallEax();
            asm.AddEsp((byte)(args.Length * 4));
            asm.MovEaxTo(retValPtr);
            asm.Return();

            return asm.ToByteArray();
        }

        private byte[] Assemble64(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args)
        {
            Assembler asm = new Assembler();

            asm.SubRsp(40);

            if (_attach)
            {
                asm.MovRax(Exports[mono_thread_attach]);
                asm.MovRcx(_rootDomain);
                asm.CallRax();
            }

            asm.MovRax(functionPtr);

            for (int i = 0; i < args.Length; i++)
            {
                switch (i)
                {
                    case 0:
                        asm.MovRcx(args[i]);
                        break;
                    case 1:
                        asm.MovRdx(args[i]);
                        break;
                    case 2:
                        asm.MovR8(args[i]);
                        break;
                    case 3:
                        asm.MovR9(args[i]);
                        break;
                }
            }

            asm.CallRax();
            asm.AddRsp(40);
            asm.MovRaxTo(retValPtr);
            asm.Return();

            return asm.ToByteArray();
        }

        private IntPtr Execute(IntPtr address, params IntPtr[] args)
        {
            IntPtr retValPtr = Is64Bit ? Memory.AllocateAndWrite((long)0) : Memory.AllocateAndWrite(0);

            byte[] code = Assemble(address, retValPtr, args);
            IntPtr alloc = Memory.AllocateAndWrite(code);
            IntPtr thread = Native.CreateRemoteThread(_handle, IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, out _);
            if (thread == IntPtr.Zero)
                throw new Exception("Failed to create a remote thread", new Win32Exception(Marshal.GetLastWin32Error()));

            WaitResult result = Native.WaitForSingleObject(thread, -1);

            if (result == WaitResult.WAIT_FAILED)
                throw new Exception("Failed to wait for a remote thread", new Win32Exception(Marshal.GetLastWin32Error()));
            IntPtr ret = Is64Bit ? (IntPtr)Memory.ReadLong(retValPtr) : (IntPtr)Memory.ReadInt(retValPtr);

            if ((long)ret == 0x00000000C0000005)
                throw new Exception($"An access violation occurred while executing {Exports.First(e => e.Value == address).Key}()");
            return ret;
        }

        private string GetClassName(IntPtr monoObject)
        {
            IntPtr @class = Execute(Exports[mono_object_get_class], monoObject);
            ThrowIfNull(@class, mono_object_get_class);
            IntPtr className = Execute(Exports[mono_class_get_name], @class);
            ThrowIfNull(className, mono_class_get_name);
            return Memory.ReadString(className, 256, Encoding.UTF8);
        }

        public void RuntimeInvoke(IntPtr @class, IntPtr method)
        {
            IntPtr excPtr = Is64Bit ? Memory.AllocateAndWrite((long)0) : Memory.AllocateAndWrite(0);

            IntPtr result = Execute(Exports[mono_runtime_invoke], method, @class, IntPtr.Zero, excPtr);

            IntPtr exc = Memory.ReadIntPtr(excPtr);

            if (exc != IntPtr.Zero)
            {
                string className = GetClassName(exc);
                IntPtr messagePtr = Memory.ReadIntPtr(exc + (Is64Bit ? 0x20 : 0x10));
                string message = ReadMonoString(messagePtr);
                throw new Exception($"The managed method threw an exception: ({className}) {message}");
            }
        }


        public string ReadMonoString(IntPtr monoString)
        {
            int len = Memory.ReadInt(monoString + (Is64Bit ? 0x10 : 0x8));
            return Memory.ReadUnicodeString(monoString + (Is64Bit ? 0x14 : 0xC), len * 2);
        }

        private IntPtr GetRootDomain()
        {
            IntPtr rootDomain = Execute(Exports[mono_get_root_domain]);
            ThrowIfNull(rootDomain, mono_get_root_domain);
            _attach = true;
            return rootDomain;
        }

        private IntPtr GetImageAssembly()
        {
            if (_rootDomain == IntPtr.Zero)
                _rootDomain = GetRootDomain();
            IntPtr assembly = Execute(Exports[mono_domain_assembly_open], _rootDomain, Memory.AllocateAndWrite("Assembly-CSharp"));
            ThrowIfNull(assembly, mono_domain_assembly_open);
            IntPtr image = Execute(Exports[mono_assembly_get_image], assembly);
            ThrowIfNull(image, mono_assembly_get_image);
            return image;
        }

        public IntPtr GetClassByToken(Int32 token)
        {
            IntPtr klass = Execute(Exports[mono_class_get], _imageAssembly, token);
            ThrowIfNull(klass, mono_class_get);
            return klass;
        }

        public IntPtr GetClassByName(string className, string? @namespace = string_null)
        {
            var namespaceClass = (@namespace == null || @namespace == string_null) ? string_null : @namespace;
            IntPtr classChar = Execute(Exports[mono_class_from_name], _imageAssembly, Memory.AllocateAndWrite(namespaceClass), Memory.AllocateAndWrite(className));
            ThrowIfNull(classChar, mono_class_from_name);
            return classChar;
        }

        public IntPtr GetClassByObject(IntPtr obj)
        {
            IntPtr klass = Execute(Exports[mono_object_get_class], obj);
            ThrowIfNull(klass, mono_object_get_class);
            return klass;
        }

        public IntPtr GetFieldByToken(Int32 token, out IntPtr klass)
        {
            IntPtr bufferClass = Memory.Allocate(IntPtr.Size);
            IntPtr field = Execute(Exports[mono_field_from_token], _imageAssembly, token, bufferClass, IntPtr.Zero);
            klass = Memory.ReadIntPtr(bufferClass);
            ThrowIfNull(field, mono_field_from_token);
            return field;
        }

        public IntPtr GetFieldByName(IntPtr classPtr, string fieldName)
        {
            IntPtr field = Execute(Exports[mono_class_get_field_from_name], classPtr, Memory.AllocateAndWrite(fieldName));
            ThrowIfNull(field, mono_class_get_field_from_name);
            return field;
        }

        public IntPtr GetStaticFieldValue(IntPtr classPtr, IntPtr fieldPtr)
        {
            IntPtr vTable = Execute(Exports[mono_class_vtable], _rootDomain, classPtr);
            IntPtr buffer = Memory.Allocate(IntPtr.Size);
            IntPtr result = Execute(Exports[mono_field_static_get_value], vTable, fieldPtr, buffer);
            ThrowIfNull(result, mono_field_static_get_value);
            return result;
        }

        public IntPtr GetMethodByToken(Int32 token, IntPtr classPtr)
        {
            IntPtr method = Execute(Exports[mono_get_method], _imageAssembly, token, classPtr);
            ThrowIfNull(method, mono_get_method);
            return method;
        }

        public IntPtr GetMethodByName(IntPtr @class, string methodName)
        {
            IntPtr method = Execute(Exports[mono_class_get_method_from_name], @class, Memory.AllocateAndWrite(methodName), IntPtr.Zero);
            ThrowIfNull(method, mono_class_get_method_from_name);
            return method;
        }

        public Int32 GetTokenMethod(IntPtr methodPtr)
        {
            Int32 token = Execute(Exports[mono_method_get_token], methodPtr).ToInt32();
            ThrowIfNull(token, mono_method_get_token);
            return token;
        }

        public IntPtr GetFieldOffset(IntPtr fieldPtr)
        {
            IntPtr offset = Execute(Exports[mono_field_get_offset], fieldPtr);
            ThrowIfNull(offset, mono_field_get_offset);
            return offset;
        }
    }

}
