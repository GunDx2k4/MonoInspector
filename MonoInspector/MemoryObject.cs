using System.Reflection;
using System.Runtime.CompilerServices;

namespace MonoInspector
{
    public abstract class MemoryObject
    {
        private Inspector _inspector;

        protected Dictionary<Int32, IntPtr> CachedAddressByToken { get; } = new Dictionary<Int32, IntPtr>();
        protected Dictionary<Int32, IntPtr> CachedValueByToken { get; } = new Dictionary<Int32, IntPtr>();
        protected Dictionary<Int32, IntPtr> CachedMethodByToken { get; } = new Dictionary<Int32, IntPtr>();
        protected Dictionary<IntPtr, IntPtr> CachedOffsetByAddress { get; } = new Dictionary<IntPtr, IntPtr>();
        protected Dictionary<IntPtr, IntPtr> CachedClassByValue { get; } = new Dictionary<IntPtr, IntPtr>();

        public MemoryObject(Inspector inspector)
        {
            _inspector = inspector ?? throw new ArgumentNullException(nameof(inspector), "Inspector cannot be null.");
        }

        private static void ThrowIfNotTableTypeMethod(MetadataToken token)
        {
            if (token.Table != TableType.MethodDef && token.Table != TableType.MethodRef)
                throw new ArgumentException($"MetadataToken must be of type MethodDef or MethodRef. Given: {token.Table}");
        }

        private static void ThrowIfNotTableTypeClass(MetadataToken token)
        {
            if (token.Table != TableType.TypeDef && token.Table != TableType.TypeRef && token.Table != TableType.TypeSpec)
                throw new ArgumentException($"MetadataToken must be of type TypeDef, TypeRef or TypeSpec. Given: {token.Table}");
        }

        private static void ThrowIfNotTableTypeField(MetadataToken token)
        {
            if (token.Table != TableType.FieldDef && token.Table != TableType.FieldRef)
                throw new ArgumentException($"MetadataToken must be of type FieldDef or FieldRef. Given: {token.Table}");
        }

        protected IntPtr GetMethodAddressByToken(IntPtr classAddress, [CallerMemberName] string propertyName = "")
        {
            if (string.IsNullOrEmpty(propertyName))
                return default;
            var property = this.GetType().GetProperty(propertyName);
            if (property == null)
                return default;
            var attribute = property.GetCustomAttribute<MetadataTokenAttribute>();
            if (attribute == null)
                return default;
            var token = attribute.Token;

            ThrowIfNotTableTypeMethod(token);

            return GetMethodAddressByToken(token, classAddress);
        }

        protected IntPtr GetMethodAddressByToken(Int32 classToken,[CallerMemberName] string propertyName = "")
        {
            if (string.IsNullOrEmpty(propertyName))
                return default;
            var property = this.GetType().GetProperty(propertyName);
            if (property == null)
                return default;
            var attribute = property.GetCustomAttribute<MetadataTokenAttribute>();
            if (attribute == null)
                return default;
            var token = attribute.Token;

            ThrowIfNotTableTypeMethod(token);

            return GetMethodAddressByToken(token, GetClassAddressByToken(classToken));
        }

        protected IntPtr GetClassAddressByToken([CallerMemberName] string propertyName = "")
        {
            if (string.IsNullOrEmpty(propertyName))
                return default;
            var property = this.GetType().GetProperty(propertyName);
            if (property == null)
                return default;
            var attribute = property.GetCustomAttribute<MetadataTokenAttribute>();
            if (attribute == null)
                return default;

            var token = attribute.Token;

            ThrowIfNotTableTypeClass(token);

            return GetClassAddressByToken(token);
        }

        protected T? GetFieldValueByToken<T>(IntPtr instanceAddress, [CallerMemberName] string propertyName = "")
        {
            if (string.IsNullOrEmpty(propertyName))
                return default;
            var property = this.GetType().GetProperty(propertyName);
            if (property == null)
                return default;
            var attribute = property.GetCustomAttribute<MetadataTokenAttribute>();
            if (attribute == null)
                return default;

            var token = attribute.Token;

            ThrowIfNotTableTypeField(token);

            if (CachedValueByToken.TryGetValue(token, out IntPtr cacheValue) && cacheValue != IntPtr.Zero)
            {
                var value = ReadValueFromAddress<T>(cacheValue);
                if (value != null)
                    return value;
            }
            var (fieldAddress, classOfField) = GetFieldAddressByToken(token);
            var fieldOffset = GetFieldOffSet(fieldAddress);

            var valueAddress = instanceAddress + fieldOffset;

            if (CachedValueByToken.ContainsKey(token))
                CachedValueByToken[token] = valueAddress;
            else
                CachedValueByToken.Add(token, valueAddress);

            return ReadValueFromAddress<T>(valueAddress);
        }

        protected T? GetFieldStaticValueByToken<T>([CallerMemberName] string propertyName = "")
        {
            if (string.IsNullOrEmpty(propertyName))
                return default;
            var property = this.GetType().GetProperty(propertyName);
            if (property == null)
                return default;
            var attribute = property.GetCustomAttribute<MetadataTokenAttribute>();
            if (attribute == null)
                return default;

            var token = attribute.Token;

            ThrowIfNotTableTypeField(token);

            if (CachedValueByToken.TryGetValue(token, out IntPtr cacheValue) && cacheValue != IntPtr.Zero)
            {
                var value = ReadValueFromAddress<T>(cacheValue);
                if (value != null)
                    return value;
            }
            var (fieldAddress, classOfField) = GetFieldAddressByToken(token);

            var valueAddress = _inspector.GetStaticFieldValue(classOfField, fieldAddress);

            if (CachedValueByToken.ContainsKey(token))
                CachedValueByToken[token] = valueAddress;
            else
                CachedValueByToken.Add(token, valueAddress);

            return ReadValueFromAddress<T>(valueAddress);
        }


        private IntPtr GetMethodAddressByToken(Int32 token, IntPtr classAddress)
        {
            if (CachedMethodByToken.TryGetValue(token, out IntPtr cacheAddress) && cacheAddress != IntPtr.Zero)
                return cacheAddress;

            var functionAddress = _inspector.GetMethodByToken(token, classAddress);

            if (CachedMethodByToken.ContainsKey(token))
                CachedMethodByToken[token] = functionAddress;
            else
                CachedMethodByToken.Add(token, functionAddress);

            return functionAddress;
        }

        private IntPtr GetClassAddressByToken(Int32 token)
        {
            if (CachedAddressByToken.TryGetValue(token, out IntPtr cacheAddress))
                return cacheAddress;

            var classAddress = _inspector.GetClassByToken(token);

            if (CachedAddressByToken.ContainsKey(token))
                CachedAddressByToken[token] = classAddress;
            else
                CachedAddressByToken.Add(token, classAddress);

            return classAddress;
        }

        private (IntPtr, IntPtr) GetFieldAddressByToken(Int32 token)
        {
            if (CachedAddressByToken.TryGetValue(token, out IntPtr cacheAddress) &&
                CachedAddressByToken.TryGetValue(token, out IntPtr cacheClassAddress) &&
                cacheAddress != IntPtr.Zero && cacheClassAddress != IntPtr.Zero)
                return (cacheAddress, cacheClassAddress);

            var fieldAddress = _inspector.GetFieldByToken(token, out IntPtr classOfField);

            if (CachedAddressByToken.ContainsKey(token))
            {
                CachedAddressByToken[-token] = classOfField;
                CachedAddressByToken[token] = fieldAddress;
            }
            else
            {
                CachedAddressByToken.Add(-token, classOfField);
                CachedAddressByToken.Add(token, fieldAddress);
            }

            return (fieldAddress, classOfField);
        }

        private IntPtr GetFieldOffSet(IntPtr fieldAddress)
        {
            if (CachedOffsetByAddress.TryGetValue(fieldAddress, out IntPtr cacheOffset) && cacheOffset != IntPtr.Zero)
                return cacheOffset;

            var offset = _inspector.GetFieldOffset(fieldAddress);

            if (CachedOffsetByAddress.ContainsKey(fieldAddress))
                CachedOffsetByAddress[fieldAddress] = offset;
            else
                CachedOffsetByAddress.Add(fieldAddress, offset);

            return offset;
        }

        private IntPtr GetClassAddressByValueAddress(IntPtr valueAddress)
        {
            if (CachedClassByValue.TryGetValue(valueAddress, out IntPtr cacheClassAddress) && cacheClassAddress != IntPtr.Zero)
                return cacheClassAddress;

            var classAddress = _inspector.GetClassByObject(valueAddress);

            if (CachedClassByValue.ContainsKey(valueAddress))
                CachedClassByValue[valueAddress] = classAddress;
            else
                CachedClassByValue.Add(valueAddress, classAddress);

            return classAddress;
        }

        private T? ReadValueFromAddress<T>(IntPtr address)
        {
            if (address == IntPtr.Zero)
                return default;
            try
            {
                switch (typeof(T))
                {
                    case Type t when t == typeof(int):
                        return (T)(object)_inspector.Memory.ReadInt(address);
                    case Type t when t == typeof(long):
                        return (T)(object)_inspector.Memory.ReadLong(address);
                    case Type t when t == typeof(float):
                        return (T)(object)_inspector.Memory.ReadFloat(address);
                    case Type t when t == typeof(double):
                        return (T)(object)_inspector.Memory.ReadDouble(address);
                    case Type t when t == typeof(string):
                        return (T)(object)_inspector.ReadMonoString(_inspector.Is64Bit ? (IntPtr)_inspector.Memory.ReadLong(address) : _inspector.Memory.ReadInt(address));
                    case Type t when t == typeof(byte):
                        return (T)(object)_inspector.Memory.ReadByte(address);
                    case Type t when t == typeof(short):
                        return (T)(object)_inspector.Memory.ReadShort(address);
                    case Type t when t == typeof(bool):
                        return (T)(object)(_inspector.Memory.ReadByte(address) != 0);
                    case Type t when t == typeof(IntPtr):
                        return (T)(object)address;
                    default:
                        throw new NotSupportedException($"Type {typeof(T)} is not supported.");
                }
            }
            catch (Exception)
            {
                return default;
            }
        }
    }
}
