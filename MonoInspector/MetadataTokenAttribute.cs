namespace MonoInspector
{
    public class MetadataTokenAttribute : Attribute
    {
        public MetadataToken Token { get; }

        public MetadataTokenAttribute(Int32 token)
        {
            Token = token;
        }
    }
}
