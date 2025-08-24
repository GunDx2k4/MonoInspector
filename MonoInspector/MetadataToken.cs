namespace MonoInspector
{
    public enum TableType : byte
    {
        TypeDef = 0x02,
        TypeRef = 0x01,
        TypeSpec = 0x10,
        MethodDef = 0x06,
        FieldDef = 0x04,
        MethodRef = 0x0A,
        FieldRef = 0x0D,
        String = 0x70
    }

    public struct MetadataToken
    {

        public TableType Table { get; }
        public int Row { get; }

        public Int32 Token => ((byte)Table << 24) | (Row & 0x00FFFFFF);


        public MetadataToken(Int32 token)
        {
            Table = (TableType)(token >> 24);
            Row = token & 0x00FFFFFF;
        }

        public MetadataToken(TableType table, int row)
        {
            Table = table;
            Row = row;
        }

        public override string ToString()
        {
            return $"0x{Token:X8}";
        }

        public static implicit operator int(MetadataToken metadataToken)
        {
            return metadataToken.Token;
        }

        public static implicit operator MetadataToken(int token)
        {
            return new MetadataToken(token);
        }
    }
}
