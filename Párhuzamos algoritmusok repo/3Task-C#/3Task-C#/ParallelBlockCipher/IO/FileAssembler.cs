using System.Collections.Generic;

namespace ParallelBlockCipher.IO
{
    public static class FileAssembler
    {
        public static byte[] Combine(IEnumerable<byte[]> blocks)
        {
            var arr = blocks as byte[][] ?? System.Linq.Enumerable.ToArray(blocks);
            var total = 0;
            foreach (var b in arr) total += b.Length;
            var output = new byte[total];
            var offset = 0;
            foreach (var b in arr)
            {
                System.Buffer.BlockCopy(b, 0, output, offset, b.Length);
                offset += b.Length;
            }
            return output;
        }
    }
}
