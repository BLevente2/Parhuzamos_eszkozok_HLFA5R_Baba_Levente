using System.Collections.Generic;

namespace ParallelBlockCipher.IO
{
    public static class FileSplitter
    {
        public static byte[][] Split(byte[] data, int blockSize, bool pad)
        {
            if (pad) data = Crypto.Padding.Pad(data, blockSize);
            var blocks = new byte[data.Length / blockSize][];
            for (var i = 0; i < blocks.Length; i++)
            {
                blocks[i] = new byte[blockSize];
                System.Buffer.BlockCopy(data, i * blockSize, blocks[i], 0, blockSize);
            }
            return blocks;
        }
    }
}
