using System;
using System.Collections.Generic;
using ParallelBlockCipher.Core;

namespace ParallelBlockCipher.Strategies
{
    public class SingleThreadedStrategy : IEncryptionStrategy
    {
        public IEnumerable<byte[]> Process(IEnumerable<byte[]> blocks, byte[] key, IBlockCipher cipher, bool decrypt, Action<int>? progress)
        {
            var src = blocks as byte[][] ?? System.Linq.Enumerable.ToArray(blocks);
            var dst = new byte[src.Length][];
            for (var i = 0; i < src.Length; i++)
            {
                dst[i] = decrypt ? cipher.DecryptBlock(src[i], key) : cipher.EncryptBlock(src[i], key);
                progress?.Invoke(1);
            }
            return dst;
        }
    }
}
