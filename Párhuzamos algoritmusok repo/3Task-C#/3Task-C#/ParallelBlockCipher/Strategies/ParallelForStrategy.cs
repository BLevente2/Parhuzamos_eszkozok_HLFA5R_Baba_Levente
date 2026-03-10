using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using ParallelBlockCipher.Core;

namespace ParallelBlockCipher.Strategies
{
    public class ParallelForStrategy : IEncryptionStrategy
    {
        private readonly int _max;
        public ParallelForStrategy(int max = 0) { _max = max; }
        public IEnumerable<byte[]> Process(IEnumerable<byte[]> blocks, byte[] key, IBlockCipher cipher, bool decrypt, Action<int>? progress)
        {
            var src = blocks as byte[][] ?? System.Linq.Enumerable.ToArray(blocks);
            var dst = new byte[src.Length][];
            var po = new ParallelOptions();
            if (_max > 0) po.MaxDegreeOfParallelism = _max;
            Parallel.For(0, src.Length, po, i =>
            {
                dst[i] = decrypt ? cipher.DecryptBlock(src[i], key) : cipher.EncryptBlock(src[i], key);
                progress?.Invoke(1);
            });
            return dst;
        }
    }
}
