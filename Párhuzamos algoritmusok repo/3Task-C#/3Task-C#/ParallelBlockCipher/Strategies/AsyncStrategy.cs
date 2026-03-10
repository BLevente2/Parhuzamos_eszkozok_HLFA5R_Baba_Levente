using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ParallelBlockCipher.Core;

namespace ParallelBlockCipher.Strategies
{
    public class AsyncStrategy : IEncryptionStrategy
    {
        private readonly int _maxDegree;

        public AsyncStrategy(int maxDegree)
        {
            _maxDegree = maxDegree < 1 ? Environment.ProcessorCount : maxDegree;
        }

        public IEnumerable<byte[]> Process(IEnumerable<byte[]> blocks, byte[] key, IBlockCipher cipher, bool decrypt, Action<int>? progress)
        {
            var src = blocks as byte[][] ?? System.Linq.Enumerable.ToArray(blocks);
            var dst = new byte[src.Length][];
            using var sem = new SemaphoreSlim(_maxDegree);
            var tasks = new Task[src.Length];

            for (var i = 0; i < src.Length; i++)
            {
                var idx = i;
                tasks[idx] = Task.Run(async () =>
                {
                    await sem.WaitAsync();
                    try
                    {
                        dst[idx] = decrypt ? cipher.DecryptBlock(src[idx], key) : cipher.EncryptBlock(src[idx], key);
                        progress?.Invoke(1);
                    }
                    finally
                    {
                        sem.Release();
                    }
                });
            }

            Task.WhenAll(tasks).Wait();
            return dst;
        }
    }
}
