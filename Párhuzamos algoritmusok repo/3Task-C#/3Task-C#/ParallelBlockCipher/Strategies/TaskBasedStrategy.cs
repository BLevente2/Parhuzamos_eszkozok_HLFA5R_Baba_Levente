using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ParallelBlockCipher.Core;

namespace ParallelBlockCipher.Strategies
{
    public class TaskBasedStrategy : IEncryptionStrategy
    {
        private readonly int _maxDegree;
        private readonly int _batch;

        public TaskBasedStrategy(int maxDegree, int batch = 1000)
        {
            _maxDegree = maxDegree < 1 ? Environment.ProcessorCount : maxDegree;
            _batch = batch;
        }

        public IEnumerable<byte[]> Process(IEnumerable<byte[]> blocks, byte[] key, IBlockCipher cipher, bool decrypt, Action<int>? progress)
        {
            var src = blocks as byte[][] ?? System.Linq.Enumerable.ToArray(blocks);
            var dst = new byte[src.Length][];
            using var sem = new SemaphoreSlim(_maxDegree);
            var tasks = new List<Task>();

            for (var i = 0; i < src.Length; i += _batch)
            {
                var start = i;
                var end = Math.Min(i + _batch, src.Length);
                sem.Wait();
                tasks.Add(Task.Run(() =>
                {
                    try
                    {
                        for (var j = start; j < end; j++)
                        {
                            dst[j] = decrypt ? cipher.DecryptBlock(src[j], key) : cipher.EncryptBlock(src[j], key);
                            progress?.Invoke(1);
                        }
                    }
                    finally
                    {
                        sem.Release();
                    }
                }));
            }

            Task.WhenAll(tasks).Wait();
            return dst;
        }
    }
}
