using System;
using System.Collections.Generic;

namespace ParallelBlockCipher.Core
{
    public interface IEncryptionStrategy
    {
        IEnumerable<byte[]> Process(IEnumerable<byte[]> blocks, byte[] key, IBlockCipher cipher, bool decrypt, Action<int>? progress);
    }
}
