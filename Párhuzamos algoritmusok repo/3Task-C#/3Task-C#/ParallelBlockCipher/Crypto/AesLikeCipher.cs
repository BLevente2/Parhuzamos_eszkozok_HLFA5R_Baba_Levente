using System;
using ParallelBlockCipher.Core;

namespace ParallelBlockCipher.Crypto
{
    public sealed class AesLikeCipher : IBlockCipher
    {
        public int BlockSizeBytes => 16;

        public byte[] EncryptBlock(byte[] plainBlock, byte[] key)
        {
            if (plainBlock.Length != BlockSizeBytes || key.Length == 0) throw new ArgumentException();
            var state = new byte[BlockSizeBytes];
            Buffer.BlockCopy(plainBlock, 0, state, 0, BlockSizeBytes);
            for (var round = 0; round < 4; round++)
            {
                AddRoundKey(state, key, round);
                SubBytes(state);
                Rotate(state, ((round + 1) * 3) % BlockSizeBytes);
            }
            return state;
        }

        public byte[] DecryptBlock(byte[] cipherBlock, byte[] key)
        {
            if (cipherBlock.Length != BlockSizeBytes || key.Length == 0) throw new ArgumentException();
            var state = new byte[BlockSizeBytes];
            Buffer.BlockCopy(cipherBlock, 0, state, 0, BlockSizeBytes);
            for (var round = 3; round >= 0; round--)
            {
                Rotate(state, BlockSizeBytes - (((round + 1) * 3) % BlockSizeBytes));
                InvSubBytes(state);
                AddRoundKey(state, key, round);
            }
            return state;
        }

        private static void AddRoundKey(byte[] state, byte[] key, int round)
        {
            for (var i = 0; i < state.Length; i++)
                state[i] ^= key[(i + round) % key.Length];
        }

        private static void SubBytes(byte[] state)
        {
            for (var i = 0; i < state.Length; i++)
                state[i] = (byte)((state[i] * 7 + 13) & 0xFF);
        }

        private static void InvSubBytes(byte[] state)
        {
            for (var i = 0; i < state.Length; i++)
            {
                var x = (state[i] - 13) & 0xFF;
                state[i] = (byte)((x * 183) & 0xFF);
            }
        }

        private static void Rotate(byte[] data, int count)
        {
            if (count == 0) return;
            var tmp = new byte[count];
            Buffer.BlockCopy(data, 0, tmp, 0, count);
            Buffer.BlockCopy(data, count, data, 0, data.Length - count);
            Buffer.BlockCopy(tmp, 0, data, data.Length - count, count);
        }
    }
}
