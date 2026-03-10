using System;

namespace ParallelBlockCipher.Crypto
{
    public static class Padding
    {
        public static byte[] Pad(byte[] data, int blockSize)
        {
            var padLen = blockSize - (data.Length % blockSize);
            if (padLen == 0) padLen = blockSize;
            var output = new byte[data.Length + padLen];
            Buffer.BlockCopy(data, 0, output, 0, data.Length);
            for (var i = data.Length; i < output.Length; i++) output[i] = (byte)padLen;
            return output;
        }

        public static byte[] Unpad(byte[] padded, int blockSize)
        {
            if (padded.Length == 0 || padded.Length % blockSize != 0) throw new ArgumentException(nameof(padded));
            var padLen = padded[^1];
            if (padLen == 0 || padLen > blockSize) throw new ArgumentException(nameof(padded));
            for (var i = padded.Length - padLen; i < padded.Length; i++)
                if (padded[i] != padLen) throw new ArgumentException(nameof(padded));
            var output = new byte[padded.Length - padLen];
            Buffer.BlockCopy(padded, 0, output, 0, output.Length);
            return output;
        }
    }
}
