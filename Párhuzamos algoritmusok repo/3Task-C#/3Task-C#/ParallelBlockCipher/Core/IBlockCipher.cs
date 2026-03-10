namespace ParallelBlockCipher.Core
{
    public interface IBlockCipher
    {
        int BlockSizeBytes { get; }
        byte[] EncryptBlock(byte[] plainBlock, byte[] key);
        byte[] DecryptBlock(byte[] cipherBlock, byte[] key);
    }
}
