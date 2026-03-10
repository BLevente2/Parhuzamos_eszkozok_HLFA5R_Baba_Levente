using System.Runtime.InteropServices;

namespace AES.WinForms.Native;

internal static class NativeOpenClMethods
{
    private const string LibraryName = "crypto_aes_opencl.dll";

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_opencl_warmup", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus Warmup();

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_opencl_shutdown", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void Shutdown();

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_opencl_last_error_message", CallingConvention = CallingConvention.Cdecl)]
    internal static extern nint LastErrorMessage();

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_opencl_aes_ctr_encrypt_alloc", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesCtrEncryptAlloc(byte[] key, nuint keyLenBytes, byte[] iv16, int padding, byte[] plaintext, nuint plaintextLen, out nint ciphertextOut, out nuint ciphertextLenOut);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_opencl_aes_ctr_decrypt_alloc", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesCtrDecryptAlloc(byte[] key, nuint keyLenBytes, byte[] iv16, int padding, byte[] ciphertext, nuint ciphertextLen, out nint plaintextOut, out nuint plaintextLenOut);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_opencl_aes_gcm_encrypt_alloc", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesGcmEncryptAlloc(byte[] key, nuint keyLenBytes, byte[] iv, nuint ivLen, byte[]? aad, nuint aadLen, byte[] plaintext, nuint plaintextLen, out nint ciphertextOut, out nuint ciphertextLenOut, byte[] tag16Out);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_opencl_aes_gcm_decrypt_alloc", CallingConvention = CallingConvention.Cdecl)]
    internal static extern NativeStatus AesGcmDecryptAlloc(byte[] key, nuint keyLenBytes, byte[] iv, nuint ivLen, byte[]? aad, nuint aadLen, byte[] ciphertext, nuint ciphertextLen, byte[] tag16, out nint plaintextOut, out nuint plaintextLenOut);

    [DllImport(LibraryName, EntryPoint = "crypto_ffi_opencl_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void Free(nint pointer);
}
