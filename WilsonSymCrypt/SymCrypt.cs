// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Runtime.InteropServices;

namespace Microsoft.IdentityModel.Tokens
{

    public static class SymCrypt
    {
        private const string DllName = "SymCrypt.dll";

        //typedef _Return_type_success_( return == SYMCRYPT_NO_ERROR ) enum {
        //    SYMCRYPT_NO_ERROR = 0,
        //    SYMCRYPT_UNUSED = 0x8000, // Start our error codes here so they're easier to distinguish
        //    SYMCRYPT_WRONG_KEY_SIZE, 32769
        //    SYMCRYPT_WRONG_BLOCK_SIZE,
        //    SYMCRYPT_WRONG_DATA_SIZE,
        //    SYMCRYPT_WRONG_NONCE_SIZE,
        //    SYMCRYPT_WRONG_TAG_SIZE,
        //    SYMCRYPT_WRONG_ITERATION_COUNT,
        //    SYMCRYPT_AUTHENTICATION_FAILURE,
        //    SYMCRYPT_EXTERNAL_FAILURE,
        //    SYMCRYPT_FIPS_FAILURE,
        //    SYMCRYPT_HARDWARE_FAILURE,
        //    SYMCRYPT_NOT_IMPLEMENTED,
        //    SYMCRYPT_INVALID_BLOB,
        //    SYMCRYPT_BUFFER_TOO_SMALL,
        //    SYMCRYPT_INVALID_ARGUMENT, // 0x800E, 32782
        //    SYMCRYPT_MEMORY_ALLOCATION_FAILURE,
        //    SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE,
        //    SYMCRYPT_INCOMPATIBLE_FORMAT,
        //    SYMCRYPT_VALUE_TOO_LARGE,
        //    SYMCRYPT_SESSION_REPLAY_FAILURE,
        //    SYMCRYPT_HBS_NO_OTS_KEYS_LEFT,
        //    SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH,
        //}
        //SYMCRYPT_ERROR;

        #region HMAC
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SymCryptHmacSha256(
            byte[] expandedKey,
            byte[] pbData,
            int cbData,
            byte[] pbResult);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SymCryptHmacSha256ExpandKey(
            out SYMCRYPT_HMAC_SHA256_EXPANDED_KEY pExpandedKey,
            byte[] pbKey,
            int cbKey);
        #endregion

        #region ML-DSA
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr SymCryptMlDsakeyAllocate(
        SYMCRYPT_MLDSA_PARAMS_ENUM mldsa_params);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SymCryptMlDsakeyFree(
            IntPtr key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsakeyGenerate(
            IntPtr key,
            uint flags);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsaSign(
            IntPtr key,
            byte[] pbData,
            long cbData,
            byte[] pbOptional,
            long cbOptional,
            uint flags,
            byte[] pbSignature,
            long pcbSignature);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsaVerify(
            IntPtr key,
            byte[] pbData,
            long cbData,
            byte[] pbOptional,
            long cbOptional,
            byte[] pbSignature,
            long pcbSignature,
            uint flags);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsaSizeofKeyFormatFromParams(
                SYMCRYPT_MLDSA_PARAMS_ENUM mldsa_params,
                SYMCRYPT_MLDSAKEY_FORMAT mlDsakeyFormat,
                ref long pcbKeyFormat);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsakeyGetValue(
            IntPtr key,
            byte[] pbDst,
            long cbDst,
            SYMCRYPT_MLDSAKEY_FORMAT mlDsakeyFormat,
            uint flags);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsakeySetValue(
            byte[] pbKey,
            long cbKey,
            SYMCRYPT_MLDSAKEY_FORMAT mlDsaKeyFormat,
            uint flags,
            IntPtr ppkMlDsakey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsaSizeofSignatureFromParams(
            SYMCRYPT_MLDSA_PARAMS_ENUM mldsa_params,
            ref int pcbSignature);
        #endregion

        #region structs
        #endregion
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYMCRYPT_HMAC_SHA256_EXPANDED_KEY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public ulong[] innerState;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public ulong[] outerState;

        public ulong magic;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYMCRYPT_MLDSA_KEY
    {
        // Define the fields of the key structure as needed
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct SYMCRYPT_MLDSA_STRUCT
    {
        public int nBitsOfP;
        public int nBitsOfQ;
        public int nBitsOfSeed;
        public int fipsStandard;
    }

    public enum SYMCRYPT_MLDSAKEY_FORMAT
    {
        SYMCRYPT_MLDSAKEY_FORMAT_NULL = 0,
        SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED = 1,
        SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY = 2,
        SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY = 3
    }

    public enum SYMCRYPT_MLDSA_PARAMS_ENUM
    {
        SYMCRYPT_MLDSA_PARAMS_NULL = 0,
        SYMCRYPT_MLDSA_PARAMS_MLDSA44 = 1,
        SYMCRYPT_MLDSA_PARAMS_MLDSA65 = 2,
        SYMCRYPT_MLDSA_PARAMS_MLDSA87 = 3,
    }
}
