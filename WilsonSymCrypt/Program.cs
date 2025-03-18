// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

internal class Program
{
    private static void Main(string[] args)
    {
        SymCryptTests.SignAndVerifyWithMlDsa();
    }
}

/// <summary>
/// This class tests integration with SymCrypt
/// </summary>
public class SymCryptTests
{
    public static void SignVerifyWithHmac()
    {
        byte[] data = Encoding.UTF8.GetBytes("Hello, SymCrypt!");
        try
        {
            int signatureLength = 32;
            byte[] symCryptHmacSignature = new byte[signatureLength];
            byte[] key = new byte[32];
            SYMCRYPT_HMAC_SHA256_EXPANDED_KEY expandedKey;
            SymCrypt.SymCryptHmacSha256ExpandKey(out expandedKey, key, key.Length);
            byte[] mldsaKey = Utils.StructToByteArray(expandedKey);

            SymCrypt.SymCryptHmacSha256(
                mldsaKey,
                data,
                data.Length,
                symCryptHmacSignature);

            Aes aes = Aes.Create();
            aes.Key = key;
            HMACSHA256 hmac = new HMACSHA256(aes.Key);
            byte[] hmacSignature = hmac.ComputeHash(data);

            if (!Utils.AreEqual(hmacSignature, symCryptHmacSignature))
                Console.WriteLine("HMAC and SymCrypt DO NOT not have the same signature.");
            else
                Console.WriteLine("HMAC and SymCrypt have the SAME signature.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    public static void SignAndVerifyWithMlDsa()
    {
        SYMCRYPT_MLDSA_STRUCT mldsa_params = new SYMCRYPT_MLDSA_STRUCT
        {
            nBitsOfP = 2048,
            nBitsOfQ = 256,
            nBitsOfSeed = 256,
            fipsStandard = 2 // SYMCRYPT_DLGROUP_FIPS_186_3
        };

        MldsaSecurityKey mldsaKey = MldsaSecurityKey.CreateKey(SYMCRYPT_MLDSA_PARAMS_ENUM.SYMCRYPT_MLDSA_PARAMS_MLDSA44);

        byte[] data = Encoding.UTF8.GetBytes("Hello, SymCrypt!");
        mldsaKey.SignData(data, out byte[] signature);
        bool isValid = mldsaKey.VerifyData(data, signature);
        mldsaKey.Dispose();
    }
}

