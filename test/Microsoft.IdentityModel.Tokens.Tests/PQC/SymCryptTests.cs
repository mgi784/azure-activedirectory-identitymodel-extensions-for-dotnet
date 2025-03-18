// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.PQC.SignVerify.Tests
{
    /// <summary>
    /// This class tests integration with SymCrypt
    /// </summary>
    public class SymCryptTests
    {
        /// <summary>
        /// Compares that Dotnet HMAC and SymCrypt have the same signature
        /// </summary>
        [Fact]
        public void CompareHmacSymCryptDotNetTest()
        {
            byte[] data = Encoding.UTF8.GetBytes("Hello, SymCrypt!");
            try
            {
                int signatureLength = 32;
                byte[] symCryptHmacSignature = new byte[signatureLength];
                byte[] key = new byte[32];
                SYMCRYPT_HMAC_SHA256_EXPANDED_KEY expandedKey;
                SymCrypt.SymCryptHmacSha256ExpandKey(out expandedKey, key, key.Length);
                byte[] mldsaKey = SymCryptUtils.StructToByteArray(expandedKey);

                SymCrypt.SymCryptHmacSha256(
                    mldsaKey,
                    data,
                    data.Length,
                    symCryptHmacSignature);

                Aes aes = Aes.Create();
                aes.Key = key;
                HMACSHA256 hmac = new HMACSHA256(aes.Key);
                byte[] hmacSignature = hmac.ComputeHash(data);

                if (!SymCryptUtils.AreEqual(hmacSignature, symCryptHmacSignature))
                    Console.WriteLine("HMAC and SymCrypt DO NOT not have the same signature.");
                else
                    Console.WriteLine("HMAC and SymCrypt have the SAME signature.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Signs and verifies data using ML-DSA
        /// </summary>
        [Fact]
        public void SignAndVerifyWithMlDsaTest()
        {
            MldsaSecurityKey mldsaKey = MldsaSecurityKey.CreateKey(SYMCRYPT_MLDSA_PARAMS_ENUM.MLDSA44);

            byte[] data = Encoding.UTF8.GetBytes("Hello, SymCrypt!");
            mldsaKey.SignData(data, out byte[] signature);
            bool isValid = mldsaKey.VerifyData(data, signature);
            mldsaKey.Dispose();
        }
    }
}
