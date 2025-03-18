// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.PQC.MetaData.Tests
{
    /// <summary>
    /// This class tests integration with SymCrypt
    /// </summary>
    public class MetadataTests
    {
        /// <summary>
        /// Parses a JsonWebKeySet with MLDSA, RSA, ECD keys and X509Certs.
        /// This is the first step in reading OpenIdConnectConfiguration with ML-DSA keys.
        /// </summary>
        [Fact]
        public void ReadJsonWebKeySet()
        {
            string metadata = $$"""
            {
                "keys" : [
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "JDNa_4i4r7FgigL3sHIlI3xV-IU",
                        "x5t": "JDNa_4i4r7FgigL3sHIlI3xV-IU",
                        "n": "iQ745_U-vjkxPblaw6phBpe08fC42mpcrS4pcr15HiyZQyQV-BFcEVyLwPdsz3ulMRN7OB_UMfCcPBHqOjguejoab6hyJFVVMw_epP4a3SpQN9qaCbnqaSxgSGiqSq663g3TjsF_Wu1m9L41eNoF6Yvh5kULMd6lqjY0LPO5ZZxaQFLtIHahoJKMvYy1BTS0VYcNsXTjxkgUEL6Vc8GV5vaClbnY3VA2hLbXC1SGJWjVGdYXhkuck2tHr58u87MPEaQ33C6YfyISZKsdumF5bTCcIH75jjC3WbMVOLgWg5w0MSiHOFyI76Ihxbb0nRicEuao0WzO9AS7HJ7L24FHFQ",
                        "e": "AQAB",
                        "x5c": [
                            "MIIC/jCCAeagAwIBAgIJAMLglrQkJ8UDMA0GCSqGSIb3DQEBCwUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMjUwMjIxMDAzMjA1WhcNMzAwMjIxMDAzMjA1WjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiQ745/U+vjkxPblaw6phBpe08fC42mpcrS4pcr15HiyZQyQV+BFcEVyLwPdsz3ulMRN7OB/UMfCcPBHqOjguejoab6hyJFVVMw/epP4a3SpQN9qaCbnqaSxgSGiqSq663g3TjsF/Wu1m9L41eNoF6Yvh5kULMd6lqjY0LPO5ZZxaQFLtIHahoJKMvYy1BTS0VYcNsXTjxkgUEL6Vc8GV5vaClbnY3VA2hLbXC1SGJWjVGdYXhkuck2tHr58u87MPEaQ33C6YfyISZKsdumF5bTCcIH75jjC3WbMVOLgWg5w0MSiHOFyI76Ihxbb0nRicEuao0WzO9AS7HJ7L24FHFQIDAQABoyEwHzAdBgNVHQ4EFgQURTob3mIZ17u3KJWvDGiLEqCWubswDQYJKoZIhvcNAQELBQADggEBADoUtCzQyCV6eX+rNqthreUzRW3zL/Ybjmwd8YefQgsV0Z4k0qfbYH+21mbP4COKADLBI4Gs8tDeeBa7v4/Vs65c4ao8M1rNfIM554cTTJd5eiMeML1rzfRePbMzoj3kWi6heXcHSov6e6nip3BOcvPmbJ3cj164OkrbypdwKCdHzUd2oCUS92EA472MxkxCPSw+TcAt6/pWuTYoPJM6SwCcCGg7O2hIVaG9LYHJ65ruFeQsjsiwPPCPMolVKji8GhyPtzn+5vlN8NGoBi+dc1qpl1TQJF/5B7PZ3eqHTPPexirezjCjeuenrS9oO/xYXPvpQuwNs47RgGNXwsaULdA="
                        ],
                        "cloud_instance_name": "microsoftonline.com",
                        "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"
                    }
                ]
            }
            """;

            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(metadata);

        }
    }
}
