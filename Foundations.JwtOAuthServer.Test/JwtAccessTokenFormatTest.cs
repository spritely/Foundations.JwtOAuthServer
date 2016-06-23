// --------------------------------------------------------------------------------------------------------------------
// <copyright file="JwtAccessTokenFormatTest.cs">
//     Copyright (c) 2016. All rights reserved. Licensed under the MIT license. See LICENSE file in
//     the project root for full license information.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace Spritely.Foundations.JwtOAuthServer.Test
{
    using System;
    using NUnit.Framework;
    using Spritely.Foundations.WebApi;

    [TestFixture]
    public class JwtAccessTokenFormatTest
    {
        [Test]
        public void Constructor_throws_when_certificate_configuration_is_ambiguous()
        {
            var settings = new JwtOAuthServerSettings
            {
                AllowedClients =
                {
                    new JwtOAuthClient
                    {
                        Id = "valid_client_id",
                        Secret = "JkgHgUR3npkGFrHOXOph1R_NBtp6GikiWv_CKNt_xXU",
                        RelativeFileCertificate = new RelativeFileCertificate(),
                        StoreCertificate = new StoreCertificate()
                    }
                }
            };

            Assert.Throws<InvalidOperationException>(() => new JwtAccessTokenFormat(settings));
        }


        [Test]
        public void Constructor_throws_when_certificate_cannot_be_loaded()
        {
            var settings = new JwtOAuthServerSettings
            {
                AllowedClients =
                {
                    new JwtOAuthClient
                    {
                        Id = "valid_client_id",
                        Secret = "JkgHgUR3npkGFrHOXOph1R_NBtp6GikiWv_CKNt_xXU",
                        StoreCertificate = new StoreCertificate
                        {
                            CertificateThumbprint = "invalidthumbprint"
                        }
                    }
                }
            };

            Assert.Throws<InvalidOperationException>(() => new JwtAccessTokenFormat(settings));
        }

        [Test]
        public void Constructor_throws_when_a_client_secret_is_not_Base64UrlEncoded()
        {
            var settings = new JwtOAuthServerSettings
            {
                AllowedClients =
                {
                    new JwtOAuthClient
                    {
                        Id = "valid_client_id",
                        Secret = "invalid secret"
                    }
                }
            };

            Assert.Throws<FormatException>(() => new JwtAccessTokenFormat(settings));
        }
    }
}
