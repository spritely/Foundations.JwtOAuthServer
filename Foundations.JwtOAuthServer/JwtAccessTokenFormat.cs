// --------------------------------------------------------------------------------------------------------------------
// <copyright file="JwtAccessTokenFormat.cs">
//     Copyright (c) 2016. All rights reserved. Licensed under the MIT license. See LICENSE file in
//     the project root for full license information.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace Spritely.Foundations.JwtOAuthServer
{
    using System;
    using System.Globalization;
    using System.IdentityModel.Tokens;
    using System.Linq;
    using System.Security.Cryptography;
    using Jose;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataHandler.Encoder;
    using Spritely.Foundations.WebApi;

    /// <summary>
    /// Formats an authentication ticket as a JSON Web token.
    /// </summary>
    public class JwtAccessTokenFormat : ISecureDataFormat<AuthenticationTicket>
    {
        public const string HmacSha512Signature = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
        public const string Sha512Digest = "http://www.w3.org/2001/04/xmlenc#sha512";

        private readonly JwtOAuthServerSettings serverSettings;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtAccessTokenFormat"/> class.
        /// </summary>
        /// <param name="serverSettings">The server settings.</param>
        /// <exception cref="System.ArgumentNullException">If any arguments are null.</exception>
        public JwtAccessTokenFormat(JwtOAuthServerSettings serverSettings)
        {
            if (serverSettings == null)
            {
                throw new ArgumentNullException(nameof(serverSettings));
            }

            this.serverSettings = serverSettings;
        }

        /// <summary>
        /// Protects the specified data.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>A JWT token.</returns>
        /// <exception cref="ArgumentNullException">If data is null.</exception>
        /// <exception cref="InvalidOperationException">
        /// If AuthenticationTicket.Properties does not include audience.
        /// </exception>
        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var clientId = data.Properties.Dictionary.ContainsKey("audience")
                ? data.Properties.Dictionary["audience"]
                : null;

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new InvalidOperationException(Messages.Exception_JwtAccessTokenFormat_NoAudience);
            }

            var client = serverSettings.AllowedClients.FirstOrDefault(c => c.Id == clientId);
            if (client == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture,
                    Messages.Exception_JwtAccessTokenFormat_InvalidClientId, clientId));
            }

            if (client.RelativeFileCertificate != null && client.StoreCertificate != null)
            {
                throw new InvalidOperationException(Messages.Exception_JwtAccessTokenFormat_MultipleCertificateOptionsProvided);
            }

            var certificateFetcher =
                client.RelativeFileCertificate != null
                    ? new FileCertificateFetcher(client.RelativeFileCertificate)
                    : client.StoreCertificate != null
                        ? new StoreByThumbprintCertificateFetcher(client.StoreCertificate)
                        : null as ICertificateFetcher;

            var securityKey = TextEncodings.Base64Url.Decode(client.Secret);

            var issued = data.Properties.IssuedUtc?.UtcDateTime;
            var expires = data.Properties.ExpiresUtc?.UtcDateTime;
            var signingCredentials = new SigningCredentials(
                new InMemorySymmetricSecurityKey(securityKey),
                HmacSha512Signature,
                Sha512Digest);

            var token = new JwtSecurityToken(serverSettings.Issuer ?? string.Empty, clientId, data.Identity.Claims, issued, expires, signingCredentials);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(token);

            var publicKey = certificateFetcher?.Fetch()?.PublicKey.Key as RSACryptoServiceProvider;

            var finalJwt = publicKey != null
                ? JWT.Encode(jwt, publicKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM, JweCompression.DEF)
                : jwt;

            return finalJwt;
        }

        /// <summary>
        /// Unprotects the specified protected text.
        /// </summary>
        /// <param name="protectedText">The protected text.</param>
        /// <returns>Nothing - always throws.</returns>
        /// <exception cref="System.NotImplementedException">Always thrown.</exception>
        public AuthenticationTicket Unprotect(string protectedText)
        {
            throw new NotImplementedException();
        }
    }
}
