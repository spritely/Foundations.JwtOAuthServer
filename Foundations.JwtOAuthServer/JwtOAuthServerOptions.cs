// --------------------------------------------------------------------------------------------------------------------
// <copyright file="JwtOAuthServerOptions.cs">
//     Copyright (c) 2017. All rights reserved. Licensed under the MIT license. See LICENSE file in
//     the project root for full license information.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace Spritely.Foundations.JwtOAuthServer
{
    using System;
    using Microsoft.Owin.Security.OAuth;

    /// <summary>
    /// Provides a set of options for a JWT OAuth authorization server.
    /// </summary>
    /// <seealso cref="Microsoft.Owin.Security.OAuth.OAuthAuthorizationServerOptions"/>
    public class JwtOAuthServerOptions : OAuthAuthorizationServerOptions
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JwtOAuthServerOptions"/> class.
        /// </summary>
        /// <param name="serverSettings">The server settings.</param>
        /// <param name="provider">The provider.</param>
        /// <param name="jwtAccessTokenFormat">The JWT format.</param>
        public JwtOAuthServerOptions(
            JwtOAuthServerSettings serverSettings,
            IOAuthAuthorizationServerProvider provider,
            JwtAccessTokenFormat jwtAccessTokenFormat)
        {
            if (serverSettings == null)
            {
                throw new ArgumentNullException(nameof(serverSettings));
            }

            if (provider == null)
            {
                throw new ArgumentNullException(nameof(provider));
            }

            if (jwtAccessTokenFormat == null)
            {
                throw new ArgumentNullException(nameof(jwtAccessTokenFormat));
            }

            AuthenticationType = "JWT";
            AllowInsecureHttp = serverSettings.AllowInsecureHttp;
            AccessTokenExpireTimeSpan = serverSettings.AccessTokenExpireTimeSpan;
            TokenEndpointPath = serverSettings.TokenEndpointPath;

            Provider = provider;
            AccessTokenFormat = jwtAccessTokenFormat;
        }
    }
}
