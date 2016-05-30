// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Credentials.cs">
//     Copyright (c) 2016. All rights reserved. Licensed under the MIT license. See LICENSE file in
//     the project root for full license information.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace Spritely.Foundations.JwtOAuthServer
{
    /// <summary>
    /// A set of credentials to use to sign in a user.
    /// </summary>
    public class Credentials
    {
        /// <summary>
        /// Gets or sets the type of the authentication that should be used when creating the ClaimsIdentity.
        /// </summary>
        /// <value>The type of the authentication.</value>
        public string AuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the username.
        /// </summary>
        /// <value>The username.</value>
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        /// <value>The password.</value>
        public string Password { get; set; }
    }
}
