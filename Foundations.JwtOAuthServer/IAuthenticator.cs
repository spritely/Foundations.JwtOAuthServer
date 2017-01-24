// --------------------------------------------------------------------------------------------------------------------
// <copyright file="IAuthenticator.cs">
//     Copyright (c) 2017. All rights reserved. Licensed under the MIT license. See LICENSE file in
//     the project root for full license information.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace Spritely.Foundations.JwtOAuthServer
{
    using System.Security.Claims;

    /// <summary>
    /// Represents a class that can authenticate users.
    /// </summary>
    public interface IAuthenticator
    {
        /// <summary>
        /// Signs in a user using the specified credentials.
        /// </summary>
        /// <param name="credentials">The credentials.</param>
        /// <returns>The claims identity for the user or null.</returns>
        ClaimsIdentity SignIn(Credentials credentials);
    }
}
