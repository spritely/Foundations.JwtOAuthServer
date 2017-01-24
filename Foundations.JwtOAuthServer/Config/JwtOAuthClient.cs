// --------------------------------------------------------------------------------------------------------------------
// <copyright file="JwtOAuthClient.cs">
//     Copyright (c) 2017. All rights reserved. Licensed under the MIT license. See LICENSE file in
//     the project root for full license information.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace Spritely.Foundations.JwtOAuthServer
{
    using Spritely.Foundations.WebApi;

    /// <summary>
    /// Describes a JWT OAuth client.
    /// </summary>
    public class JwtOAuthClient
    {
        /// <summary>
        /// Gets or sets the identifier.
        /// </summary>
        /// <value>The identifier.</value>
        public string Id { get; set; }

        /// <summary>
        /// Gets or sets the base 64 url encoded secret shared with this client.
        /// </summary>
        /// <value>The secret.</value>
        public string Secret { get; set; }

        /// <summary>
        /// Gets or sets the relative file certificate.
        /// </summary>
        /// <value>
        /// The relative file certificate.
        /// </value>
        public RelativeFileCertificate RelativeFileCertificate { get; set; }

        /// <summary>
        /// Gets or sets the store certificate.
        /// </summary>
        /// <value>
        /// The store certificate.
        /// </value>
        public StoreCertificate StoreCertificate { get; set; }
    }
}
