// --------------------------------------------------------------------------------------------------------------------
// <copyright file="AppBuilderExtensions.cs">
//     Copyright (c) 2017. All rights reserved. Licensed under the MIT license. See LICENSE file in
//     the project root for full license information.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace Spritely.Foundations.JwtOAuthServer
{
    using System;
    using Microsoft.Owin.Security.OAuth;
    using Owin;
    using Spritely.Foundations.WebApi;

    /// <summary>
    /// Extensions for IAppBuilder
    /// </summary>
    public static class AppBuilderExtensions
    {
        /// <summary>
        /// Adds JWT OAuth server container initializer to the application.
        /// </summary>
        /// <param name="app">The application.</param>
        /// <returns>The modified application.</returns>
        public static IAppBuilder UseJwtOAuthServerContainerInitializer(this IAppBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            InitializeContainer initializeContainer =
                container =>
                {
                    container.Register<IOAuthAuthorizationServerProvider, JwtOAuthClientValidatingServerProvider>();
                };

            return app.UseContainerInitializer(initializeContainer);
        }

        /// <summary>
        /// Sets up the application to uses an JWT OAuth authorization server.
        /// </summary>
        /// <param name="app">The application.</param>
        /// <returns>The modified application.</returns>
        public static IAppBuilder UseJwtOAuthServer(this IAppBuilder app)
        {
            var serverOptions = app.GetInstance<JwtOAuthServerOptions>();
            return app.UseOAuthAuthorizationServer(serverOptions);
        }
    }
}
