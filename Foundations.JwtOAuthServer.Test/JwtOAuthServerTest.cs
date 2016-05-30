﻿// --------------------------------------------------------------------------------------------------------------------
// <copyright file="JwtOAuthServerTest.cs">
//     Copyright (c) 2016. All rights reserved. Licensed under the MIT license. See LICENSE file in
//     the project root for full license information.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace Spritely.Foundations.JwtOAuthServer.Test
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.Owin.Testing;
    using NSubstitute;
    using NSubstitute.ExceptionExtensions;
    using NUnit.Framework;
    using Spritely.Foundations.WebApi;

    [TestFixture]
    public class JwtOAuthServerTest
    {
        [Test]
        public async Task Token_requests_with_no_client_id_are_rejected()
        {
            var substitutes = new Substitutes();

            using (var server = CreateTestServerWith(substitutes.InitializeContainer))
            {
                var response = await server.CreateRequest("/token").GetAsync();

                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            }
        }

        [Test]
        public async Task Token_requests_with_an_invalid_client_id_are_rejected()
        {
            var substitutes = new Substitutes();
            substitutes.LoginForm["client_id"] = "invalid_client_id";

            using (var server = CreateTestServerWith(substitutes.InitializeContainer))
            {
                var response = await server.CreateRequest("/token").PostFormAsync(substitutes.LoginForm);

                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            }
        }

        [Test]
        public async Task Token_requests_with_a_valid_client_id_are_accepted()
        {
            var substitutes = new Substitutes();
            substitutes.Authenticator.SignIn(Arg.Any<Credentials>()).Returns(new ClaimsIdentity());

            using (var server = CreateTestServerWith(substitutes.InitializeContainer))
            {
                var response = await server.CreateRequest("/token").PostFormAsync(substitutes.LoginForm);

                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            }
        }

        [Test]
        public async Task Authenticator_recieves_credentials_supplied_to_service()
        {
            var substitutes = new Substitutes();
            substitutes.LoginForm["username"] = "testuser@mydomain.com";
            substitutes.LoginForm["password"] = "50m3P@ssw0rd";

            using (var server = CreateTestServerWith(substitutes.InitializeContainer))
            {
                await server.CreateRequest("/token").PostFormAsync(substitutes.LoginForm);
            }

            substitutes.Authenticator.Received().SignIn(Arg.Is<Credentials>(
                c => c.UserName == "testuser@mydomain.com" && c.Password == "50m3P@ssw0rd" && c.AuthenticationType == "JWT"));
        }

        [Test]
        public async Task Token_response_contains_invalid_grant_when_authenticator_returns_null_identity()
        {
            var substitutes = new Substitutes();

            using (var server = CreateTestServerWith(substitutes.InitializeContainer))
            {
                var response = await server.CreateRequest("/token").PostFormAsync(substitutes.LoginForm);
                var content = await response.Content.ReadAsStringAsync();

                Assert.That(content, Contains.Substring(@"""error"":""invalid_grant"""));
            }
        }

        [Test]
        public async Task Token_response_contains_invalid_grant_when_authenticator_throws_an_exception()
        {
            var substitutes = new Substitutes();
            substitutes.Authenticator.SignIn(Arg.Any<Credentials>())
                .ThrowsForAnyArgs(new ApplicationException("This is a test"));

            using (var server = CreateTestServerWith(substitutes.InitializeContainer))
            {
                var response = await server.CreateRequest("/token").PostFormAsync(substitutes.LoginForm);
                var content = await response.Content.ReadAsStringAsync();

                Assert.That(content, Contains.Substring(@"""error"":""invalid_grant"""));
                Assert.That(content, Contains.Substring(@"""error_description"":""This is a test"""));
            }
        }

        [Test]
        public async Task Token_response_contains_token_when_authenticator_returns_an_identity()
        {
            var substitutes = new Substitutes();
            substitutes.Authenticator.SignIn(Arg.Any<Credentials>()).Returns(new ClaimsIdentity());

            using (var server = CreateTestServerWith(substitutes.InitializeContainer))
            {
                var response = await server.CreateRequest("/token").PostFormAsync(substitutes.LoginForm);
                var content = await response.Content.ReadAsStringAsync();

                Assert.That(content, Contains.Substring(@"""access_token"":"));
                Assert.That(content, Contains.Substring(@"""token_type"":""bearer"""));
            }
        }

        [Test]
        public async Task Token_response_contains_expected_expires_in()
        {
            var substitutes = new Substitutes();
            substitutes.ServerSettings.AccessTokenExpireTimeSpan = TimeSpan.FromSeconds(22);
            substitutes.Authenticator.SignIn(Arg.Any<Credentials>()).Returns(new ClaimsIdentity());

            using (var server = CreateTestServerWith(substitutes.InitializeContainer))
            {
                var response = await server.CreateRequest("/token").PostFormAsync(substitutes.LoginForm);
                var content = await response.Content.ReadAsStringAsync();

                Assert.That(content, Contains.Substring(@"""expires_in"":21"));
            }
        }

        private class Substitutes
        {
            public JwtOAuthServerSettings ServerSettings { get; } = new JwtOAuthServerSettings();

            public IAuthenticator Authenticator { get; } = Substitute.For<IAuthenticator>();

            public IDictionary<string, string> LoginForm { get; } = new Dictionary<string, string>
            {
                {"username", "username"},
                {"password", "password"},
                {"grant_type", "password"},
                {"client_id", "valid_client_id"}
            };

            public InitializeContainer InitializeContainer
            {
                get
                {
                    return c =>
                    {
                        c.Register(() => ServerSettings);
                        c.Register(() => Authenticator);
                    };
                }
            }

            public Substitutes()
            {
                ServerSettings.AllowInsecureHttp = true;
                ServerSettings.AllowedClients.Add(new JwtOAuthClient { Id = "valid_client_id", Secret = "JkgHgUR3npkGFrHOXOph1R_NBtp6GikiWv_CKNt_xXU" });
            }
        }

        private static TestServer CreateTestServerWith(InitializeContainer initializeContainer)
        {
            var server = TestServer.Create(
                app =>
                {
                    Start.Initialize();

                    app.UseSettingsContainerInitializer()
                        .UseJwtOAuthServerContainerInitializer()
                        .UseContainerInitializer(initializeContainer)
                        .UseJwtOAuthServer();
                });

            return server;
        }
    }

    internal static class TestServerExtensions
    {
        public static async Task<HttpResponseMessage> PostFormAsync(this RequestBuilder request, IEnumerable<KeyValuePair<string, string>> formValues)
        {
            var response = await request
                .AddHeader("Content-Type", "application/x-www-form-urlencoded")
                .And(r =>
                {
                    r.Content = new FormUrlEncodedContent(formValues);
                })
                .PostAsync();

            return response;
        }
    }
}
