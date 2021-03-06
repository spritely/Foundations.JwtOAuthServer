﻿// --------------------------------------------------------------------------------------------------------------------
// <copyright file="GlobalSuppressions.cs">
//     Copyright (c) 2017. All rights reserved. Licensed under the MIT license. See LICENSE file in
//     the project root for full license information.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

using System.Diagnostics.CodeAnalysis;

[assembly:
    SuppressMessage("Microsoft.Naming", "CA1703:ResourceStringsShouldBeSpelledCorrectly", MessageId = "clientid",
        Scope = "resource", Target = "Spritely.Foundations.JwtOAuthServer.Messages.resources",
        Justification = "client_id refers to a standardized OAuth property in the API.")]
[assembly:
    SuppressMessage("Style", "IDE0002:Simplify Member Access", Justification = "This is an auto-generated file.",
        Scope = "member", Target = "~P:Spritely.Foundations.JwtOAuthServer.Messages.ResourceManager")]
