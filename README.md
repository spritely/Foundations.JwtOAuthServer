# Spritely.Foundations.JwtOAuthServer
Provides a default starting point for setting up a new OAuth2 web service which includes Its.Config, Its.Log, and JWT preconfigured for key scenarios. Just add your custom authentication tied to your back end database and light up OAuth2 very easily.

This project is based on Spritely.Foundations.WebApi so be sure to check that out for questions about the basic service setup: https://github.com/spritely/Foundations.WebApi.

# Usage
Spritely.Foundations.JwtOAuthServer provides everything related to hosting the web service endpoint. The only thing you need to do is plug in your own IAuthenticator implementation:

```csharp
public interface IAuthenticator
{
    ClaimsIdentity SignIn(Credentials credentials);
}
```

Here's a simple example implementation:

```csharp
public class Authenticator : IAuthenticator
{
    private readonly IAuthRepository authRepository;

    public Authenticator(IAuthRepository authRepository)
    {
        if (authRepository == null)
        {
            throw new ArgumentNullException(nameof(authRepository));
        }

        this.authRepository = authRepository;
    }

    public ClaimsIdentity SignIn(Credentials credentials)
    {
        if (credentials == null)
        {
            throw new ArgumentNullException(nameof(credentials));
        }

        var signInResult = this.authRepository.SignIn(credentials.UserName, credentials.Password);

        var identity = new ClaimsIdentity(credentials.AuthenticationType);

        identity.AddClaim(new Claim("sub", signInResult.Username));
        identity.AddClaim(new Claim("my_claim", signInResult.SomeProperty));

        foreach (var role in signInDetails.Roles)
        {
            identity.AddClaim(new Claim(identity.RoleClaimType, role));
        }

        return identity;
    }
}
```

Now you just need to register the authenticator in the dependency injection container and start up the server as follows:

```csharp
public class Startup
{
    private static void InitializeContainer(Container container)
    {
        // Your repository might need more setup...
        container.Register<IAuthRepository, MyAuthRepository>();
        container.Register<IAuthenticator, Authenticator>();
    }

    public static void Configuration(IAppBuilder app)
    {
        Start.Initialize();

        // This registers a method to be called when the container is initialized
        app.UseContainerInitializer(InitializeContainer)
            // Setup Its.Config - see Spritely.Foundations.WebApi for more
            .UseSettingsContainerInitializer()
              
            // Setup the dependency injection container for JWT OAuth server
            .UseJwtOAuthServerContainerInitializer()
              
            // Start the JWT OAuth Server
            .UseJwtOAuthServer();
    }

    public static void Main()
    {
        Start.Console<Startup>();
    }
}
```
  
Nearly done. We need the App.config and HostingSettings.json from https://github.com/spritely/Foundations.WebApi and a JwtOAuthServerSettings.json similar to:
  
```json
{
    "accessTokenExpireTimeSpan": "1.00:00:00",
    "issuer": "https://auth.mydomain.com",
    "allowedClients": [
        {
            "id": "my.client.id.typically.mydomain.com",
            "secret": "JkgHgUR3npkGFrHOXOph1R_NBtp6GikiWv_CKNt_xXU"
        }
    ]
}
```

Each allowedClient also supports using an X509 certificate to encrypt the JWT tokens. To enable use one of the following two options depending on if you want to load the certificate from a file:

```json
{
    "accessTokenExpireTimeSpan": "1.00:00:00",
    "issuer": "https://auth.mydomain.com",
    "allowedClients": [
        {
            "id": "my.client.id.typically.mydomain.com",
            "secret": "JkgHgUR3npkGFrHOXOph1R_NBtp6GikiWv_CKNt_xXU",
            "relativeFileCertificate": {
                "relativeFilePath": "/Certificates/MyCertificate.pfx",
                "password": "my-password",
                "keyStorageFlags": "machineKeySet, exportable"
            }
        }
    ]
}
```

or from the Windows store (but you cannot use both for a single client):

```json
{
    "accessTokenExpireTimeSpan": "1.00:00:00",
    "issuer": "https://auth.mydomain.com",
    "allowedClients": [
        {
            "id": "my.client.id.typically.mydomain.com",
            "secret": "JkgHgUR3npkGFrHOXOph1R_NBtp6GikiWv_CKNt_xXU",
            "storeCertificate": {
                "certificateThumbprint": "aa1234...."
            }
        }
    ]
}
```

That's it. Start the app and make an OAuth2 call to https://auth.mydomain.com/token with the given client id and it will return a JWT token with the claims you provided in your Authenticator.