package config

final case class OidcConfig(
    authorizationEndpoint: String,
    tokenEndpoint: String,
    jwksEndpoint: String,
    logoutEndpoint: String,
    clientId: String,
    secret: String,
    redirectUri: String,
    jwtUsernameField: String,
    jwtFirstnameField: String,
    jwtLastnameField: String,
    jwtEmailField: String = "email",
    scope: String = "openid profile email",
    tenantId: Option[String] = None
)
