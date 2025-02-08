package config

import cats.data.NonEmptySet

//import eu.timepit.refined.pureconfig.*
import eu.timepit.refined.string.Url
import eu.timepit.refined.types.net.UserPortNumber
import eu.timepit.refined.types.numeric.PosInt
import eu.timepit.refined.types.string.NonEmptyString
//import pureconfig.generic.derivation.default.*
import pureconfig.module.cats.*
import pureconfig.ConfigReader

final case class OAuth2ClientConfig(
    host: String,
    port: Int,
    realm: String,
    clientSecret: String,
    clientId: String,
    audience: String, // API identifier
    issuer: String,   // The issuer of the token. For Auth0, this is just your Auth0 domain including the URI scheme and a trailing slash.
    algorithms: Set[String],
    authorizationEndpoint: String,
    tokenEndpoint: String,
    redirectUrl: String,
    userInfoEndpoint: String,
    tokenIntrospectionUri: String,
    endSessionEndpoint: String, // Single logout (or single sign-out). The end session endpoint can be used to trigger single sign-out in the browser.
    postLogoutRedirectUris: Option[Set[String]],
    backChannelLogoutUri: Option[String] // e.g., "https://myapp.com/backchannel-logout"
)
