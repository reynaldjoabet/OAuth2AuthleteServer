package config

import scala.concurrent.duration.Duration

import com.authlete.common.conf.AuthleteConfiguration

final case class AuthleteConfig(
    apiVersion: Int,
    apiKey: String, // same as serviceId
    apiSecret: String,
    requestTimeout: Duration,
    auth: String,
    isDpopEnabled: Boolean,
    baseUrl: String,          // https://api.authlete.com
    dpopKey: String,          // Get the public/private key pair used for DPoP signatures in JWK format.
    clientCertificate: String // Get the certificate used for MTLS bound access tokens in PEM format.
)
