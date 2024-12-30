package config

import scala.concurrent.duration.Duration

final case class AuthleteConfig(
    host: String,
    port: Int,
    apiKey: String,
    apiSecret: String,
    requestTimeout: Duration
)
