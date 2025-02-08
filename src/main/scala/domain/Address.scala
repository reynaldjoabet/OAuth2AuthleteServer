package domain

import io.circe.Codec

final case class Address(
    streetAddress: String,
    locality: String,
    region: String,
    postalCode: String,
    country: String
) derives Codec
