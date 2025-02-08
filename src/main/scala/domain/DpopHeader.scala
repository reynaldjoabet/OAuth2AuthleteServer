package domain

final case class DpopHeader(typ: String, kid: Option[String], alg: String, jwk: String)

object DpopHeader {

  /// A field with the value dpop+jwt, which explicitly types the
  /// DPoP proof JWT as recommended in Section 3.11 of [RFC8725]
  ///
  /// In case of DPoP, must always be: 'dpop+jwt'
  val typ: String = ""
  /// An identifier for a JWS asymmetric digital signature algorithm
  /// from [IANA.JOSE.ALGS]. It MUST NOT be none or an identifier for a
  /// symmetric algorithm (Message Authentication Code (MAC)).
  // val alg: JwkKeyPairAlg,
  /// Represents the public key chosen by the client in JSON Web Key
  /// (JWK) [RFC7517] format as defined in Section 4.1.3 of [RFC7515].
  /// It MUST NOT contain a private key.
  // val jwk: JWKSPublicKey= "some public key"
  val kid: Option[String] = None

}
