package object domain {

//Json Web Signature Algorithm
  enum JWSAlg(value: String) {

    case JWSAlg_NONE  extends JWSAlg("NONE")
    case JWSAlg_HS256 extends JWSAlg("HS256")
    case JWSAlg_HS384 extends JWSAlg("HS384")
    case JWSAlg_HS512 extends JWSAlg("HS512")
    case JWSAlg_RS256 extends JWSAlg("RS256")
    case JWSAlg_RS384 extends JWSAlg("RS384")
    case JWSAlg_RS512 extends JWSAlg("RS512")
    case JWSAlg_ES256 extends JWSAlg("ES256") // ECDSA (Elliptic Curve Digital Signature Algorithm)
    case JWSAlg_ES384 extends JWSAlg("ES384") // Elliptic Curve Digital Signature Algorithm (ECDSA) with the P-384 curve and SHA-384 hash function
    case JWSAlg_ES512 extends JWSAlg("ES512")
    case JWSAlg_PS256 extends JWSAlg("PS256")
    case JWSAlg_PS384 extends JWSAlg("PS384")
    case JWSAlg_PS512 extends JWSAlg("PS512")

  }

  enum ServiceProfile(value: String) {

    case ServiceProfile_FAPI         extends ServiceProfile("FAPI")
    case ServiceProfile_OPEN_BANKING extends ServiceProfile("OPEN_BANKING")

  }

  enum ResponseMode(value: String) {

    case ResponseMode_QUERY         extends ResponseMode("QUERY")
    case ResponseMode_FRAGMENT      extends ResponseMode("FRAGMENT")
    case ResponseMode_FORM_POST     extends ResponseMode("FORM_POST")
    case ResponseMode_JWT           extends ResponseMode("JWT")
    case ResponseMode_QUERY_JWT     extends ResponseMode("QUERY_JWT")
    case ResponseMode_FRAGMENT_JWT  extends ResponseMode("FRAGMENT_JWT")
    case ResponseMode_FORM_POST_JWT extends ResponseMode("FORM_POST_JWT")

  }

  enum JWEEnc(value: String) {

    case JWEEnc_A128CBC_HS256 extends JWEEnc("A128CBC_HS256")
    case JWEEnc_A192CBC_HS384 extends JWEEnc("A192CBC_HS384")
    case JWEEnc_A256CBC_HS512 extends JWEEnc("A256CBC_HS512")
    case JWEEnc_A128GCM       extends JWEEnc("A128GCM")
    case JWEEnc_A192GCM       extends JWEEnc("A192GCM")
    case JWEEnc_A256GCM       extends JWEEnc("A256GCM")

    override def toString(): String = value

  }

  enum JWEAlg(value: String) {

    case JWEAlg_RSA1_5             extends JWEAlg("RSA1_5")
    case JWEAlg_RSA_OAEP           extends JWEAlg("RSA_OAEP")
    case JWEAlg_RSA_OAEP_256       extends JWEAlg("RSA_OAEP_256")
    case JWEAlg_A128KW             extends JWEAlg("A128KW")
    case JWEAlg_A192KW             extends JWEAlg("A192KW")
    case JWEAlg_A256KW             extends JWEAlg("A256KW")
    case JWEAlg_DIR                extends JWEAlg("DIR")
    case JWEAlg_ECDH_ES            extends JWEAlg("ECDH_ES")
    case JWEAlg_ECDH_ES_A128KW     extends JWEAlg("ECDH_ES_A128KW")
    case JWEAlg_ECDH_ES_A192KW     extends JWEAlg("ECDH_ES_A192KW")
    case JWEAlg_ECDH_ES_A256KW     extends JWEAlg("ECDH_ES_A256KW")
    case JWEAlg_A128GCMKW          extends JWEAlg("A128GCMKW")
    case JWEAlg_A192GCMKW          extends JWEAlg("A192GCMKW")
    case JWEAlg_A256GCMKW          extends JWEAlg("A256GCMKW")
    case JWEAlg_PBES2_HS256_A128KW extends JWEAlg("PBES2_HS256_A128KW")
    case JWEAlg_PBES2_HS384_A192KW extends JWEAlg("PBES2_HS384_A192KW")
    case JWEAlg_PBES2_HS512_A256KW extends JWEAlg("PBES2_HS512_A256KW")

    override def toString(): String = value

  }

  enum GrantType(name: String) derives CanEqual {

    case AuthorizationCodeGrantType extends GrantType("authorization_code")
    case ClientCredentialsGrantType extends GrantType("client_credentials")
    case ImplicitGrantType          extends GrantType("implicit")
    case PasswordGrantType          extends GrantType("password")
    case RefreshTokenGrantType      extends GrantType("refresh_token")
    case JWTBearerGrantType         extends GrantType("urn:ietf:params:oauth:grant-type:jwt-bearer")
    case TokenExchangeGrantType     extends GrantType("urn:ietf:params:oauth:grant-type:token-exchange")
    case DeviceGrantType            extends GrantType("urn:ietf:params:oauth:grant-type:device_code")
    case CIBAGrantType              extends GrantType("urn:openid:params:grant-type:ciba")

    override def toString(): String = name

  }

  enum Display(value: String) {

    case Display_PAGE  extends Display("PAGE")
    case Display_POPUP extends Display("POPUP")
    case Display_TOUCH extends Display("TOUCH")
    case Display_WAP   extends Display("WAP")
    override def toString(): String = value

  }

  enum Algorithm(val value: String) {

    case RS256 extends Algorithm("RS256")
    case RS384 extends Algorithm("RS384")
    case RS512 extends Algorithm("RS512")
    case ES256 extends Algorithm("ES256")
    case ES384 extends Algorithm("ES384")
    case ES512 extends Algorithm("ES512")
    case PS256 extends Algorithm("PS256")
    case PS384 extends Algorithm("PS384")
    case PS512 extends Algorithm("PS512")

    override def toString(): String = value

  }

// Values for the cnf claim
//CanEqual[-L, -R] A marker trait indicating that values of type L can be compared to values of type R
  enum ConfirmationMethod(value: String) derives CanEqual {

    /// JSON web key
    case JsonWebKey extends ConfirmationMethod("jwk")
    /// JSON web key thumbprint
    case JwkThumbprint extends ConfirmationMethod("jkt")
    /// X.509 certificate thumbprint using SHA256
    case X509ThumbprintSha256 extends ConfirmationMethod("x5t#S256")

    override def toString(): String = value

  }

//pkh -Proof Key for Holder

  enum ClientAuthMethod(value: String) {

    case ClientAuthMethod_NONE                extends ClientAuthMethod("NONE")
    case ClientAuthMethod_CLIENT_SECRET_BASIC extends ClientAuthMethod("CLIENT_SECRET_BASIC")
    case ClientAuthMethod_CLIENT_SECRET_POST  extends ClientAuthMethod("CLIENT_SECRET_POST")
    case ClientAuthMethod_CLIENT_SECRET_JWT   extends ClientAuthMethod("CLIENT_SECRET_JWT")
    case ClientAuthMethod_PRIVATE_KEY_JWT     extends ClientAuthMethod("PRIVATE_KEY_JWT")
    case ClientAuthMethod_TLS_CLIENT_AUTH     extends ClientAuthMethod("TLS_CLIENT_AUTH")

    case ClientAuthMethod_SELF_SIGNED_TLS_CLIENT_AUTH
        extends ClientAuthMethod("SELF_SIGNED_TLS_CLIENT_AUTH")

  }

}
