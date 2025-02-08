package domain

import java.time.LocalDate
import java.util.{Date, Locale, TimeZone}

import com.authlete.common.types.StandardClaims
import io.circe.Codec
// final case class User(
//     subject: String,
//     loginId: String,
//     password: String,
//     name: String,
//     email: String,
//     address: Address,
//     phoneNumber: String
// )

case class User(
    /**
      * The subject (unique identifier) of the user.
      */
    subject: String,
    /**
      * The login ID.
      */
    loginId: String,

    /**
      * The login password.
      */
    password: String,
    /**
      * The name of the user.
      */
    name: String,
    /**
      * The email address of the user.
      */
    email: String,
    /**
      * The postal address of the user.
      */
    address: Option[Address] = None,
    /**
      * The phone number of the user.
      */
    phoneNumber: Option[String] = None,
    /**
      * The code of the user.
      */
    code: Option[String] = None,

    // Below are standard claims as defined in https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    phoneNumberVerified: Boolean = false,
    emailVerified: Boolean = false,
    givenName: Option[String] = None,
    familyName: Option[String] = None,
    middleName: Option[String] = None,
    nickName: Option[String] = None,
    profile: Option[String] = None,
    picture: Option[String] = None,
    website: Option[String] = None,
    gender: Option[String] = None,
    zoneinfo: Option[String] = None,
    locale: Option[String] = None,
    preferredUsername: Option[String] = None,
    birthdate: Option[String] = None
    // updatedAt: Option[LocalDate] = None,

    // Custom claims
    // nationalities: List[String] = List.empty,

    // // Attributes
    // attributes: Map[String, Any] = Map.empty,

    // // Extra claims
    // extraClaims: Map[String, Any] = Map.empty
) derives Codec
