import java.net.URLEncoder

import scala.language.strictEquality

import cats.effect.IO

import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.Claim
import com.auth0.jwt.JWT
import com.authlete.common.dto.CredentialDeferredParseResponse
import com.authlete.common.dto.IntrospectionResponse
import com.authlete.common.dto.Scope
import com.authlete.common.dto.TokenRequest
import io.circe.Codec
import io.circe.Decoder
import io.circe.Json
import org.http4s.Header
import org.http4s.Headers
import org.http4s.Response
import org.http4s.Status
import services.*

val m = Map("one" -> 1).++(Map("two" -> 2)).++(if (true) Map("three" -> 3) else Map.empty)

m ++ Map("two" -> 2)

m.concat(Map("two" -> 2))

m

"Hello{Name}{LastName}"

final class Student(name: String)

new Student("")

Student("")

Map(
  "name"    -> Seq("Alice"),
  "colors"  -> Seq("red", "green"),
  "choices" -> Seq("1", "3")
)

val dpopProof = ""

val header = """{
    "typ": "dpop+jwt",
    "alg": "ES256",
    "jwk":{
      "kty":"EC",
      "x":"some values",
      "y": "some values",
      "crv":"P-256"  
    }

}"""

//DPoPClaims
val payload = """{
"jwk": "public key in jwt format",
"jti":" jwt id",
"htm": "http method",
"htu":" http target url(exlude the query or url fragment)",
"iat":"issued at( in seconds)",
"nonce":"dpop-nonce issued by server",
"ath": "base64url encoded sha-256 hash access token"
}
"""

// nonce and ath are optional
"Dpop dpop token which is signed by private key "

//The confirmation
val cnf = domain.ConfirmationMethod.X509ThumbprintSha256

cnf.toString()

domain.GrantType.CIBAGrantType

domain.GrantType.TokenExchangeGrantType.ordinal

domain.GrantType.AuthorizationCodeGrantType

domain.GrantType.CIBAGrantType

domain.GrantType.ClientCredentialsGrantType

domain.GrantType.DeviceGrantType

domain.GrantType.ImplicitGrantType

domain.GrantType.JWTBearerGrantType

domain.GrantType.PasswordGrantType

domain.GrantType.RefreshTokenGrantType

domain.GrantType.TokenExchangeGrantType

domain.GrantType.TokenExchangeGrantType.toString()

/**
  * Previously, Scala had universal equality: Two values of any types could be compared with each
  * other using == and !=. This came from the fact that == and != are implemented in terms of Java’s
  * equals method, which can also compare values of any two reference types. multiversal equality is
  * an opt-in way to make universal equality safer. It uses the binary type class CanEqual to
  * indicate that values of two given types can be compared with each other.
  */

7 == 9

given h: CanEqual[Int, String] = CanEqual.derived

9 == "l"

trait Book {

  def author: String
  def title: String
  def year: Int

}

case class PrintedBook(
    author: String,
    title: String,
    year: Int,
    pages: Int
) extends Book

case class AudioBook(
    author: String,
    title: String,
    year: Int,
    lengthInMinutes: Int
) extends Book

given CanEqual[PrintedBook, PrintedBook] = CanEqual.derived
given CanEqual[AudioBook, AudioBook]     = CanEqual.derived

// [4a] comparing two printed books works as desired
val p1 = PrintedBook("1984", "George Orwell", 1961, 328)
val p2 = PrintedBook("1984", "George Orwell", 1961, 328)

p1 == p2

val pBook = PrintedBook("1984", "George Orwell", 1961, 328)
val aBook = AudioBook("1984", "George Orwell", 2006, 682)

//pBook == aBook //compiler error

// allow `PrintedBook == AudioBook`, and `AudioBook == PrintedBook`
given CanEqual[PrintedBook, AudioBook] = CanEqual.derived
given CanEqual[AudioBook, PrintedBook] = CanEqual.derived

3

val f: String = null

Option(f).isEmpty

"DPoP must be used on the token endpoint when a DPoP key thumbprint is used on the authorize endpoint."

"The DPoP proof token used on the token endpoint does not match the original used on the authorize endpoint."

"Client cannot request OpenID scopes in client credentials flow"

val token = JWT
  .create()
  .withClaim("hello", "name")
  .withClaim("mynull", null.asInstanceOf[String])
  .sign(Algorithm.HMAC256("hello"))

JWT.decode(token).getHeader()

JWT.decode(token).getClaim("hello").isNull()

JWT.decode(token).getClaim("mynull").isNull()

JWT.decode(token).getClaim("mynull").isMissing()

domain.Algorithm.valueOf("RS256") // Some(RS256)
//domain.Algorithm.valueOf("UNKNOWN") // None

val value =
  "DPoP eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiZXhhbXBsZS5jb20iLCJleHAiOjE2MjUwNDA4MDB9.FS0OpvxhNqxv5CKtVVuEs1eo7Q4FOM6lA4ohrF1fJ5U"

val tokenPrefix = "DPoP"

if (value.startsWith(tokenPrefix)) {
  Some(value.stripPrefix(tokenPrefix).trim)
} else {
  None
}

import io.circe.syntax.*

val tokenReq = TokenRequest()

tokenReq.getDpop()

tokenReq.setDpop(Some("helloooodude").orNull)

tokenReq.getDpop()
//tokenReq.asJson
tokenReq.setAccessTokenDuration(Some(12L).getOrElse(0L))

val params = Map(
  "response_type" -> "code",
  "client_id"     -> "your-client-id",
  "redirect_uri"  -> "https://your-app.com/callback",
  "scope"         -> "openid profile email",
  "state"         -> "xyz123"
).map { case (k, v) => if (v.isEmpty) (k, "") else (k, v) }

params.filter((k, v) => !v.isBlank())

val sample = Map(
  "key1" -> Seq("value1"),
  "key2" -> Seq(),
  "key3" -> Seq("value3", "value4"),
  "key4" -> Seq("")
).map { case (k, v) => if (v.isEmpty) (k, "") else (k, v.toList.head) }

sample.filter((k, v) => v.nonEmpty)

val result = Map(
  "key1" -> Seq("value1"),
  "key2" -> Seq(),
  "key3" -> Seq("value3", "value4"),
  "key4" -> Seq("")
).flatMap { case (k, v) =>
  v.find(_.nonEmpty).map(k -> _)
}

result
  .map { case (key, value) =>
    s"${URLEncoder.encode(key, "UTF-8")}=${URLEncoder.encode(value, "UTF-8")}"
  }
  .mkString("&")

import io.circe.parser

val json = """{
    "action": "OK",
    "authTime": 0,
    "clientId": 2800496004,
    "expiresAt": 1730203012000,
    "grantType": "AUTHORIZATION_CODE",
    "issuableCredentials": null,
    "properties": null,
    "refreshable": true,
    "resources": null,
    "responseContent": "Bearer error=\"invalid_request\"",
    "resultCode": "A056001",
    "resultMessage": "[A056001] The access token is valid.",
    "scopeDetails": null,
    "scopes": null,
    "serviceAttributes": null,
    "subject": "john.s@example.com",
    "sufficient": false,
    "usable": true
}
  """.stripMargin

//parser.decode[IntrospectionResponse](json)

Json.obj("properties" -> Json.arr(List.empty[String].map(Json.fromString)*))

final case class MyObject(properties: List[String]) derives Decoder

val myJson = """ {
  "properties" : [
  ]
}""".stripMargin

parser.decode[MyObject](myJson)

import com.authlete.common.web.BearerToken
import com.authlete.common.web.DpopToken
import io.circe.generic.semiauto.deriveEncoder
import io.circe.syntax.*

DpopToken.parse("DPOP helllo")

val scope = Scope().setName("openid").setDescription("id")

//scope.asJson

val scopeJson = """{
  "name" : "openid",
  "description" : "id"
}
""".stripMargin

//parser.decode[Scope](scopeJson)

val credentialDeferredParseResponse = CredentialDeferredParseResponse()

credentialDeferredParseResponse.setResultMessage("hello message")

credentialDeferredParseResponse.setResultCode("rrsult code")

credentialDeferredParseResponse.setAction(CredentialDeferredParseResponse.Action.OK)

credentialDeferredParseResponse.setResponseContent("content bere")

val data = """{
  "resultCode":" my resut code",
  "resultMessage": "my message",
  "action":"OK",
  "responseContent":"my content"
}
""".stripMargin

//credentialDeferredParseResponse.asJson

val credentialDeferredParseResponse2 = parser
  .decode[CredentialDeferredParseResponse](data)
  .toOption
  .get

credentialDeferredParseResponse2.getResponseContent()

credentialDeferredParseResponse2.getResultMessage()

credentialDeferredParseResponse2.getInfo()

credentialDeferredParseResponse2.getAction()
case class MyConfig(age: Int, isenabled: Boolean) derives Codec

val config = """
{"isenabled":true,
"age":45}
"""

val config2 = """
{"age":45}
"""
parser.decode[MyConfig](config)

parser.decode[MyConfig](config2)

var g = Array(1, 23, 3)

(1 to 10).foreach(x => g.+:(x))

val scopes = Array(1, 2, 3)

val dScopes: Option[Array[Int]] = None //Option(Array(2,7,89,9))

dScopes
  .map { ds =>
    scopes ++ ds.map(_ + 87)
  }
  .getOrElse(scopes)

import org.http4s.headers
import org.typelevel.ci.*

val headerOption = Option(Header.Raw(ci"DPoP-Nonce", "value"))

Response[IO](Status.Accepted, headers = Headers.of(Header.Raw(ci"DPoP-Nonce", "value")))

private def extractClientCertificate(clientCertificatePath: Array[String]): Option[String] =
  // A client certificate is unavailable.(None)
  Option(clientCertificatePath).flatMap(path => if (path.isEmpty) None else Some(path(0)))

extractClientCertificate(null)

extractClientCertificate(Array.empty)

private def extractSubsequenceFromClientCertificatePath(
    clientCertificatePath: Array[String]
): Option[Array[String]] =
  Option(clientCertificatePath).flatMap(path => if (path.isEmpty) None else Some(path.tail))

extractSubsequenceFromClientCertificatePath(null)

extractSubsequenceFromClientCertificatePath(Array.empty)
