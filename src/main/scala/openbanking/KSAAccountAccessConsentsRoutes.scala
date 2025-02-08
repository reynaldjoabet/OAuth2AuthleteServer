package openbanking

import cats.effect.kernel.Async
import cats.syntax.all.*

import org.http4s.*
import org.http4s.dsl.Http4sDsl
import services.AuthleteService

/**
  * This is a dummy implementation of {@code /account-access-consents} API which is defined in the
  * specification of KSA / SAMA Open Banking.
  */

final case class KSAAccountAccessConsentsRoutes[F[_]: Async](authleteService: AuthleteService[F])
    extends Http4sDsl[F] {

  /// api/open-banking/v1.1/account-access-consents
  val routes = HttpRoutes.of[F] {
    case req @ POST -> Root / "account-access-consents" :? IncomingInteractionIdParam(
          incomingInteractionId
        ) =>
      ???

  }

}
