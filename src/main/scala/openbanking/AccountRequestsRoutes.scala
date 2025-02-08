package openbanking

import cats.effect.kernel.Async
import cats.syntax.all.*

import org.http4s.*
import org.http4s.dsl.Http4sDsl
import services.AuthleteService

/**
  * This is a dummy implementation of {@code /account-requests} API which is defined in <i>"Account
  * and Transaction API Specification"</i> of UK Open Banking.
  */
final case class AccountRequestsRoutes[F[_]: Async](authleteService: AuthleteService[F])
    extends Http4sDsl[F] {
///api/open-banking/v1.1/account-requests

  val routes = HttpRoutes.of[F] {
    case req @ POST -> Root / "account-requests" :? IncomingInteractionIdParam(
          incomingInteractionId
        ) =>
      ???

  }

}
