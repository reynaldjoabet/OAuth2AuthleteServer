package oauth2.client

import cats.effect.IO

import org.http4s.*
import io.circe.Encoder
import io.circe.literal.json
import io.circe.jawn
import io.circe.parser.parse
import io.circe.Decoder
import io.circe.syntax.EncoderOps
import cats.syntax.all.*

//import cats.parse.strings.Json
/** These implicit instances allow http4s to decode JSON requests that our API
  * receives, and encode our API's responses in JSON.
  */
object JsonEntityCodec {

  given jsonEntityEncoder[A](using Encoder[A]): EntityEncoder[IO, A] = {
    EntityEncoder.encodeBy[IO, A](
      headers.`Content-Type`(MediaType.application.json)
    ) { value =>
      val jsonByteArray = value.asJson.noSpaces.getBytes
      val singleChunk = fs2.Chunk.array(jsonByteArray)
      val output: EntityBody[IO] = fs2.Stream.chunk(singleChunk)
      Entity(output)
    }
  }

  given jsonEntityDecoder[A](using Decoder[A]): EntityDecoder[IO, A] = {
    EntityDecoder.decodeBy[IO, A](MediaRange.`*/*`) { msg =>
      DecodeResult[IO, A](
        msg.as[String].flatMap { str =>
          IO.apply {
            jawn.decodeAccumulating[A](str).leftMap(_.head).toEither match {
              case Right(report) =>
                Right(report)
              case Left(err) =>
                Left(MalformedMessageBodyFailure(err.getMessage, cause = None))
            }
          }
        }
      )
    }
  }
}
