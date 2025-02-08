import org.http4s.dsl.impl.OptionalQueryParamDecoderMatcher

package object openbanking {

  object CodeParam  extends OptionalQueryParamDecoderMatcher[String]("code")
  object StateParam extends OptionalQueryParamDecoderMatcher[String]("state")
  object IncomingInteractionIdParam
      extends OptionalQueryParamDecoderMatcher[String]("incomingInteractionId")

}
