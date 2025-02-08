package domain

/**
  * Links
  *
  * @see
  *   <a href="https://openbanking-brasil.github.io/areadesenvolvedor/#tocS_Links" >Links</a>
  */

final case class Links(
    self: String,
    first: String,
    prev: String,
    next: String,
    last: String
)
