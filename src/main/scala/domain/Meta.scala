package domain

import java.time.LocalDateTime

/**
  * Meta
  *
  * @see
  *   <a href="https://openbanking-brasil.github.io/areadesenvolvedor/#tocS_Meta" >Meta</a>
  */
final case class Meta(totalRecords: Int, totalPages: Int, requestDateTime: LocalDateTime)
