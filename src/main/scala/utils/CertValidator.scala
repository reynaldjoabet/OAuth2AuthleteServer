// package utils
// import java.io.ByteArrayInputStream
// import java.io.IOException
// import java.io.InputStream
// import java.nio.charset.StandardCharsets
// import java.nio.file.Files
// import java.nio.file.Path
// import java.security.GeneralSecurityException
// import java.security.InvalidAlgorithmParameterException
// import java.security.NoSuchAlgorithmException
// import java.security.cert.CertPath
// import java.security.cert.CertPathValidator
// import java.security.cert.CertPathValidatorException
// import java.security.cert.Certificate
// import java.security.cert.CertificateException
// import java.security.cert.CertificateFactory
// import java.security.cert.PKIXCertPathValidatorResult
// import java.security.cert.PKIXParameters
// import java.security.cert.TrustAnchor
// import java.security.cert.X509Certificate
// import java.util.*
// import scala.util.Try

// object CertValidator {

//       private val sCertificateFactory = getCertificateFactoryInstance()
//       private val   sCertPathValidator  = getCertPathValidatorInstance()
//       private val mParameters:PKIXParameters = ???

//       private def getCertificateFactoryInstance()=

//           Try(
//               CertificateFactory.getInstance("X.509"))

//       private def getCertPathValidatorInstance()=
//           Try(CertPathValidator.getInstance("PKIX"))

//       private def createParameters(anchorCertificates:Path*)=
//       {
//         //              throws CertificateException, InvalidAlgorithmParameterException, IOException
//         val anchors = new HashSet[TrustAnchor]()

//         anchorCertificates.map(anchorCertificate=> anchors.add(createTrustAnchor(anchorCertificate)))

//           val params = new PKIXParameters(anchors);
//           params.setRevocationEnabled(false);

//       }

//       private def createTrustAnchor(anchorCertificate: Path )=
//              new TrustAnchor(createCertificate(anchorCertificate), null)

//       private static X509Certificate createCertificate(Path certificate)
//               throws CertificateException, IOException
//       {
//           try (InputStream in = Files.newInputStream(certificate))
//           {
//               return (X509Certificate)certificateFactory().generateCertificate(in);
//           }
//       }

//       public CertValidator(Path...anchorCertificates)
//               throws CertificateException, InvalidAlgorithmParameterException,
//               NoSuchAlgorithmException, IOException
//       {
//           mParameters = createParameters(anchorCertificates);
//       }

//       public PKIXCertPathValidatorResult validate(CertPath certPath)
//               throws CertPathValidatorException, InvalidAlgorithmParameterException
//       {
//           return (PKIXCertPathValidatorResult)
//                   certPathValidator().validate(certPath, mParameters);
//       }

//       public PKIXCertPathValidatorResult validate(List<? extends Certificate> certificates)
//               throws CertPathValidatorException, InvalidAlgorithmParameterException, CertificateException
//       {
//           return validate(certificateFactory().generateCertPath(certificates));
//       }

//       public PKIXCertPathValidatorResult validate(String... certificates)
//               throws CertPathValidatorException, InvalidAlgorithmParameterException, CertificateException
//       {
//           List<Certificate> certs = new ArrayList<>(certificates.length);

//           for (String certificate : certificates)
//           {
//               certs.add(toCertificate(certificate));
//           }

//           return validate(certs);
//       }

//       public PKIXCertPathValidatorResult validate(HttpServletRequest request) throws GeneralSecurityException
//       {
//           // Extract the chain of the client certificate.
//           String[] chain = CertificateUtils.extractChain(request);

//           // If no certificate chain is included.
//           if (chain == null || chain.length == 0)
//           {
//               throw new GeneralSecurityException(
//                       "The HTTP request does not contain a certificate chain.");
//           }

//           return validate(chain);
//       }

//       private def  toCertificate( certificate: String) =
//       {
//           val certificate = normalizeCertificate(certificate);

//         //   try (InputStream in = new ByteArrayInputStream(certificate.getBytes(StandardCharsets.UTF_8)))
//         //   {
//         //       return certificateFactory().generateCertificate(in)

//         ???
//       }

//       private def  normalizeCertificate(certificate: String ):String={
//           val pem = certificate.replaceAll("\\s+(?!CERTIFICATE-----)", "\n").trim()
//           if(pem.startsWith("-----BEGIN CERTIFICATE"))
//               pem.trim()
//               else new StringBuilder()
//               .append("-----BEGIN CERTIFICATE-----\n")
//               .append(pem)
//               .append("\n-----END CERTIFICATE-----")
//               .toString();
//       }

// }
