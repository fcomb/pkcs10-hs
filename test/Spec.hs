module Main where

import           Crypto.Hash
import qualified Crypto.PubKey.DSA        as DSA
import qualified Crypto.PubKey.RSA        as RSA
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Parse
import           Data.ASN1.Types
import qualified Data.ByteString          as B
import qualified Data.ByteString.Char8    as BC
import           Data.PEM
import           Data.X509
import           Data.X509.PKCS10
import           Keys
import           Test.Tasty
import           Test.Tasty.HUnit
-- import           Test.Tasty.QuickCheck as QC

main :: IO ()
main = do
  defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [unitTests]

unitTests = testGroup "Unit tests"
  [ testCase "CSR with subject and extension (RSA)" $ do
      req <- defaultRsaCSR subjectAttrs extAttrs
      checkCSR req subjectAttrs extAttrs $ PubKeyRSA rsaPublicKey
  , testCase "CSR with empty subject and extension (RSA)" $ do
      req <- defaultRsaCSR emptySubjectAttrs emptyExtAttrs
      checkCSR req emptySubjectAttrs emptyExtAttrs $ PubKeyRSA rsaPublicKey
  , testCase "CSR fixtures (RSA)" $ do
      let subjAttrs = X520Attributes [(X520CommonName, asn1CharacterString Printable "api"), (X520CommonName, asn1CharacterString Printable "fcomb"), (X520CommonName, asn1CharacterString Printable "com"), (X520StateOrProvinceName, asn1CharacterString Printable "Moscow"), (X520LocalityName, asn1CharacterString Printable "Moscow"), (X520OrganizationName, asn1CharacterString Printable "End Point"), (X520OrganizationalUnitName, asn1CharacterString Printable "fcomb"), (EmailAddress, asn1CharacterString IA5 "in@fcomb.io"), (X509SubjectAltName, asn1CharacterString Printable "DNS.1=fcomb.com")]
      checkRsaFixtureCSR "rsa" "rsa1" subjAttrs (PKCS9Attributes [PKCS9Attribute $ ExtBasicConstraints False Nothing, PKCS9Attribute $ ExtKeyUsage [KeyUsage_digitalSignature,KeyUsage_nonRepudiation,KeyUsage_keyEncipherment]])
      checkRsaFixtureCSR "rsa" "rsa2" subjAttrs emptyExtAttrs
      checkRsaFixtureCSR "rsa" "rsa3" emptySubjectAttrs emptyExtAttrs
  , testCase "CSR with subject and extension (DSA)" $ do
      req <- defaultDsaCSR subjectAttrs extAttrs
      checkCSR req subjectAttrs extAttrs $ PubKeyDSA dsaPublicKey
  ,  testCase "CSR with empty subject and extension (DSA)" $ do
      req <- defaultDsaCSR emptySubjectAttrs emptyExtAttrs
      checkCSR req emptySubjectAttrs emptyExtAttrs $ PubKeyDSA dsaPublicKey
  ]

subjectAttrs = makeX520Attributes [(X520CommonName, "node.fcomb.io"), (X520OrganizationName, "fcomb")]

emptySubjectAttrs = X520Attributes []

extAttrs = PKCS9Attributes [PKCS9Attribute $ ExtExtendedKeyUsage [KeyUsagePurpose_ServerAuth, KeyUsagePurpose_CodeSigning], PKCS9Attribute $ ExtKeyUsage [KeyUsage_digitalSignature, KeyUsage_cRLSign]]

emptyExtAttrs = PKCS9Attributes []

checkRsaFixtureCSR keyName csrName subjectAttrs extAttrs = do
  rsaPem <- readPEMFile $ "./test/fixtures/" ++ keyName ++ ".pem"
  let publicKey = RSA.private_pub $ readRsaPubKey rsaPem 256
  putStrLn $ show $ publicKey
  csrPem <- readPEMFile $ "./test/fixtures/" ++ csrName ++ ".csr"
  let req = readCSR csrPem
  putStrLn $ show $ req
  checkCSR req subjectAttrs extAttrs $ PubKeyRSA publicKey

defaultRsaCSR subjectAttrs extAttrs = do
  Right req <- generateCSR subjectAttrs extAttrs (KeyPairRSA rsaPublicKey rsaPrivateKey) SHA512
  return req

defaultDsaCSR subjectAttrs extAttrs = do
  Right req <- generateCSR subjectAttrs extAttrs (KeyPairDSA dsaPublicKey dsaPrivateKey) SHA1
  return $ req

readPEMFile file = do
  content <- B.readFile file
  return $ either error (pemContent . head) $ pemParseBS content

decodeDER :: ASN1Object o => BC.ByteString -> Either String (o, [ASN1])
decodeDER bs =
  f asn
  where
    asn = fromASN1 <$> decodeASN1' DER bs
    f = either (Left . show) id

checkAttrs csr subjectAttrs extAttrs = do
  let certReqInfo = certificationRequestInfo csr
  assertBool "subject == subjectAttrs" $
    (subject certReqInfo) == subjectAttrs
  assertBool "attributes == extAttrs" $
    (attributes certReqInfo) == extAttrs

checkDER csr = do
  let (Right csr') = (fromDER . toDER) csr
  assertBool "csr' == csr" $ csr' == csr

checkPEM csr = do
  let (Right csr') = (fromPEM . toPEM) csr
  assert $ csr' == csr
  let (Right csr'') = (fromPEM . toNewFormatPEM) csr
  assertBool "csr'' == csr" $ csr'' == csr
  assertBool "pemName == CERTIFICATE REQUEST" $
    (pemName . toPEM $ csr) == "CERTIFICATE REQUEST"
  assertBool "pemName == NEW CERTIFICATE REQUEST" $
    (pemName . toNewFormatPEM $ csr) == "NEW CERTIFICATE REQUEST"

verifyCSR csr pubKey = do
  assertBool "verify csr" $ verify csr pubKey
  let csr' = csr { signature = Signature $ BC.pack "invalid" }
  assertBool "verify not valid csr" $ not $ verify csr' pubKey

checkCSR csr subjectAttrs extAttrs pubKey = do
  checkAttrs csr subjectAttrs extAttrs
  checkDER csr
  checkPEM csr
  verifyCSR csr pubKey

readRsaPubKey :: B.ByteString -> Int -> RSA.PrivateKey
readRsaPubKey bs size =
  case decodeASN1' DER bs of
    Right (Start Sequence :
           IntVal _ :
           IntVal public_n :
           IntVal public_e :
           IntVal private_d :
           IntVal private_p :
           IntVal private_q :
           IntVal private_dP :
           IntVal private_dQ :
           IntVal private_qinv :
           End Sequence : _) ->
           RSA.PrivateKey {
                  RSA.private_pub = RSA.PublicKey {
                    RSA.public_size = size
                  , RSA.public_n = public_n
                  , RSA.public_e = public_e
                  }
                , RSA.private_d = private_d
                , RSA.private_p = private_p
                , RSA.private_q = private_q
                , RSA.private_dP = private_dP
                , RSA.private_dQ = private_dQ
                , RSA.private_qinv = private_qinv
           }
    _ -> error "RSA.PrivateKey: unknown format"

readCSR bs =
  case decodeDER bs of
    Right (csr @ CertificationRequest {}, _) -> csr
    Left e -> error e
