module Main where

import           Crypto.Hash
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as BC
import           Data.PEM
import           Data.X509
import           Data.X509.PKCS10
import           Keys
import           Test.Tasty
import           Test.Tasty.HUnit
-- import           Test.Tasty.QuickCheck as QC

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [unitTests]

unitTests = testGroup "Unit tests"
  [ testCase "CSR with subject and extension (RSA)" $ do
      req <- defaultRsaCSR subjectAttrs extAttrs
      checkCSR req subjectAttrs extAttrs
      checkDER req
      checkPEM req
      verifyCSR req $ PubKeyRSA rsaPublicKey
  , testCase "CSR with empty subject and extension (RSA)" $ do
      req <- defaultRsaCSR emptySubjectAttrs emptyExtAttrs
      checkCSR req emptySubjectAttrs emptyExtAttrs
      checkDER req
      checkPEM req
      verifyCSR req $ PubKeyRSA rsaPublicKey
  , testCase "CSR with subject and extension (DSA)" $ do
      req <- defaultDsaCSR subjectAttrs extAttrs
      checkCSR req subjectAttrs extAttrs
      checkDER req
      checkPEM req
      verifyCSR req $ PubKeyDSA dsaPublicKey
  ,  testCase "CSR with empty subject and extension (DSA)" $ do
      req <- defaultDsaCSR emptySubjectAttrs emptyExtAttrs
      checkCSR req emptySubjectAttrs emptyExtAttrs
      checkDER req
      checkPEM req
      verifyCSR req $ PubKeyDSA dsaPublicKey
  ]

subjectAttrs = X520Attributes [(X520CommonName, "node.fcomb.io"), (X520OrganizationName, "fcomb")]

emptySubjectAttrs = X520Attributes []

extAttrs = PKCS9Attributes [PKCS9Attribute $ ExtExtendedKeyUsage [KeyUsagePurpose_ServerAuth, KeyUsagePurpose_CodeSigning], PKCS9Attribute $ ExtKeyUsage [KeyUsage_digitalSignature, KeyUsage_cRLSign]]

emptyExtAttrs = PKCS9Attributes []

defaultRsaCSR subjectAttrs extAttrs = do
  Right req <- generateCSR subjectAttrs extAttrs (KeyPairRSA rsaPublicKey rsaPrivateKey) SHA512
  return req

defaultDsaCSR subjectAttrs extAttrs = do
  Right req <- generateCSR subjectAttrs extAttrs (KeyPairDSA dsaPublicKey dsaPrivateKey) SHA1
  return $ req

readPEMFile file = do
    content <- B.readFile file
    return $ either error id $ pemParseBS content

checkCSR csr subjectAttrs extAttrs = do
  let certReqInfo = certificationRequestInfo csr
  assert $ (subject certReqInfo) == subjectAttrs
  assert $ (attributes certReqInfo) == extAttrs

checkDER csr = do
  let (Right csr') = (fromDER . toDER) csr
  assert $ csr' == csr

checkPEM csr = do
  let (Right csr') = (fromPEM . toPEM) csr
  assert $ csr' == csr
  let (Right csr'') = (fromPEM . toNewFormatPEM) csr
  assert $ csr'' == csr
  assert $ (pemName . toPEM $ csr) == "CERTIFICATE REQUEST"
  assert $ (pemName . toNewFormatPEM $ csr) == "NEW CERTIFICATE REQUEST"

verifyCSR csr pubKey = do
  assert $ verify csr pubKey
  let csr' = csr { signature = Signature $ BC.pack "invalid" }
  assert . not $ verify csr' pubKey
