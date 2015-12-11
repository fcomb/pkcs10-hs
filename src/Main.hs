{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings         #-}

module Main where

import           Control.Applicative      ((<$>), (<*>))
import           Control.Monad
import           Crypto.Hash
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import           Crypto.Random            (MonadRandom)
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.BitArray
import           Data.ASN1.Encoding
import           Data.ASN1.OID
import           Data.ASN1.Parse
import           Data.ASN1.Types
import           Data.Bits
import           Data.ByteArray.Encoding
import qualified Data.ByteString          as B
import qualified Data.ByteString.Base64   as Base64
import qualified Data.ByteString.Char8    as BC
import qualified Data.ByteString.Lazy     as L
import           Data.PEM
import           Data.Typeable
import           Data.X509
import           Data.X509.File
import           Data.X509.Memory
import           Data.X509.PKCS10
import           Numeric
import           Text.Printf

publicExponent :: Integer
publicExponent = 0x10001 -- 65537

rsaKeySize :: Int
rsaKeySize = 256 -- 2048 bits

readPEMFile file = do
    content <- B.readFile file
    return $ either error id $ pemParseBS content

encodeDER :: ASN1Object o => o -> BC.ByteString
encodeDER = encodeASN1' DER . flip toASN1 []

decodeDER :: ASN1Object o => BC.ByteString -> Either String (o, [ASN1])
decodeDER bs =
  f asn
  where
    asn = fromASN1 <$> decodeASN1' DER bs
    f = either (Left . show) id

generateCSR :: (MonadRandom m, HashAlgorithmConversion hashAlg) => X520Attributes -> PKCS9Attributes -> PubKey -> PrivKey -> hashAlg -> m (Either String BC.ByteString)
generateCSR subject extAttrs (PubKeyRSA pubKey) (PrivKeyRSA privKey) hashAlg =
  f <$> signature
  where
    f = either (Left . show) (Right . encodeDER . genReq)
    certReq = CertificationRequestInfo {
                version = Version 0
                , subject = subject
                , subjectPublicKeyInfo = PubKeyRSA pubKey
                , attributes = extAttrs
              }
    signature = RSA.signSafer (Just hashAlg) privKey $ encodeDER certReq
    sigAlg = fromHashAlgorithmASN1 hashAlg
    genReq s = CertificationRequest {
                 certificationRequestInfo = certReq
                 , signatureAlgorithm = SignatureALG sigAlg PubKeyALG_RSA
                 , signature = Signature s
               }

main :: IO ()
main = do
     (pubKey, privKey) <- RSA.generate rsaKeySize publicExponent
     let subject = X520Attributes [(X520CommonName, "node.fcomb.io"), (X520OrganizationName, "fcomb")]
     let extAttrs = PKCS9Attributes [PKCS9Attribute $ ExtExtendedKeyUsage [KeyUsagePurpose_ServerAuth, KeyUsagePurpose_CodeSigning], PKCS9Attribute $ ExtKeyUsage [KeyUsage_cRLSign, KeyUsage_digitalSignature]]
     Right bits <- generateCSR subject extAttrs (PubKeyRSA pubKey) (PrivKeyRSA privKey) SHA512
     B.writeFile "/tmp/pkcs10.der" bits
     B.writeFile "/tmp/pkcs10.pem" $ pemWriteBS PEM { pemName = "NEW CERTIFICATE REQUEST", pemHeader = [], pemContent = bits }
     putStrLn $ show $ either (const CertificationRequest {}) fst $ decodeDER bits
