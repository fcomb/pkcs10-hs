{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings         #-}

module Main where

import           Control.Applicative      ((<$>), (<*>))
import           Control.Monad
import           Crypto.Hash
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import           Crypto.Random            (MonadRandom)
import qualified Data.ByteString          as B
import           Data.PEM
import           Data.X509
import           Data.X509.PKCS10
import           Numeric
import           Text.Printf

publicExponent :: Integer
publicExponent = 0x10001 -- 65537

rsaKeySize :: Int
rsaKeySize = 256 -- 2048 bits

main :: IO ()
main = do
  (pubKey, privKey) <- RSA.generate rsaKeySize publicExponent
  let subject = X520Attributes [(X520CommonName, "node.fcomb.io"), (X520OrganizationName, "fcomb")]
  let extAttrs = PKCS9Attributes [PKCS9Attribute $ ExtExtendedKeyUsage [KeyUsagePurpose_ServerAuth, KeyUsagePurpose_CodeSigning], PKCS9Attribute $ ExtKeyUsage [KeyUsage_cRLSign, KeyUsage_digitalSignature]]
  Right bits <- generateCSR subject extAttrs (PubKeyRSA pubKey) (PrivKeyRSA privKey) SHA512
  B.writeFile "/tmp/pkcs10.der" bits
  B.writeFile "/tmp/pkcs10.pem" $ pemWriteBS PEM { pemName = "NEW CERTIFICATE REQUEST", pemHeader = [], pemContent = bits }
  putStrLn $ show $ either (const CertificationRequest {}) fst $ decodeDER bits
