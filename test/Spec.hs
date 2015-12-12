{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings         #-}

module Main where

import           Crypto.Hash
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Data.ByteString   as B
import           Data.PEM
import           Data.X509
import           Data.X509.PKCS10

publicExponent :: Integer
publicExponent = 0x10001 -- 65537

rsaKeySize :: Int
rsaKeySize = 256 -- 2048 bits

main :: IO ()
main = do
  (pubKey, privKey) <- RSA.generate rsaKeySize publicExponent
  let subject = X520Attributes [(X520CommonName, "node.fcomb.io"), (X520OrganizationName, "fcomb")]
  let extAttrs = PKCS9Attributes [PKCS9Attribute $ ExtExtendedKeyUsage [KeyUsagePurpose_ServerAuth, KeyUsagePurpose_CodeSigning], PKCS9Attribute $ ExtKeyUsage [KeyUsage_cRLSign, KeyUsage_digitalSignature]]
  Right rsaCSR <- generateCSR subject extAttrs (KeyPairRSA pubKey privKey) SHA512
  B.writeFile "/tmp/pkcs10.pem" $ (pemWriteBS . toNewFormatPEM) rsaCSR
  putStrLn $ show $ either (const CertificationRequest {}) fst $ (decodeDER . toDER) rsaCSR

  let dsaParams = DSA.Params
                   { DSA.params_p = 0xa8f9cd201e5e35d892f85f80e4db2599a5676a3b1d4f190330ed3256b26d0e80a0e49a8fffaaad2a24f472d2573241d4d6d6c7480c80b4c67bb4479c15ada7ea8424d2502fa01472e760241713dab025ae1b02e1703a1435f62ddf4ee4c1b664066eb22f2e3bf28bb70a2a76e4fd5ebe2d1229681b5b06439ac9c7e9d8bde283
                 , DSA.params_g = 0x2b3152ff6c62f14622b8f48e59f8af46883b38e79b8c74deeae9df131f8b856e3ad6c8455dab87cc0da8ac973417ce4f7878557d6cdf40b35b4a0ca3eb310c6a95d68ce284ad4e25ea28591611ee08b8444bd64b25f3f7c572410ddfb39cc728b9c936f85f419129869929cdb909a6a3a99bbe089216368171bd0ba81de4fe33
                 , DSA.params_q = 0xf85f0f83ac4df7ea0cdf8f469bfeeaea14156495
                   }
  let dsaPubKey = DSA.PublicKey
                    { DSA.public_y       = 0xa01542c3da410dd57930ca724f0f507c4df43d553c7f69459939685941ceb95c7dcc3f175a403b359621c0d4328e98f15f330a63865baf3e7eb1604a0715e16eed64fd14b35d3a534259a6a7ddf888c4dbb5f51bbc6ed339e5bb2a239d5cfe2100ac8e2f9c16e536f25119ab435843af27dc33414a9e4602f96d7c94d6021cec
                      , DSA.public_params = dsaParams
                    }
  dsaPrivNumber <- DSA.generatePrivate dsaParams
  let dsaPrivKey = DSA.PrivateKey
                         { DSA.private_x      = dsaPrivNumber
                           , DSA.private_params = dsaParams
                         }
  Right dsaCSR <- generateCSR subject extAttrs (KeyPairDSA dsaPubKey dsaPrivKey) SHA1
  B.writeFile "/tmp/pkcs10-dsa.pem" $ (pemWriteBS . toNewFormatPEM) dsaCSR
  putStrLn $ show $ either (const CertificationRequest {}) fst $ (decodeDER . toDER) dsaCSR
  return ()
