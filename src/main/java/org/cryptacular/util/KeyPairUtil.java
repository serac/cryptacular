/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.util.io.Streams;
import org.cryptacular.adapter.Converter;
import org.cryptacular.asn.OpenSSLPrivateKeyDecoder;
import org.cryptacular.asn.PKCS8PrivateKeyDecoder;
import org.cryptacular.asn.PublicKeyDecoder;

/**
 * Utility methods for public/private key pairs used for asymmetric encryption.
 *
 * @author  Middleware Services
 */
public final class KeyPairUtil
{

  /** Data used to verify key pairs. */
  private static final byte[] SIGN_BYTES = ByteUtil.toBytes(
    "Mr. Watson--come here--I want to see you.");


  /** Private constructor of utility class. */
  private KeyPairUtil() {}


  /**
   * Gets the length in bits of a public key where key size is dependent on the
   * particulars of the algorithm.
   *
   * <ul>
   *   <li>DSA - length of p</li>
   *   <li>EC - length of p for prime fields, m for binary fields</li>
   *   <li>RSA - length of modulus</li>
   * </ul>
   *
   * @param  pubKey  Public key.
   *
   * @return  Size of the key in bits.
   */
  public static int length(final PublicKey pubKey)
  {
    final int size;
    if (pubKey instanceof DSAPublicKey) {
      size = ((DSAPublicKey) pubKey).getParams().getP().bitLength();
    } else if (pubKey instanceof RSAPublicKey) {
      size = ((RSAPublicKey) pubKey).getModulus().bitLength();
    } else if (pubKey instanceof ECPublicKey) {
      size = ((ECPublicKey) pubKey).getParams().getCurve().getField()
        .getFieldSize();
    } else {
      throw new IllegalArgumentException(pubKey + " not supported.");
    }
    return size;
  }


  /**
   * Gets the length in bits of a private key where key size is dependent on the
   * particulars of the algorithm.
   *
   * <ul>
   *   <li>DSA - length of q in bits</li>
   *   <li>EC - length of p for prime fields, m for binary fields</li>
   *   <li>RSA - modulus length in bits</li>
   * </ul>
   *
   * @param  privKey  Private key.
   *
   * @return  Size of the key in bits.
   */
  public static int length(final PrivateKey privKey)
  {
    final int size;
    if (privKey instanceof DSAPrivateKey) {
      size = ((DSAPrivateKey) privKey).getParams().getQ().bitLength();
    } else if (privKey instanceof RSAPrivateKey) {
      size = ((RSAPrivateKey) privKey).getModulus().bitLength();
    } else if (privKey instanceof ECPrivateKey) {
      size = ((ECPrivateKey) privKey).getParams().getCurve().getField()
        .getFieldSize();
    } else {
      throw new IllegalArgumentException(privKey + " not supported.");
    }
    return size;
  }


  /**
   * Determines whether the given public and private keys form a proper key pair
   * by computing and verifying a digital signature with the keys.
   *
   * @param  pubKey  DSA, RSA or EC public key.
   * @param  privKey  DSA, RSA, or EC private key.
   *
   * @return  True if the keys form a functioning keypair, false otherwise.
   * Errors during signature verification are treated as false.
   */
  public static boolean isKeyPair(
    final PublicKey pubKey,
    final PrivateKey privKey)
  {
    final String alg = pubKey.getAlgorithm();
    if (!alg.equals(privKey.getAlgorithm())) {
      return false;
    }

    // Dispatch onto the algorithm-specific method
    final boolean result;
    if ("DSA".equals(alg)) {
      result = isKeyPair((DSAPublicKey) pubKey, (DSAPrivateKey) privKey);
    } else if ("RSA".equals(alg)) {
      result = isKeyPair((RSAPublicKey) pubKey, (RSAPrivateKey) privKey);
    } else if ("EC".equals(alg)) {
      result = isKeyPair((ECPublicKey) pubKey, (ECPrivateKey) privKey);
    } else {
      throw new IllegalArgumentException(alg + " not supported.");
    }
    return result;
  }


  /**
   * Determines whether the given DSA public and private keys form a proper key
   * pair by computing and verifying a digital signature with the keys.
   *
   * @param  pubKey  DSA public key.
   * @param  privKey  DSA private key.
   *
   * @return  True if the keys form a functioning keypair, false otherwise.
   * Errors during signature verification are treated as false.
   */
  public static boolean isKeyPair(
    final DSAPublicKey pubKey,
    final DSAPrivateKey privKey)
  {
    final DSASigner signer = new DSASigner();
    final DSAParameters params = new DSAParameters(
      pubKey.getParams().getP(),
      pubKey.getParams().getQ(),
      pubKey.getParams().getG());
    signer.init(true, new DSAPrivateKeyParameters(privKey.getX(), params));

    final BigInteger[] sig = signer.generateSignature(SIGN_BYTES);
    signer.init(false, new DSAPublicKeyParameters(pubKey.getY(), params));
    try {
      return signer.verifySignature(SIGN_BYTES, sig[0], sig[1]);
    } catch (Exception e) {
      return false;
    }
  }


  /**
   * Determines whether the given RSA public and private keys form a proper key
   * pair by computing and verifying a digital signature with the keys.
   *
   * @param  pubKey  RSA public key.
   * @param  privKey  RSA private key.
   *
   * @return  True if the keys form a functioning keypair, false otherwise.
   * Errors during signature verification are treated as false.
   */
  public static boolean isKeyPair(
    final RSAPublicKey pubKey,
    final RSAPrivateKey privKey)
  {
    final RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
    signer.init(
      true,
      new RSAKeyParameters(
        true,
        privKey.getModulus(),
        privKey.getPrivateExponent()));
    signer.update(SIGN_BYTES, 0, SIGN_BYTES.length);
    try {
      final byte[] sig = signer.generateSignature();
      signer.init(
        false,
        new RSAKeyParameters(
          false,
          pubKey.getModulus(),
          pubKey.getPublicExponent()));
      signer.update(SIGN_BYTES, 0, SIGN_BYTES.length);
      return signer.verifySignature(sig);
    } catch (CryptoException e) {
      return false;
    }
  }


  /**
   * Determines whether the given EC public and private keys form a proper key
   * pair by computing and verifying a digital signature with the keys.
   *
   * @param  pubKey  EC public key.
   * @param  privKey  EC private key.
   *
   * @return  True if the keys form a functioning keypair, false otherwise.
   * Errors during signature verification are treated as false.
   */
  public static boolean isKeyPair(
    final ECPublicKey pubKey,
    final ECPrivateKey privKey)
  {
    final ECDSASigner signer = new ECDSASigner();
    try {
      signer.init(true, ECUtil.generatePrivateKeyParameter(privKey));

      final BigInteger[] sig = signer.generateSignature(SIGN_BYTES);
      signer.init(false, ECUtil.generatePublicKeyParameter(pubKey));
      return signer.verifySignature(SIGN_BYTES, sig[0], sig[1]);
    } catch (InvalidKeyException e) {
      throw new IllegalArgumentException("Unsupported EC key", e);
    } catch (Exception e) {
      return false;
    }
  }


  /**
   * Reads an encoded private key from a file at the given path. Both PKCS#8 and
   * OpenSSL "traditional" formats are supported in DER or PEM encoding. See
   * {@link #decodePrivateKey(byte[])} for supported asymmetric algorithms.
   *
   * @param  path  Path to private key file.
   *
   * @return  Private key.
   *
   * @throws  IOException  On IO errors reading data from file.
   */
  public static PrivateKey readPrivateKey(final String path)
    throws IOException
  {
    return readPrivateKey(new File(path));
  }


  /**
   * Reads an encoded private key from a file. Both PKCS#8 and OpenSSL
   * "traditional" formats are supported in DER or PEM encoding. See {@link
   * #decodePrivateKey(byte[])} for supported asymmetric algorithms.
   *
   * @param  file  Private key file.
   *
   * @return  Private key.
   *
   * @throws  IOException  On IO errors reading data from file.
   */
  public static PrivateKey readPrivateKey(final File file)
    throws IOException
  {
    return readPrivateKey(new FileInputStream(file));
  }


  /**
   * Reads an encoded private key from an input stream. Both PKCS#8 and OpenSSL
   * "traditional" formats are supported in DER or PEM encoding. See {@link
   * #decodePrivateKey(byte[])} for supported asymmetric algorithms.
   *
   * @param  in  Input stream containing private key data.
   *
   * @return  Private key.
   *
   * @throws  IOException  On IO errors reading data from file.
   */
  public static PrivateKey readPrivateKey(final InputStream in)
    throws IOException
  {
    return decodePrivateKey(Streams.readAll(in));
  }


  /**
   * Reads an encrypted private key from a file at the given path. Both PKCS#8
   * and OpenSSL "traditional" formats are supported in DER or PEM encoding. See
   * {@link #decodePrivateKey(byte[])} for supported asymmetric algorithms.
   *
   * @param  path  Path to private key file.
   * @param  password  Password used to encrypt private key.
   *
   * @return  Private key.
   *
   * @throws  IOException  On IO errors reading data from file.
   */
  public static PrivateKey readPrivateKey(
    final String path,
    final char[] password)
    throws IOException
  {
    return readPrivateKey(new File(path), password);
  }


  /**
   * Reads an encrypted private key from a file. Both PKCS#8 and OpenSSL
   * "traditional" formats are supported in DER or PEM encoding. See {@link
   * #decodePrivateKey(byte[])} for supported asymmetric algorithms.
   *
   * @param  file  Private key file.
   * @param  password  Password used to encrypt private key.
   *
   * @return  Private key.
   *
   * @throws  IOException  On IO errors reading data from file.
   */
  public static PrivateKey readPrivateKey(
    final File file,
    final char[] password)
    throws IOException
  {
    return readPrivateKey(new FileInputStream(file), password);
  }


  /**
   * Reads an encrypted private key from an input stream. Both PKCS#8 and
   * OpenSSL "traditional" formats are supported in DER or PEM encoding. See
   * {@link #decodePrivateKey(byte[])} for supported asymmetric algorithms.
   *
   * @param  in  Input stream containing private key data.
   * @param  password  Password used to encrypt private key.
   *
   * @return  Private key.
   *
   * @throws  IOException  On IO errors reading data from file.
   */
  public static PrivateKey readPrivateKey(
    final InputStream in,
    final char[] password)
    throws IOException
  {
    return decodePrivateKey(Streams.readAll(in), password);
  }


  /**
   * Decodes an encoded private key in either PKCS#8 or OpenSSL "traditional"
   * format in either DER or PEM encoding. Keys from the following asymmetric
   * algorithms are supported:
   *
   * <ul>
   *   <li>DSA</li>
   *   <li>RSA</li>
   *   <li>Elliptic curve</li>
   * </ul>
   *
   * @param  encodedKey  Encoded private key data.
   *
   * @return  Private key.
   */
  public static PrivateKey decodePrivateKey(final byte[] encodedKey)
  {
    return decodePrivateKey(encodedKey, null);
  }


  /**
   * Decodes an encrypted private key. The following formats are supported:
   *
   * <ul>
   *   <li>DER or PEM encoded PKCS#8 format</li>
   *   <li>PEM encoded OpenSSL "traditional" format</li>
   * </ul>
   *
   * <p>Keys from the following asymmetric algorithms are supported:</p>
   *
   * <ul>
   *   <li>DSA</li>
   *   <li>RSA</li>
   *   <li>Elliptic curve</li>
   * </ul>
   *
   * @param  encryptedKey  Encrypted private key data.
   * @param  password  Password used to encrypt private key.
   *
   * @return  Private key.
   */
  public static PrivateKey decodePrivateKey(
    final byte[] encryptedKey,
    final char[] password)
  {
    AsymmetricKeyParameter key;
    try {
      final PKCS8PrivateKeyDecoder decoder = new PKCS8PrivateKeyDecoder();
      key = decoder.decode(encryptedKey, password);
    } catch (Exception e) {
      final OpenSSLPrivateKeyDecoder decoder = new OpenSSLPrivateKeyDecoder();
      key = decoder.decode(encryptedKey, password);
    }
    return Converter.convertPrivateKey(key);
  }


  /**
   * Reads a DER or PEM-encoded public key from a file.
   *
   * @param  path  Path to DER or PEM-encoded public key file.
   *
   * @return  Public key.
   *
   * @throws  IOException  On IO errors
   */
  public static PublicKey readPublicKey(final String path)
    throws IOException
  {
    return readPublicKey(new File(path));
  }


  /**
   * Reads a DER or PEM-encoded public key from a file.
   *
   * @param  file  DER or PEM-encoded public key file.
   *
   * @return  Public key.
   *
   * @throws  IOException  On IO errors
   */
  public static PublicKey readPublicKey(final File file)
    throws IOException
  {
    return readPublicKey(new FileInputStream(file));
  }


  /**
   * Reads a DER or PEM-encoded public key from data in the given stream.
   *
   * @param  in  Input stream containing an encoded key.
   *
   * @return  Public key.
   *
   * @throws  IOException  On IO errors
   */
  public static PublicKey readPublicKey(final InputStream in)
    throws IOException
  {
    return decodePublicKey(Streams.readAll(in));
  }


  /**
   * Decodes public keys formatted in an X.509 SubjectPublicKeyInfo structure in
   * either PEM or DER encoding.
   *
   * @param  encoded  Encoded public key bytes.
   *
   * @return  Public key.
   */
  public static PublicKey decodePublicKey(final byte[] encoded)
  {
    return Converter.convertPublicKey(new PublicKeyDecoder().decode(encoded));
  }
}
