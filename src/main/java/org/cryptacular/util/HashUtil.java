/*
 * Licensed to Virginia Tech under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Virginia Tech licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.cryptacular.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.cryptacular.SaltedHash;
import org.cryptacular.generator.ConstantSaltProvider;
import org.cryptacular.generator.NullSaltProvider;
import org.cryptacular.generator.SaltProvider;

/**
 * Utility class for computing cryptographic hashes.
 *
 * @author  Marvin S. Addison
 */
public final class HashUtil
{
  /** Private constructor of utility class. */
  private HashUtil() {}


  /**
   * Computes the hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final byte[] data)
  {
    return hashInternal(digest, data, new NullSaltProvider(), 1, null);
  }


  /**
   * Computes the hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input stream containing data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] hash(final Digest digest, final InputStream input)
  {
    return hashInternal(digest, input, new NullSaltProvider(), 1, null);
  }


  /**
   * Computes the salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  data  Data to hash.
   * @param  salt  Provider of salt data.
   *
   * @return  Container for digest output and salt.
   */
  public static SaltedHash hash(final Digest digest, final byte[] data, final SaltProvider salt)
  {
    return hash(digest, data, salt, 1);
  }


  /**
   * Computes the salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input stream containing data to hash.
   * @param  salt  Provider of salt data.
   *
   * @return  Container for digest output and salt.
   */
  public static SaltedHash hash(final Digest digest, final InputStream input, final SaltProvider salt)
  {
    return hash(digest, input, salt, 1);
  }


  /**
   * Computes an iterated, salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  data  Data to hash.
   * @param  salt  Provider of salt data.
   * @param  iterations  Number of hash iterations to perform on input data.
   *
   * @return  Container for digest output and salt.
   */
  public static SaltedHash hash(final Digest digest, final byte[] data, final SaltProvider salt, final int iterations)
  {
    final ByteBuffer buffer = ByteBuffer.allocate(salt.getLength());
    final byte[] hash = hashInternal(digest, data, salt, iterations, buffer);
    final byte[] collectedSalt = new byte[buffer.limit()];
    buffer.flip();
    buffer.get(collectedSalt);
    return new SaltedHash(hash, collectedSalt);
  }


  /**
   * Computes an iterated, salted hash of the given data using the given algorithm.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input stream containing data to hash.
   * @param  salt  Provider of salt data.
   * @param  iterations  Number of hash iterations to perform on input data.
   *
   * @return  Container for digest output and salt.
   */
  public static SaltedHash hash(
    final Digest digest, final InputStream input, final SaltProvider salt, final int iterations)
  {
    final ByteBuffer buffer = ByteBuffer.allocate(salt.getLength());
    final byte[] hash = hashInternal(digest, input , salt, iterations, buffer);
    final byte[] collectedSalt = new byte[buffer.limit()];
    buffer.flip();
    buffer.get(collectedSalt);
    return new SaltedHash(hash, collectedSalt);
  }


  /**
   * Determines whether the hash of the given input equals a known value.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Data to hash.
   * @param  hash  Hash to compare with.
   *
   * @return  True if the hash of the data under the given digest is equal to the hash, false otherwise.
   */
  public static boolean compareHash(final Digest digest, final byte[] input, final byte[] hash)
  {
    return Arrays.equals(hash(digest, input), hash);
  }


  /**
   * Determines whether the hash of the given input equals a known value.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input stream containing data to hash.
   * @param  hash  Hash to compare with.
   *
   * @return  True if the hash of the data under the given digest is equal to the hash, false otherwise.
   */
  public static boolean compareHash(final Digest digest, final InputStream input, final byte[] hash)
  {
    return Arrays.equals(hash(digest, input), hash);
  }


  /**
   * Determines whether the salted hash of the given input equals a known hash. The hash value is assumed to contain
   * the salt appended to the hash output.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input to hash.
   * @param  iterations  Number of hash rounds.
   * @param  saltedHash  Hash to compare with of the form <code>DIGEST+SALT</code>, that is, where the salt is appended
   *                     to the digest output bytes.
   *
   * @return  True if the hash of the data under the given digest is equal to the hash, false otherwise.
   */
  public static boolean compareSaltedHash(
    final Digest digest, final byte[] input, final int iterations, final byte[] saltedHash)
  {
    final byte[] salt = new byte[saltedHash.length - digest.getDigestSize()];
    System.arraycopy(saltedHash, digest.getDigestSize(), salt, 0, salt.length);
    final SaltedHash result = hash(digest, input, new ConstantSaltProvider(salt), iterations);
    return Arrays.equals(result.concatenateSalt(true), saltedHash);
  }


  /**
   * Determines whether the salted hash of the given input equals a known hash. The hash value is assumed to contain
   * the salt appended to the hash output.
   *
   * @param  digest  Hash algorithm.
   * @param  input  Input stream containing data to hash.
   * @param  iterations  Number of hash rounds.
   * @param  saltedHash  Hash to compare with of the form <code>DIGEST+SALT</code>, that is, where the salt is appended
   *                     to the digest output bytes.
   *
   * @return  True if the hash of the data under the given digest is equal to the hash, false otherwise.
   */
  public static boolean compareSaltedHash(
    final Digest digest, final InputStream input, final int iterations, final byte[] saltedHash)
  {
    final byte[] salt = new byte[saltedHash.length - digest.getDigestSize()];
    System.arraycopy(saltedHash, digest.getDigestSize(), salt, 0, salt.length);
    final SaltedHash result = hash(digest, input, new ConstantSaltProvider(salt), iterations);
    return Arrays.equals(result.concatenateSalt(true), saltedHash);
  }


  /**
   * Produces the SHA-1 hash of the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha1(final byte[] data)
  {
    return hash(new SHA1Digest(), data);
  }


  /**
   * Produces the SHA-1 hash of the given data.
   *
   * @param  input  Input stream containing data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha1(final InputStream input)
  {
    return hash(new SHA1Digest(), input);
  }


  /**
   * Produces the SHA-256 hash of the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha256(final byte[] data)
  {
    return hash(new SHA256Digest(), data);
  }


  /**
   * Produces the SHA-256 hash of the given data.
   *
   * @param  input  Input stream containing data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha256(final InputStream input)
  {
    return hash(new SHA256Digest(), input);
  }


  /**
   * Produces the SHA-512 hash of the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha512(final byte[] data)
  {
    return hash(new SHA512Digest(), data);
  }


  /**
   * Produces the SHA-512 hash of the given data.
   *
   * @param  input  Input stream containing data to hash.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha512(final InputStream input)
  {
    return hash(new SHA512Digest(), input);
  }


  /**
   * Produces the SHA-3 hash of the given data.
   *
   * @param  data  Data to hash.
   * @param  bitLength  Desired size in bits.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha3(final byte[] data, final int bitLength)
  {
    return hash(new SHA3Digest(bitLength), data);
  }


  /**
   * Produces the SHA-3 hash of the given data.
   *
   * @param  input  Input stream containing data to hash.
   * @param  bitLength  Desired size in bits.
   *
   * @return  Hash bytes that completely fill returned byte array.
   */
  public static byte[] sha3(final InputStream input, final int bitLength)
  {
    return hash(new SHA3Digest(bitLength), input);
  }


  /**
   * Computes a salted hash but does not concatenate the salt to the hash bytes.
   *
   * @param  digest  Digest algorithm.
   * @param  data  Data to hash.
   * @param  salt  Salt provider.
   * @param  iterations  Number of hash rounds.
   * @param  saltBuf  Buffer to collect salt.
   *
   * @return  Digest bytes.
   */
  private static byte[] hashInternal(
    final Digest digest, final byte[] data, final SaltProvider salt, final int iterations, final ByteBuffer saltBuf)
  {
    final byte[] saltBytes = salt.generate(0, iterations);
    if (saltBytes != null) {
      digest.update(saltBytes, 0, saltBytes.length);
      saltBuf.put(saltBytes);
    }
    final byte[] output = new byte[digest.getDigestSize()];
    digest.update(data, 0, data.length);
    digest.doFinal(output, 0);
    iterate(digest, output, salt, iterations, saltBuf);
    return output;
  }


  /**
   * Computes a salted hash but does not concatenate the salt to the hash bytes.
   *
   * @param  digest  Digest algorithm.
   * @param  in  Input stream containing data to hash.
   * @param  salt  Optional salt.
   * @param  iterations  Number of hash rounds.
   * @param  saltBuf  Buffer to collect salt.
   *
   * @return  Digest bytes.
   */
  private static byte[] hashInternal(
    final Digest digest, final InputStream in, final SaltProvider salt, final int iterations, final ByteBuffer saltBuf)
  {
    final byte[] saltBytes = salt.generate(0, iterations);
    if (saltBytes != null) {
      digest.update(saltBytes, 0, saltBytes.length);
      saltBuf.put(saltBytes);
    }
    final byte[] buffer = new byte[StreamUtil.CHUNK_SIZE];
    int length;
    try {
      while ((length = in.read(buffer)) > 0) {
        digest.update(buffer, 0, length);
      }
    } catch (IOException e) {
      throw new RuntimeException("Error reading stream", e);
    }
    final byte[] output = new byte[digest.getDigestSize()];
    digest.doFinal(output, 0);
    iterate(digest, output, salt, iterations, saltBuf);
    return output;
  }


  /**
   * Computes the given number of iterations on a hash.
   *
   * @param  digest  Digest algorithm.
   * @param  hash  Initial hash output (i.e. first iteration).
   * @param  salt  Salt provider.
   * @param  iterations  Number of iterations to compute.
   * @param  saltBuf  Buffer to collect salt.
   */
  private static void iterate(
    final Digest digest, final byte[] hash, final SaltProvider salt, final int iterations, final ByteBuffer saltBuf)
  {
    byte[] saltBytes;
    for (int i = 1; i < iterations; i++) {
      saltBytes = salt.generate(i, iterations);
      if (saltBytes != null) {
        digest.update(saltBytes, 0, saltBytes.length);
        saltBuf.put(saltBytes);
      }
      digest.update(hash, 0, hash.length);
      digest.doFinal(hash, 0);
    }
    saltBytes = salt.generate(iterations, iterations);
    if (saltBytes != null) {
      digest.update(saltBytes, 0, saltBytes.length);
      digest.doFinal(hash, 0);
      saltBuf.put(saltBytes);
    }
  }
}
