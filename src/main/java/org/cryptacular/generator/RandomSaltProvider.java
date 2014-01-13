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

package org.cryptacular.generator;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.cryptacular.util.NonceUtil;

/**
 * @author Marvin S. Addison
 */
public class RandomSaltProvider implements SaltProvider
{
  /** Flag that determines whether salt is applied at start or end of hashing rounds. */
  private final boolean applyAtEnd;

  /** Size of generated salt values. */
  private final int length;

  /** Provides random data for salt. */
  private final SP80090DRBG rbg;


  /**
   * Creates a new instance that applies salt at the end of the hashing process.
   *
   * @param  length  Number of bytes of generated salt values.
   */
  public RandomSaltProvider(final int length)
  {
    this(length, true);
  }

  /**
   * Creates a new instance that applies salt at beginning or end according to the <code>applyAtEnd</code>
   * parameter.
   *
   * @param  length  Number of bytes of generated salt values.
   * @param  applyAtEnd  True to generate salt at end (default) of hashing process, false to generate at start.
   */
  public RandomSaltProvider(final int length, final boolean applyAtEnd)
  {
    this.length = length;
    this.rbg = newRBG(length);
    this.applyAtEnd = applyAtEnd;
  }


  /** {@inheritDoc} */
  @Override
  public byte[] generate(int current, int total)
  {
    if (applyAtEnd) {
      if (current == total) {
        return generate();
      }
    } else {
      if (current == 0) {
        return generate();
      }
    }
    return null;
  }


  /** {@inheritDoc} */
  @Override
  public int getLength()
  {
    return length;
  }


  /**
   * Generates the random salt value.
   *
   * @return  {@link #getLength()} bytes of random salt.
   */
  private byte[] generate()
  {
    final byte[] salt = new byte[length];
    rbg.generate(salt, null, false);
    return salt;
  }


  /**
   * Creates a new DRBG instance.
   *
   * @param  length  Length in bits of values to be produced by DRBG instance.
   *
   * @return  New DRGB instance.
   */
  private static SP80090DRBG newRBG(final int length)
  {
    return new HashSP800DRBG(
      new SHA256Digest(),
      length,
      new EntropySource() {
        @Override
        public boolean isPredictionResistant()
        {
          return false;
        }

        @Override
        public byte[] getEntropy()
        {
          return NonceUtil.timestampNonce(length);
        }

        @Override
        public int entropySize()
        {
          return length;
        }
      },
      null,
      NonceUtil.timestampNonce(8));
  }
}
