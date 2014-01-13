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

package org.cryptacular.bean;

import java.io.InputStream;

import org.bouncycastle.crypto.Digest;
import org.cryptacular.SaltedHash;
import org.cryptacular.generator.Nonce;
import org.cryptacular.generator.SaltProvider;
import org.cryptacular.spec.Spec;
import org.cryptacular.util.HashUtil;

/**
 * Computes a salted hash from a random salt source.
 *
 * @author Marvin S. Addison
 */
public class SaltedHashBean implements HashBean<SaltedHash>
{
  /** Salt provider. */
  private SaltProvider saltProvider;

  /** Number of hash iterations. */
  private int iterations = 1;

  /** Digest specification. */
  private Spec<Digest> digestSpec;


  /**
   * @return  Digest specification that determines the instance of {@link Digest} used to compute the hash.
   */
  public Spec<Digest> getDigestSpec()
  {
    return digestSpec;
  }


  /**
   * Sets the digest specification that determines the instance of {@link Digest} used to compute the hash.
   *
   * @param  digestSpec  Digest algorithm specification.
   */
  public void setDigestSpec(final Spec<Digest> digestSpec)
  {
    this.digestSpec = digestSpec;
  }


  /**
   * @return  Gets the provider of salt bytes.
   */
  public SaltProvider getSaltProvider()
  {
    return saltProvider;
  }


  /**
   * Sets the provider of salt bytes.
   *
   * @param  provider  Salt provider.
   */
  public void setSaltProvider(final SaltProvider provider)
  {
    this.saltProvider = provider;
  }


  /**
   * @return  Number of iterations the digest function is applied to the input data.
   */
  public int getIterations()
  {
    return iterations;
  }


  /**
   * Sets the number of iterations the digest function is applied to the input data.
   *
   * @param  iterations  Digest function iterations. Default value is 1.
   */
  public void setIterations(final int iterations)
  {
    this.iterations = iterations;
  }


  /** {@inheritDoc} */
  @Override
  public SaltedHash hash(final byte[] input)
  {
    return HashUtil.hash(digestSpec.newInstance(), input, saltProvider, iterations);
  }


  /** {@inheritDoc} */
  @Override
  public SaltedHash hash(final InputStream input)
  {
    return HashUtil.hash(digestSpec.newInstance(), input, saltProvider, iterations);
  }


  /** {@inheritDoc} */
  @Override
  public boolean compare(final byte[] input, final SaltedHash saltedHash)
  {
    return HashUtil.compareSaltedHash(
      digestSpec.newInstance(),
      input,
      iterations,
      saltedHash.concatenateSalt(true));
  }


  /** {@inheritDoc} */
  @Override
  public boolean compare(final InputStream input, final SaltedHash saltedHash)
  {
    return HashUtil.compareSaltedHash(
      digestSpec.newInstance(),
      input,
      iterations,
      saltedHash.concatenateSalt(true));
  }
}
