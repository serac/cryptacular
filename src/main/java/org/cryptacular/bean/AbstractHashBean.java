/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import org.bouncycastle.crypto.Digest;
import org.cryptacular.spec.Spec;
import org.cryptacular.util.HashUtil;

/**
 * Abstract base class for all hash beans.
 *
 * @author  Middleware Services
 */
public abstract class AbstractHashBean
{

  /** Digest specification. */
  private Spec<Digest> digestSpec;

  /** Number of hash rounds. */
  private int iterations = 1;


  /** Creates a new instance. */
  public AbstractHashBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  digestSpec  Digest specification.
   * @param  iterations  Number of hash rounds.
   */
  public AbstractHashBean(final Spec<Digest> digestSpec, final int iterations)
  {
    setDigestSpec(digestSpec);
    setIterations(iterations);
  }


  /**
   * @return  Digest specification that determines the instance of {@link
   * Digest} used to compute the hash.
   */
  public Spec<Digest> getDigestSpec()
  {
    return digestSpec;
  }


  /**
   * Sets the digest specification that determines the instance of {@link
   * Digest} used to compute the hash.
   *
   * @param  digestSpec  Digest algorithm specification.
   */
  public void setDigestSpec(final Spec<Digest> digestSpec)
  {
    this.digestSpec = digestSpec;
  }


  /**
   * @return  Number of iterations the digest function is applied to the input
   * data.
   */
  public int getIterations()
  {
    return iterations;
  }


  /**
   * Sets the number of iterations the digest function is applied to the input
   * data.
   *
   * @param  iterations  Number of hash rounds. Default value is 1.
   */
  public void setIterations(final int iterations)
  {
    if (iterations < 1) {
      throw new IllegalArgumentException("Iterations must be positive");
    }
    this.iterations = iterations;
  }


  /**
   * Hashes the given data.
   *
   * @param  data  Data to hash.
   *
   * @return  Digest output.
   */
  protected byte[] hashInternal(final Object... data)
  {
    return HashUtil.hash(digestSpec.newInstance(), iterations, data);
  }


  /**
   * Compares the hash of the given data against a known hash output.
   *
   * @param  hash  Known hash value. If the length of the array is greater than
   * the length of the digest output, anything beyond the digest length is
   * considered salt data that is hashed <strong>after</strong> the input data.
   * @param  data  Data to hash.
   *
   * @return  True if hashed data equals known hash output, false otherwise.
   */
  protected boolean compareInternal(final byte[] hash, final Object... data)
  {
    return
      HashUtil.compareHash(digestSpec.newInstance(), hash, iterations, data);
  }
}
