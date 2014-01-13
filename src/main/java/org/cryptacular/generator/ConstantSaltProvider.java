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

/**
 * @author Marvin S. Addison
 */
public class ConstantSaltProvider implements SaltProvider
{
  /** Flag that determines whether salt is applied at start or end of hashing rounds. */
  private final boolean applyAtEnd;

  /** Constant salt value. */
  private final byte[] salt;


  /**
   * Creates a new instance with the given constant salt value.
   *
   * @param  salt  Constant salt value.
   */
  public ConstantSaltProvider(final byte[] salt)
  {
    this(salt, true);
  }


  /**
   * Creates a new instance with the given constant salt value.
   *
   * @param  salt  Constant salt value.
   * @param  applyAtEnd  True to generate salt at end (default) of hashing process, false to generate at start.
  */
  public ConstantSaltProvider(final byte[] salt, final boolean applyAtEnd)
  {
    this.salt = salt;
    this.applyAtEnd = applyAtEnd;
  }


  /** {@inheritDoc} */
  @Override
  public byte[] generate(final int current, final int total)
  {
    if (applyAtEnd) {
      if (current == total) {
        return salt;
      }
    } else {
      if (current == 0) {
        return salt;
      }
    }
    return null;
  }


  /** {@inheritDoc} */
  @Override
  public int getLength()
  {
    return salt.length;
  }
}
