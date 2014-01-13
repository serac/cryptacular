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
 * Salt value that always returns null.
 *
 * @author Marvin S. Addison
 */
public class NullSaltProvider implements SaltProvider
{
  /** {@inheritDoc} */
  @Override
  public byte[] generate(final int current, final int total)
  {
    return null;
  }


  /** {@inheritDoc} */
  @Override
  public int getLength()
  {
    return 0;
  }
}
