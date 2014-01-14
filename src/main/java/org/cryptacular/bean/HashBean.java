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

/**
 * Strategy interface to support beans that produce hash outputs in various formats, e.g. raw bytes, hex output, etc.
 *
 * @author Marvin S. Addison
 * @param  <T>  Type of output (e.g. byte[], string) produced by hash bean.
 */
public interface HashBean<T>
{
  /**
   * Hashes the given data.
   *
   * @param  data  Data to hash. Callers should expect support for at least the following types:
   *               <code>byte[]</code>, {@link CharSequence}, {@link java.io.InputStream},
   *               and {@link org.cryptacular.io.Resource}.
   *               Unless otherwise noted, character data is processed in the <code>UTF-8</code> character set;
   *               if another character set is desired, the caller should convert to <code>byte[]</code>
   *               and provide the resulting bytes.
   *
   * @return  Digest output.
   */
  T hash(Object ... data);


  /**
   * Compares a known hash value with the hash of the given data.
   *
   * @param  hash  Known hash value.
   * @param  data  Data to hash.
   *
   * @return  True if the hashed data matches the given hash, false otherwise.
   */
  boolean compare(final T hash, Object ... data);
}
