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
package org.cryptacular.pbe;

import org.cryptacular.spec.BufferedBlockCipherSpec;

/**
 * Supported password-based encryption algorithms for PKCS#5 PBES2 encryption
 * scheme. The ciphers mentioned in PKCS#5 are supported as well as others in
 * common use or of presumed value.
 *
 * @author  Middleware Services
 * @version  $Revision: 2745 $
 */
public enum PBES2Algorithm {

  /** DES CBC cipher. */
  DES("1.3.14.3.2.7", new BufferedBlockCipherSpec("DES", "CBC", "PKCS5"), 64),

  /** 3-DES CBC cipher. */
  DESede("1.2.840.113549.3.7", new BufferedBlockCipherSpec("DESede", "CBC", "PKCS5"), 192),

  /** RC2 CBC cipher. */
  RC2("1.2.840.113549.3.2", new BufferedBlockCipherSpec("RC2", "CBC", "PKCS5"), 64),

  /** RC5 CBC cipher. */
  RC5("1.2.840.113549.3.9", new BufferedBlockCipherSpec("RC5", "CBC", "PKCS5"), 128),

  /** AES-128 CBC cipher. */
  AES128("2.16.840.1.101.3.4.1.2", new BufferedBlockCipherSpec("AES", "CBC", "PKCS5"), 128),

  /** AES-192 CBC cipher. */
  AES192("2.16.840.1.101.3.4.1.22", new BufferedBlockCipherSpec("AES", "CBC", "PKCS5"), 192),

  /** AES-256 CBC cipher. */
  AES256("2.16.840.1.101.3.4.1.42", new BufferedBlockCipherSpec("AES", "CBC", "PKCS5"), 256);


  /** Algorithm identifier OID. */
  private final String oid;

  /** Cipher algorithm specification. */
  private final BufferedBlockCipherSpec cipherSpec;

  /** Cipher key size in bits. */
  private final int keySize;


  /**
   * Creates a new instance with given parameters.
   *
   * @param  id  Algorithm OID.
   * @param  cipherSpec  Cipher algorithm specification.
   * @param  keySizeBits  Size of derived key in bits to be used with cipher.
   */
  PBES2Algorithm(final String id, final BufferedBlockCipherSpec cipherSpec, final int keySizeBits)
  {
    this.oid = id;
    this.cipherSpec = cipherSpec;
    this.keySize = keySizeBits;
  }


  /**
   * Gets the PBE algorithm for the given object identifier.
   *
   * @param  oid  PBE algorithm OID.
   *
   * @return  Algorithm whose identifier equals given value.
   *
   * @throws  IllegalArgumentException  If no matching algorithm found.
   */
  public static PBES2Algorithm fromOid(final String oid)
  {
    for (PBES2Algorithm a : PBES2Algorithm.values()) {
      if (a.getOid().equals(oid)) {
        return a;
      }
    }
    throw new IllegalArgumentException("Unknown PBES1Algorithm for OID " + oid);
  }


  /** @return  the oid */
  public String getOid()
  {
    return oid;
  }


  /** @return  Cipher algorithm specification. */
  public BufferedBlockCipherSpec getCipherSpec()
  {
    return cipherSpec;
  }


  /**
   * @return  Size of derived key in bits or -1 if algorithm does not define a key size.
   */
  public int getKeySize()
  {
    return keySize;
  }
}