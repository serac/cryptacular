/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.cryptacular.util.ByteUtil;

/**
 * Cleartext header prepended to ciphertext providing data required for
 * decryption.
 *
 * <p>Data format:</p>
 *
 * <pre>
     +-----+----------+-------+------------+---------+
     | Len | NonceLen | Nonce | KeyNameLen | KeyName |
     +-----+----------+-------+------------+---------+
 * </pre>
 *
 * <p>Where fields are defined as follows:</p>
 *
 * <ul>
 *   <li>Len - Total header length in bytes (4-byte integer)</li>
 *   <li>NonceLen - Nonce length in bytes (4-byte integer)</li>
 *   <li>Nonce - Nonce bytes (variable length)</li>
 *   <li>KeyNameLen (OPTIONAL) - Key name length in bytes (4-byte integer)</li>
 *   <li>KeyName (OPTIONAL) - Key name encoded as bytes in platform-specific
 *     encoding (variable length)</li>
 * </ul>
 *
 * <p>The last two fields are optional and provide support for multiple keys at
 * the encryption provider. A common case for multiple keys is key rotation; by
 * tagging encrypted data with a key name, an old key may be retrieved by name
 * to decrypt outstanding data which will be subsequently re-encrypted with a
 * new key.</p>
 *
 * @author  Middleware Services
 */
public class CiphertextHeader
{

  /** Header nonce field value. */
  private final byte[] nonce;

  /** Header key name field value. */
  private String keyName;

  /** Header length in bytes. */
  private int length;


  /**
   * Creates a new instance with only a nonce.
   *
   * @param  nonce  Nonce bytes.
   */
  public CiphertextHeader(final byte[] nonce)
  {
    this(nonce, null);
  }


  /**
   * Creates a new instance with a nonce and named key.
   *
   * @param  nonce  Nonce bytes.
   * @param  keyName  Key name.
   */
  public CiphertextHeader(final byte[] nonce, final String keyName)
  {
    this.nonce = nonce;
    this.length = 8 + nonce.length;
    if (keyName != null) {
      this.length += 4 + keyName.getBytes().length;
      this.keyName = keyName;
    }
  }

  /**
   * Gets the header length in bytes.
   *
   * @return  Header length in bytes.
   */
  public int getLength()
  {
    return this.length;
  }

  /**
   * Gets the bytes of the nonce/IV.
   *
   * @return  Nonce bytes.
   */
  public byte[] getNonce()
  {
    return this.nonce;
  }

  /**
   * Gets the encryption key name stored in the header.
   *
   * @return  Encryption key name.
   */
  public String getKeyName()
  {
    return this.keyName;
  }


  /**
   * Encodes the header into bytes.
   *
   * @return  Byte representation of header.
   */
  public byte[] encode()
  {
    final ByteBuffer bb = ByteBuffer.allocate(length);
    bb.order(ByteOrder.BIG_ENDIAN);
    bb.putInt(length);
    bb.putInt(nonce.length);
    bb.put(nonce);
    if (keyName != null) {
      final byte[] b = keyName.getBytes();
      bb.putInt(b.length);
      bb.put(b);
    }
    return bb.array();
  }


  /**
   * Creates a header from encrypted data containing a cleartext header
   * prepended to the start.
   *
   * @param  data  Encrypted data with prepended header data.
   *
   * @return  Decoded header.
   */
  public static CiphertextHeader decode(final byte[] data)
  {
    final ByteBuffer bb = ByteBuffer.wrap(data);
    bb.order(ByteOrder.BIG_ENDIAN);

    final int length = bb.getInt();
    final byte[] nonce = new byte[bb.getInt()];
    bb.get(nonce);

    String keyName = null;
    if (length > nonce.length + 8) {
      final byte[] b = new byte[bb.getInt()];
      bb.get(b);
      keyName = new String(b);
    }
    return new CiphertextHeader(nonce, keyName);
  }


  /**
   * Creates a header from encrypted data containing a cleartext header
   * prepended to the start.
   *
   * @param  input  Input stream that is positioned at the start of ciphertext
   * header data.
   *
   * @return  Decoded header.
   */
  public static CiphertextHeader decode(final InputStream input)
  {
    final int length = ByteUtil.readInt(input);
    final byte[] nonce = new byte[ByteUtil.readInt(input)];
    try {
      input.read(nonce);
    } catch (IOException e) {
      throw new RuntimeException("Error reading from stream", e);
    }

    String keyName = null;
    if (length > nonce.length + 8) {
      final byte[] b = new byte[ByteUtil.readInt(input)];
      try {
        input.read(b);
      } catch (IOException e) {
        throw new RuntimeException("Error reading from stream", e);
      }
      keyName = new String(b);
    }
    return new CiphertextHeader(nonce, keyName);
  }
}
