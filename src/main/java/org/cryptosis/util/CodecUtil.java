package org.cryptosis.util;

import org.cryptosis.codec.Base64Decoder;
import org.cryptosis.codec.Base64Encoder;
import org.cryptosis.codec.Decoder;
import org.cryptosis.codec.Encoder;
import org.cryptosis.codec.HexDecoder;
import org.cryptosis.codec.HexEncoder;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Utility class for common encoding conversions.
 *
 * @author Marvin S. Addison
 */
public final class CodecUtil
{
  /** Private constructor of utility class. */
  private CodecUtil() {}


  /**
   * Encodes raw bytes to the equivalent hexadecimal encoded string.
   *
   * @param  raw  Raw bytes to encode.
   *
   * @return  Hexadecimal encoded string.
   */
  public static String hex(final byte[] raw)
  {
    return encode(new HexEncoder(), raw);
  }


  /**
   * Encodes raw bytes to the equivalent hexadecimal encoded string with optional delimiting of output.
   *
   * @param  raw  Raw bytes to encode.
   * @param  delimit  True to delimit every two characters (i.e. every byte) of output with ':' character,
   *                  false otherwise.
   *
   * @return  Hexadecimal encoded string.
   */
  public static String hex(final byte[] raw, final boolean delimit)
  {
    return encode(new HexEncoder(delimit), raw);
  }


  /**
   * Decodes a hexadecimal encoded string to raw bytes.
   *
   * @param  encoded  Hex encoded character data.
   *
   * @return  Raw bytes of hex string.
   */
  public static byte[] hex(final CharSequence encoded)
  {
    return decode(new HexDecoder(), encoded);
  }


  /**
   * Encodes bytes into base64-encoded string.
   *
   * @param  raw  Raw bytes to encode.
   *
   * @return  Base64-encoded string.
   */
  public static String b64(final byte[] raw)
  {
    return encode(new Base64Encoder(), raw);
  }


  /**
   * Decodes a base64-encoded string into raw bytes
   *
   * @param  encoded  Base64-encoded character data.
   *
   * @return  Base64-decoded bytes.
   */
  public static byte[] b64(final CharSequence encoded)
  {
    return decode(new Base64Decoder(), encoded);
  }


  /**
   * Encodes bytes into base64-encoded string.
   *
   * @param  raw  Raw bytes to encode.
   * @param  lineLength  Length of each base64-encoded line in output.
   *
   * @return  Base64-encoded string.
   */
  public static String b64(final byte[] raw, final int lineLength)
  {
    return encode(new Base64Encoder(lineLength), raw);
  }


  /**
   * Encodes raw bytes using the given encoder.
   *
   * @param  encoder  Encoder to perform byte-to-char conversion.
   * @param  raw  Raw bytes to encode.
   *
   * @return  Encoded data as a string.
   */
  public static String encode(final Encoder encoder, final byte[] raw)
  {
    final CharBuffer output = CharBuffer.allocate(encoder.outputSize(raw.length));
    encoder.encode(ByteBuffer.wrap(raw), output);
    encoder.finalize(output);
    return output.flip().toString();
  }


  /**
   * Decodes the given encoded data using the given char-to-byte decoder.
   *
   * @param  decoder  Decoder to perform char-to-byte conversion.
   * @param  encoded  Encoded character data.
   *
   * @return  Decoded data as raw bytes.
   */
  public static byte[] decode(final Decoder decoder, final CharSequence encoded)
  {
    final ByteBuffer output = ByteBuffer.allocate(decoder.outputSize(encoded.length()));
    decoder.decode(CharBuffer.wrap(encoded), output);
    decoder.finalize(output);
    output.flip();
    return ByteUtil.toArray(output);
  }
}