/*
 * OpenPGPStream - Small library for standards compliant sym. encrypted files
 * Copyright (C) 2014  Andreas Rohner
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class OpenPGPCipherInputStream extends OpenPGPFilterInputStream {
	private Cipher cipher;
	private String pass;
	private MessageDigest hash;

	private byte[] outBuf;
	private boolean hashChecked = false;

	public OpenPGPCipherInputStream(InputStream in, String password)
			throws NoSuchAlgorithmException, IOException,
			WrongPasswordException {
		this(in, password, 8192);
	}

	public OpenPGPCipherInputStream(InputStream is, String password,
			int buffersize) throws NoSuchAlgorithmException, IOException,
			WrongPasswordException {
		super(is, buffersize);

		/*
		 * we need an extra buffer because cipher.update() works only
		 * on blocksize data. The problem is it buffers data that is not
		 * blocksize and overwrites its own input the next time with the
		 * buffer. This leads to strange errors. The documentation claims
		 * it can be used on the same buffer, but thats only true for
		 * blocksize data. +88 accounts for possible extra space needed
		 * for the last 22 bytes
		 */
		outBuf = new byte[BUFFERSIZE + 88];
		// nowrap=true
		pass = password;
		hash = MessageDigest.getInstance("SHA-1");

		initCipher();

		/*
		 * Sym. Encrypted and Integrity Protected Data Packet read in the
		 * header at once:
		 *
		 * packettype,packetlength,version,16 ivbytes,2 checkbytes
		 *
		 * 1+5+1+16+16=39
		 *
		 * we can be sure, that at least 25 bytes must be there
		 */
		if (readBlocking(buf, 0, 39) != 39) {
			throw new IOException("Not enough input");
		}

		// packettype
		if (buf[0] != (byte) 0xD2) {
			throw new IOException("Wrong file format or unsupported");
		}

		inputPos = 1;
		inputLen = 39;

		decodePacketLen();

		if (partial == true && packetLen < 512) {
			throw new IOException("First packet must be at least 512 bytes long");
		}

		if (buf[inputPos] != 1) {
			throw new IOException("Wrong packet version");
		}
		inputPos++;
		packetLen--;

		// decrypt first 18 bytes and check if password is correct
		try {
			if ((len = cipher.update(buf, inputPos, 39 - inputPos, outBuf)) < 18) {
				throw new IOException("Error decrypting file");
			}
		} catch (ShortBufferException e) {/* cannot occur */
		}
		// update ciphlen: subtract the bytes already read in
		packetLen -= 39 - inputPos;

		// everything is read into the cipher, so reset inputlen and inputpos
		inputLen = 0;
		inputPos = 0;

		if (outBuf[14] != outBuf[16] || outBuf[15] != outBuf[17]) {
			throw new WrongPasswordException("Decryption check failed");
		}

		// hash decrypted message
		hash.update(outBuf, 0, 18);
		pos = 18;
		len -= 18;
	}

	private void initCipher() throws IOException, NoSuchAlgorithmException {
		/*
		 * first must be a Symmetric-Key Encrypted Session Key Packet with
		 * length 15
		 */
		byte[] sessionKey = buf;

		if (readBlocking(sessionKey, 0, 15) != 15) {
			throw new IOException("Not enough input");
		}

		if (sessionKey[0] != (byte) 0xC3 && sessionKey[0] != (byte) 0x8C) {
			throw new IOException("Wrong file format");
		}
		// packet header with length,version,symalgo,s2kversion,hashalgo
		if (sessionKey[1] != 13 || sessionKey[2] != 4 || sessionKey[4] != 3) {
			throw new IOException("Wrong file format");
		}
		int c = (int) sessionKey[14] & 0xFF;
		int count = (16 + (c & 15)) << ((c >> 4) + 6);
		// 1024-65011712
		if (count < 1024 || count > 65011712) {
			throw new IOException("Wrong file format");
		}

		// 9 means AES256
		// 8 means SHA256
		// we only support AES256 with SHA256 at the moment
		if (sessionKey[3] != 9 || sessionKey[5] != 8) {
			throw new NoSuchAlgorithmException(
					"Only AES256 and SHA256 supported");
		}

		byte[] pw = pass.getBytes("UTF-8");
		int len = pw.length + 8;

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		while (count > len) {
			md.update(sessionKey, 6, 8);
			md.update(pw);
			count -= len;
		}

		if (count < 8) {
			md.update(sessionKey, 6, count);
		} else {
			md.update(sessionKey, 6, 8);
			count -= 8;
			md.update(pw, 0, count);
		}

		SecretKey secret = new SecretKeySpec(md.digest(), "AES");

		try {
			cipher = Cipher.getInstance("AES/CFB128/NoPadding");
		} catch (NoSuchPaddingException e) {
			// nopadding always exists
		}

		// iv is initialized to all 0x00 by default
		byte[] iv = new byte[16];
		IvParameterSpec ips = new IvParameterSpec(iv);

		try {
			cipher.init(Cipher.DECRYPT_MODE, secret, ips);
		} catch (InvalidKeyException e) {
			// should never occur
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// params should be ok
			e.printStackTrace();
		}
	}

	private void checkHash() throws IOException {
		/*
		 * force a finish of the data stream, we have extra bufferspace in
		 * outbuf to account for the last 22 bytes
		 */
		int n = 0;
		while (n != -1) {
			n = fill();
		}

		if (packetLen != 0)
			throw new IOException("Cannot fully read in last packet");

		hash.update(outBuf, pos, len - 20);

		if (len < 22)
			throw new IOException("Error in stream");

		int lastpos = len + pos - 22;
		if (outBuf[lastpos] != (byte) 0xD3
				|| outBuf[lastpos + 1] != (byte) 0x14)
			throw new IOException("Error in stream");

		byte[] md = hash.digest();
		byte[] md2 = new byte[20];
		System.arraycopy(outBuf, lastpos + 2, md2, 0, 20);

		if (!Arrays.equals(md, md2))
			throw new IOException("Invalid checksum at the end");

		len -= 22;
		hashChecked = true;
	}

	@Override
	protected int fill() throws IOException {
		// test if it was the last package
		if (packetLen == 0 && partial == false) {
			// stream ends here
			if (len == 0)
				len = -1;
			return -1;
		}

		fillInputBuf();

		if (packetLen == 0 && partial) {
			decodePacketLen();
		}

		int minlen = (int) Math.min((long) inputLen, packetLen);
		try {
			if (packetLen == minlen && partial == false) {
				len += cipher.doFinal(buf, inputPos, minlen, outBuf, len + pos);
			} else {
				len += cipher.update(buf, inputPos, minlen, outBuf, len + pos);
			}
		} catch (Exception e) {
			throw new IOException(e);
		}
		inputPos += minlen;
		inputLen -= minlen;
		packetLen -= minlen;

		return len;
	}

	@Override
	public int read() throws IOException {
		byte[] t = new byte[1];
		return read(t, 0, 1) == -1 ? -1 : t[0] & 0xFF;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (b == null) {
			throw new NullPointerException();
		} else if (off < 0 || len < 0 || len > b.length - off) {
			throw new IndexOutOfBoundsException();
		} else if (len == 0) {
			return 0;
		}

		if (this.len == 0) {
			int n = 0;
			pos = 0;
			while (n == 0) {
				n = fill();
			}
			if (n < 0)
				return -1;
		}

		if (inputLen < 44) {
			/*
			 * we could be at the end of the stream, so
			 * we first have to test it
			 */
			while (inputLen < 44 && inputRes != -1) {
				fillInputBuf();
			}
		}

		if (hashChecked == false
				&& ((partial == false && packetLen < 22) || (inputRes == -1 && inputLen < 44))) {
			checkHash();
		}

		int l = Math.min(len, this.len);
		if (hashChecked == false) {
			hash.update(outBuf, pos, l);
		}
		System.arraycopy(outBuf, pos, b, off, l);
		pos += l;
		this.len -= l;
		return l;
	}

	@Override
	public int peek() throws IOException {
		if (this.len == 0) {
			int n = 0;
			pos = 0;
			while (n == 0) {
				n = fill();
			}
			if (n < 0)
				return -1;
		}

		if (inputLen < 44) {
			/*
			 * we could be at the end of the stream, so
			 * we first have to test it
			 */
			while (inputLen < 44 && inputRes != -1) {
				fillInputBuf();
			}
		}

		if (hashChecked == false
				&& ((partial == false && packetLen < 22) || (inputRes == -1 && inputLen < 44))) {
			checkHash();
		}

		return outBuf[pos];
	}

	@Override
	public void close() throws IOException {
		fill();

		if (len > 0 || hashChecked == false) {
			throw new IOException("Premature close. This is a security risk!");
		}

		in.close();
	}
}
