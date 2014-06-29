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
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class OpenPGPCipherOutputStream extends OpenPGPFilterOutputStream {
	private String pass;
	private Cipher cipher;
	private MessageDigest hash;
	private SecureRandom random;
	private byte version = 1;
	private int ciphpos = 0;

	public OpenPGPCipherOutputStream(OutputStream os, String password)
			throws NoSuchAlgorithmException, IOException {
		this(os, password, 8192);
	}

	public OpenPGPCipherOutputStream(OutputStream os, String password,
			int buffersize) throws NoSuchAlgorithmException, IOException {
		super(os, buffersize);
		random = new SecureRandom();
		pass = password;
		hash = MessageDigest.getInstance("SHA-1");
		initCipher();

		// create new encrypted data packet
		out.write(0xD2);
	}

	protected void initCipher() throws IOException, NoSuchAlgorithmException {
		// packet header with length,version,symalgo,s2kversion,hashalgo
		// 9 means AES256
		// 8 means SHA256
		byte[] b = { (byte) 0xC3, 13, 4, 9, 3, 8 };
		out.write(b);

		byte[] salt = new byte[8];
		random.nextBytes(salt);

		out.write(salt);

		/*
		 * #define EXPBIAS 6 count = ((Int32)16 + (c & 15)) << ((c >> 4) +
		 * EXPBIAS);
		 *
		 * precomputed: c=0x9F .... count=1015808
		 */
		out.write(0x9F);
		int count = 1015808;
		byte[] pw = pass.getBytes("UTF-8");
		int len = pw.length + 8;

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		while (count > len) {
			md.update(salt, 0, 8);
			md.update(pw);
			count -= len;
		}

		if (count < 8) {
			md.update(salt, 0, count);
		} else {
			md.update(salt, 0, 8);
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
			cipher.init(Cipher.ENCRYPT_MODE, secret, ips);
		} catch (InvalidKeyException e) {
			// should never occur
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// params should be ok
			e.printStackTrace();
		}

		// AES has 128 bit blocksize: 16+2
		int bs = cipher.getBlockSize();
		byte[] ivrep = new byte[bs + 2];
		random.nextBytes(ivrep);
		ivrep[bs] = ivrep[bs - 2];
		ivrep[bs + 1] = ivrep[bs - 1];

		hash.update(ivrep, 0, bs + 2);
		try {
			pos = cipher.update(ivrep, 0, bs + 2, buf);
		} catch (ShortBufferException e) {
		}
		ciphpos = bs + 2;
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		hash.update(b, off, len);
		while (len > 0) {
			int tlen = Math.min(len, BUFFERSIZE - ciphpos);
			try {
				pos += cipher.update(b, off, tlen, buf, pos);
			} catch (ShortBufferException e) {
			}
			ciphpos += tlen;
			len -= tlen;
			off += tlen;

			if (pos == BUFFERSIZE) {
				out.write(PARTIAL_BUFFERSIZE);
				out.write(version);
				out.write(buf, 0, BUFFERSIZE - 1);
				version = buf[BUFFERSIZE - 1];
				pos = 0;
				ciphpos = 0;
			}
		}
	}

	private void finish() throws IOException {
		write(0xD3);
		write(0x14);
		byte[] md = hash.digest();

		if (BUFFERSIZE - ciphpos >= md.length) {
			// enough space in buffer for the hash
			try {
				pos += cipher.doFinal(md, 0, md.length, buf, pos);
			} catch (ShortBufferException | IllegalBlockSizeException
					| BadPaddingException e) {
			}
		} else {
			// not enough space in buffer for the hash
			int len = md.length;
			int off = 0;

			int tlen = BUFFERSIZE - ciphpos;
			try {
				pos += cipher.update(md, off, tlen, buf, pos);
			} catch (ShortBufferException e) {
			}
			ciphpos += tlen;
			len -= tlen;
			off += tlen;

			out.write(PARTIAL_BUFFERSIZE);
			out.write(version);
			out.write(buf, 0, BUFFERSIZE - 1);
			version = buf[BUFFERSIZE - 1];
			pos = 0;
			ciphpos = 0;

			// write out the rest
			try {
				pos += cipher.doFinal(md, off, len, buf, pos);
			} catch (ShortBufferException | IllegalBlockSizeException
					| BadPaddingException e) {
			}
		}
	}

	@Override
	public void close() throws IOException {
		finish();

		// write out whats left in the buffer
		byte[] b = encodeLength(pos + 1);
		out.write(b);
		out.write(version);

		if (pos > 0) {
			out.write(buf, 0, pos);
		}

		out.close();
	}
}
