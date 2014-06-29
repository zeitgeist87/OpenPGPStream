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
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;

public class OpenPGPFactory {

	public static InputStream getInputStream(InputStream is, String password)
			throws NoSuchAlgorithmException, IOException,
			WrongPasswordException {
		return getInputStream(is, password, 8 * 1024);
	}

	public static OutputStream getOutputStream(OutputStream os, String password)
			throws NoSuchAlgorithmException, IOException {
		return getOutputStream(os, password, OpenPGPCompression.BZIP2);
	}

	public static OutputStream getOutputStream(OutputStream os,
			String password, OpenPGPCompression compression)
			throws NoSuchAlgorithmException, IOException {
		return getOutputStream(os, password, compression, 8 * 1024);
	}

	public static InputStream getInputStream(InputStream is, String password,
			int bufsize) throws NoSuchAlgorithmException, IOException,
			WrongPasswordException {

		OpenPGPFilterInputStream in = new OpenPGPCipherInputStream(is,
				password, bufsize);
		InputStream res = in;

		int hint = in.peek();
		if (hint == -1) {
			in.close();
			throw new IOException("Invalid input stream");
		}

		if (OpenPGPCompressionInputStream.checkStreamType(hint)) {
			OpenPGPCompressionInputStream ci = new OpenPGPCompressionInputStream(
					in, bufsize);

			switch (ci.getCompression()) {
			case ZIP:
				res = new InflaterInputStream(ci, new Inflater(true));
				break;
			case ZLIB:
				res = new InflaterInputStream(ci, new Inflater());
				break;
			case BZIP2:
				res = new BZip2CompressorInputStream(ci);
				break;
			default:
				res = ci;
			}
		}

		res = new OpenPGPLiteralInputStream(res, bufsize);

		return res;
	}

	public static OutputStream getOutputStream(OutputStream os,
			String password, OpenPGPCompression compression, int bufsize)
			throws IOException, NoSuchAlgorithmException {

		OutputStream res = new OpenPGPCipherOutputStream(os, password, bufsize);
		res = new OpenPGPCompressionOutputStream(res, bufsize, compression);

		switch (compression) {
		case ZIP:
			res = new DeflaterOutputStream(res, new Deflater(
					Deflater.BEST_COMPRESSION, true));
			break;
		case ZLIB:
			res = new DeflaterOutputStream(res, new Deflater(
					Deflater.BEST_COMPRESSION, false));
			break;
		case BZIP2:
			res = new BZip2CompressorOutputStream(res);
			break;
		default:
			break;
		}

		return new OpenPGPLiteralOutputStream(res);
	}
}
