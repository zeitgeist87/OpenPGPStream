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

public class OpenPGPCompressionInputStream extends OpenPGPFilterInputStream {
	private OpenPGPCompression compression = OpenPGPCompression.NONE;

	public OpenPGPCompression getCompression() {
		return compression;
	}

	public static boolean checkStreamType(int header) {
		if (header == -1)
			return false;

		boolean oldFormat = (header & (byte) 0xC0) == (byte) 0x80;

		if (header != (byte) 0xC8
				&& !(oldFormat && ((header & (byte) 0x3C) >> 2) == 8)) {
			return false;
		}

		return true;
	}

	public OpenPGPCompressionInputStream(InputStream in, int buffersize)
			throws IOException {
		super(in, buffersize);

		if (readBlocking(buf, 0, 2) != 2) {
			throw new IOException("Not enough input");
		}

		byte header = buf[0];
		boolean oldFormat = (header & (byte) 0xC0) == (byte) 0x80;

		if (header != (byte) 0xC8
				&& !(oldFormat && ((header & (byte) 0x3C) >> 2) == 8)) {
			throw new IOException("No Compression packet found");
		}

		inputPos = 1;
		inputLen = 1;

		if (oldFormat) {
			decodePacketLenOld(header);
		} else {
			decodePacketLen();
		}

		if (partial == true && packetLen < 512) {
			throw new IOException(
					"First packet must be at least 512 bytes long");
		}

		if (inputLen == 0) {
			if (readBlocking(buf, 0, 1) != 1) {
				throw new IOException("Not enough input");
			}
			inputPos = 0;
		}
		// check compression algorithm
		switch (buf[inputPos]) {
		case 0:
			compression = OpenPGPCompression.NONE;
		case 1:
			compression = OpenPGPCompression.ZIP;
			break;
		case 2:
			compression = OpenPGPCompression.ZLIB;
			break;
		case 3:
			compression = OpenPGPCompression.BZIP2;
			break;
		default:
			throw new IOException("Unsupported compression algorithm");
		}
		packetLen--;

		inputPos = 0;
		inputLen = 0;
	}
}
