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

public class OpenPGPLiteralInputStream extends OpenPGPFilterInputStream {
	protected String filename;

	public OpenPGPLiteralInputStream(InputStream in, int buffersize)
			throws IOException {
		super(in, buffersize);

		if (readBlocking(buf, 0, 2) != 2) {
			throw new IOException("Not enough input");
		}

		byte header = buf[0];
		boolean oldFormat = (header & (byte) 0xC0) == (byte) 0x80;

		if (header != (byte) 0xCB
				&& !(oldFormat && ((header & (byte) 0x3C) >> 2) == 11)) {
			throw new IOException("No Literal packet found");
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

		// check packet type
		if (buf[inputPos] != 0x62) {
			throw new IOException("Not a binary packet type");
		}

		if (readBlocking(buf, 0, 5) != 5) {
			throw new IOException("Error in datastream");
		}

		int filenamelen = buf[0] & 0xFF;
		if (buf[0] != 0) {
			// read in the filename
			readBlocking(buf, 5, filenamelen);
		}

		filename = new String(buf, 5, filenamelen, "UTF-8");
		// System.out.println("Filename: " + filename);

		packetLen -= 6 + filenamelen;
		inputPos = 0;
		inputLen = 0;
	}

	public String getFilename() {
		return filename;
	}
}
