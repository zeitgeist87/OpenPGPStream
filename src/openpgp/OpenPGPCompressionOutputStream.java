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

public class OpenPGPCompressionOutputStream extends OpenPGPFilterOutputStream {

	public OpenPGPCompressionOutputStream(OutputStream os, int buffersize,
			OpenPGPCompression compression) throws IOException {
		super(os, buffersize);

		// new compressed data packet
		out.write(0xC8);
		/*
		 * ID           Algorithm
		 * --           ---------
		 * 0          - Uncompressed
		 * 1          - ZIP [RFC1951]
		 * 2          - ZLIB [RFC1950]
		 * 3          - BZip2 [BZ2]
		 * 100 to 110 - Private/Experimental algorithm
		 */

		// set compression algorithm to deflate
		switch (compression) {
		case NONE:
			buf[0] = 0;
		case ZIP:
			buf[0] = 1;
			break;
		case ZLIB:
			buf[0] = 2;
			break;
		case BZIP2:
			buf[0] = 3;
			break;
		}
		pos = 1;
	}
}
