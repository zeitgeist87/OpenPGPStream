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

public class OpenPGPLiteralOutputStream extends OpenPGPFilterOutputStream {

	public OpenPGPLiteralOutputStream(OutputStream os) throws IOException {
		this(os, 8192);
	}

	public OpenPGPLiteralOutputStream(OutputStream os, int buffersize)
			throws IOException {
		super(os, buffersize);
		// create a literal data packet
		out.write(0xCB);
		// binary packet
		buf[0] = 0x62;
		/*
		 * inputbuf shoud be initialized to 0 by default we need 5 more bytes
		 * set to 0
		 */
		pos = 6;
	}
}
