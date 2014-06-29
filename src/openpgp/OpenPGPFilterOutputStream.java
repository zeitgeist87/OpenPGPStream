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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public abstract class OpenPGPFilterOutputStream extends FilterOutputStream {
	// must not be biggger than 30
	protected byte BUFFERPOWER;
	protected byte PARTIAL_BUFFERSIZE;
	protected int BUFFERSIZE;

	// only used to make write more efficient
	protected byte[] onebuf = new byte[1];

	protected int pos = 0;
	protected byte[] buf;

	public OpenPGPFilterOutputStream(OutputStream out, int buffersize) {
		super(out);

		int exponent = 9;

		while ((1 << exponent) < buffersize && exponent < 30)
			exponent++;
		BUFFERSIZE = 1 << exponent;
		BUFFERPOWER = (byte) exponent;
		PARTIAL_BUFFERSIZE = (byte) (224 + BUFFERPOWER);
		buf = new byte[BUFFERSIZE];
	}

	protected static byte[] encodeLength(int len) {
		byte[] b = null;
		if (len >= 0) {
			if (len < 192) {
				b = new byte[1];
				b[0] = (byte) len;
			} else if (len >= 192 && len <= 8383) {
				// bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
				len -= 192;
				b = new byte[2];
				b[0] = (byte) (len >> 8);
				b[1] = (byte) (len & 0xFF);

				b[0] += 192;
			} else {
				/*
				 * bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |(4th_octet
				 * << 8) | 5th_octet
				 */
				b = new byte[5];
				b[0] = (byte) 0xFF;
				b[1] = (byte) ((len >> 24));
				b[2] = (byte) ((len >> 16) & 0xFF);
				b[3] = (byte) ((len >> 8) & 0xFF);
				b[4] = (byte) (len & 0xFF);
			}
		}
		return b;
	}

	@Override
	public void flush() throws IOException {
		// cannot efficiently flush the buffer
		out.flush();
	}

	@Override
	public void write(int c) throws IOException {
		onebuf[0] = (byte) c;
		write(onebuf, 0, 1);
	}

	@Override
	public void write(byte[] buf) throws IOException {
		write(buf, 0, buf.length);
	}

	@Override
	public void close() throws IOException {
		// inputpos can be 0 terminates the stream
		byte[] b = encodeLength(pos);
		out.write(b);

		if (pos > 0) {
			out.write(buf, 0, pos);
		}
		out.close();
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		// if inputbuf contains something append the new data
		if (pos > 0) {
			// if it fits into the buffer
			if (len <= BUFFERSIZE - pos) {
				// just copy it
				System.arraycopy(b, off, buf, pos, len);
				pos += len;
				off += len;
				len = 0;
			} else {
				// fill the buffer up
				int tlen = BUFFERSIZE - pos;
				System.arraycopy(b, off, buf, pos, tlen);
				off += tlen;
				len -= tlen;
				pos = BUFFERSIZE;
			}

			// if inputbuf is full write it out
			if (pos == BUFFERSIZE) {
				// set partial length
				out.write(PARTIAL_BUFFERSIZE);

				out.write(buf, 0, BUFFERSIZE);
				pos = 0;
			}
		}

		// deflate the input
		while (len >= BUFFERSIZE) {
			// set partial length
			out.write(PARTIAL_BUFFERSIZE);

			// add one bufferlen to the deflater
			out.write(b, off, BUFFERSIZE);

			off += BUFFERSIZE;
			len -= BUFFERSIZE;
		}

		if (len > 0) {
			// just copy it
			System.arraycopy(b, off, buf, pos, len);
			pos += len;
		}
	}
}
