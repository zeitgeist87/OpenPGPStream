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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public abstract class OpenPGPFilterInputStream extends FilterInputStream {
	// must not be biggger than 30
	protected byte BUFFERPOWER;
	protected int BUFFERSIZE;

	protected int pos = 0;
	protected int len = 0;
	protected byte[] buf;

	protected long packetLen = 0;
	protected boolean partial = false;

	protected int inputLen = 0;
	protected int inputPos = 0;
	protected int inputRes = 0;

	public OpenPGPFilterInputStream(InputStream in, int buffersize) {
		super(in);

		int exponent = 9;

		while ((1 << exponent) < buffersize && exponent < 30)
			exponent++;
		BUFFERSIZE = 1 << exponent;
		BUFFERPOWER = (byte) exponent;
		buf = new byte[BUFFERSIZE];
	}

	protected static int decodeLengthSpace(byte input) throws IOException {
		int first = input & 0xFF;
		return decodeLengthSpace(first);
	}

	protected static int decodeLengthSpace(int first) throws IOException {
		if (first < 192) {
			return 1;
		} else if (first >= 192 && first <= 223) {
			return 2;
		} else if (first == 255) {
			return 5;
		}

		throw new IOException("Unable to decode packet length");
	}

	protected static long decodeLength(byte[] input, int off, int len)
			throws IOException {
		int first = input[off] & 0xFF;

		if (len >= 1 && first < 192) {
			return first;
		} else if (len >= 2 && first >= 192 && first <= 223) {
			int second = input[off + 1] & 0xFF;
			return (((first - 192) << 8) | second) + 192;
		} else if (len >= 2 && first == 255) {
			// used long to prevent overflow (unsigned int would be used in c)
			return (((long) (input[off + 1] & 0xFF)) << 24)
					| (((long) (input[off + 2] & 0xFF)) << 16)
					| (((long) (input[off + 3] & 0xFF)) << 8)
					| ((long) (input[off + 4] & 0xFF));
		}

		throw new IOException("Unable to decode packet length");
	}

	protected static int decodeLengthSpaceOld(byte input) {
		switch (input & (byte) 0x03) {
		case 0:
			return 1;
		case 1:
			return 2;
		case 2:
			return 4;
		default:
			return 0;
		}
	}

	protected static long decodeLengthOld(byte[] input, int off, int len)
			throws IOException {
		if (len == 1) {
			return input[off] & 0xFF;
		} else if (len == 2) {
			return ((input[off] & 0xFF) << 8) | (input[off + 1] & 0xFF);
		} else if (len == 4) {
			return (((long) (input[off] & 0xFF)) << 24)
					| (((long) (input[off + 1] & 0xFF)) << 16)
					| (((long) (input[off + 2] & 0xFF)) << 8)
					| ((long) (input[off + 3] & 0xFF));
		}
		// undetermined size
		return -1;
	}

	protected int readBlocking(byte[] b, int off, int len) throws IOException {
		int ret = 0;
		int tlen = 0;
		while (len > 0 && (ret = in.read(b, off, len)) != -1) {
			tlen += ret;
			off += ret;
			len -= ret;
		}
		return tlen;
	}

	protected void decodePacketLen() throws IOException {
		// read next packetlen
		// check for partial length
		int first = buf[inputPos] & 0xFF;
		if (first >= 224 && first < 255) {
			packetLen = 1 << (first & 0x1F);
			partial = true;
			inputPos++;
			inputLen--;
		} else {
			int reqlen = decodeLengthSpace(first);
			if (inputLen < reqlen) {
				// read in the rest
				inputLen += readBlocking(buf, inputPos + inputLen, reqlen
						- inputLen);
				if (inputLen < reqlen) {
					throw new IOException("Error in datastream");
				}
			}
			packetLen = decodeLength(buf, inputPos, reqlen);
			inputPos += reqlen;
			inputLen -= reqlen;
			partial = false;
		}
	}

	protected void decodePacketLenOld(byte header) throws IOException {
		int reqlen = decodeLengthSpaceOld(header);

		if (inputLen < reqlen) {
			// read in the rest
			inputLen += readBlocking(buf, inputPos + inputLen, reqlen
					- inputLen);
			if (inputLen < reqlen) {
				throw new IOException("Error in datastream");
			}
		}

		packetLen = decodeLengthOld(buf, inputPos, reqlen);
		inputPos += reqlen;
		inputLen -= reqlen;
		partial = false;
	}

	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	@Override
	public int read() throws IOException {
		if (len == -1)
			return -1;

		if (len == 0) {
			int n = 0;
			while (n == 0) {
				n = fill();
			}
			if (n < 0)
				return -1;
		}

		int res = buf[pos] & 0xFF;
		pos++;
		len--;
		return res;
	}

	@Override
	public int available() throws IOException {
		return 0;
	}

	protected int fillInputBuf() throws IOException {
		if (inputLen < 128) {
			// copy old data to the start position
			if (inputLen != 0) {
				System.arraycopy(buf, inputPos, buf, 0, inputLen);
			}
			inputPos = 0;
		}

		// read in new data
		inputRes = in.read(buf, inputPos + inputLen, buf.length - inputPos
				- inputLen);
		if (inputRes <= 0 && inputLen == 0) {
			return -1;
		} else if (inputRes > 0) {
			inputLen += inputRes;
		}
		return inputLen;
	}

	protected int fill() throws IOException {
		if (packetLen >= 0) {
			// test if it was the last package
			if (packetLen == 0 && partial == false) {
				// stream ends here
				len = -1;
				return -1;
			}

			fillInputBuf();

			if (packetLen == 0 && partial) {
				decodePacketLen();
			}

			len = (int) Math.min((long) inputLen, packetLen);
			pos = inputPos;
			inputPos += len;
			inputLen -= len;
			packetLen -= len;

			return len;
		} else {
			if (len == -1 || fillInputBuf() < 0) {
				// stream ends here
				len = -1;
				return -1;
			}

			len = inputLen;
			pos = inputPos;
			inputPos += len;
			inputLen -= len;

			return len;
		}
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

		if (this.len == -1)
			return -1;

		if (this.len == 0) {
			int n = 0;
			while (n == 0) {
				n = fill();
			}
			if (n < 0)
				return -1;
		}

		int l = Math.min(len, this.len);
		System.arraycopy(buf, pos, b, off, l);
		pos += l;
		this.len -= l;
		return l;
	}

	public int peek() throws IOException {
		if (this.len == -1)
			return -1;

		if (this.len == 0) {
			int n = 0;
			while (n == 0) {
				n = fill();
			}
			if (n < 0)
				return -1;
		}

		return buf[pos] & 0xFF;
	}

	@Override
	public void close() throws IOException {
		fill();

		if (len > 0) {
			throw new IOException("Premature close. This is a security risk!");
		}

		in.close();
	}
}
