/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.program.model.data;

import java.math.BigInteger;

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.DataConverter;
import ghidra.util.StringFormat;
import ghidra.util.classfinder.*;

/**
 * Provides an implementation of a 10-byte that has not been defined yet as a
 * particular type of data in the program.
 */
public class Undefined10DataType extends Undefined {
	static {
		ClassTranslator.put("ghidra.program.model.data.Undefined10",
			Undefined10DataType.class.getName());
	}

	private final static long serialVersionUID = 1;
	private static final EndianSettingsDefinition ENDIAN = EndianSettingsDefinition.DEF;

	/** A statically defined DefaultDataType used when an Undefined byte is needed.*/
	public final static Undefined10DataType dataType = new Undefined10DataType();

	/**
	 * Constructs a new Undefined10 dataType
	 *
	 */
	public Undefined10DataType() {
		this(null);
	}

	public Undefined10DataType(DataTypeManager dtm) {
		super("undefined10", dtm);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	public int getLength() {
		return 10;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	public String getDescription() {
		return "Undefined 10-Byte";
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getMnemonic(Settings)
	 */
	public String getMnemonic(Settings settings) {
		return name;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getRepresentation(MemBuffer, Settings, int)
	 */
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		String val = "??";

		Object b = getValue(buf, settings, length);
		if (!(b instanceof BigInteger)) {
			return val;
		}
		BigInteger bi = (BigInteger)b;
		val = bi.toString(16).toUpperCase();
		val = StringFormat.padIt(val, 20, '\0', true);
		val = "0x" + val;

		return val;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		byte[] bytes = new byte[10];
		if (buf.getBytes(bytes, 0) != 10) {
			return null;
		}

		DataConverter dc = DataConverter.getInstance(ENDIAN.isBigEndian(settings, buf));

		return dc.getBigInteger(bytes, 10, false);
	}

	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Undefined10DataType(dtm);
	}
}
