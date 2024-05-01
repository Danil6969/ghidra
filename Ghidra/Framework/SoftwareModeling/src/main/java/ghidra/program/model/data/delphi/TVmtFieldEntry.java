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
package ghidra.program.model.data.delphi;

import ghidra.program.model.util.ListingUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

public class TVmtFieldEntry {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtFieldEntry", 0, manager);
		CharDataType charDT = CharDataType.dataType;
		dt.add(Cardinal.getDataType(path, manager), "FieldOffset", "Offset of the field from the start of the class data");
		dt.add(Word.getDataType(path, manager), "TypeIndex", "Type of the field");
		dt.add(new ArrayDataType(charDT, 0, charDT.getLength()), "Name", "Name of the field");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		ProgramBasedDataTypeManager manager = program.getDataTypeManager();
		StructureDataType thisDT = getDataType(path, manager);
		ListingUtils.deleteCreateData(address, thisDT, program);
		address = address.add(thisDT.getLength());
		Data data = ListingUtils.deleteCreateData(address, PascalString255DataType.dataType, program);
		address = address.add(data.getLength());
		return address;
	}
}
