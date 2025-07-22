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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.*;

public class TVmtFieldExEntry {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtFieldExEntry", 0, manager);
		dt.add(Byte.getDataType(path, manager), "Flags", "");
		dt.add(PPTypeInfo.getDataType(path, manager), "TypeRef", "Pointer to RTTI record");
		dt.add(Cardinal.getDataType(path, manager), "Offset", "");
		dt.add(new ArrayDataType(CharDataType.dataType, 0, 1), "Name", "");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		try {
			ProgramBasedDataTypeManager manager = program.getDataTypeManager();
			StructureDataType thisDT = getDataType(path, manager);
			ListingUtils.deleteCreateData(address, thisDT, program);
			TypedefDataType byteDT = Byte.getDataType(path, manager);
			address = address.add(thisDT.getLength());
			Data data = ListingUtils.deleteCreateData(address, PascalString255DataType.dataType, program);
			address = address.add(data.getLength());
			long count = MemoryUtils.readNumber(address, byteDT.getLength(), program);
			address = address.add(byteDT.getLength());
			for (int i = 1; i < count; i++) {
				address = address.add(1);
			}
			return address;
		} catch (MemoryAccessException e) {
			return null;
		}
	}
}
