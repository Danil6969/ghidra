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

import ghidra.program.model.data.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.*;

public class TExcDesc {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TExcDesc", 0, manager);
		StructureDataType entryDT = TExcDescEntry.getDataType(path, manager);
		TypedefDataType integerDT = Integer.getDataType(path, manager);
		dt.add(integerDT, "Cnt", "Number of exception classes defined in an \"except on...\"-block");
		dt.add(new ArrayDataType(entryDT, 0, entryDT.getLength()), "ExcTab", "Table of on-definitions and there handlers in an \"except on...\"-block");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		try {
			ProgramBasedDataTypeManager manager = program.getDataTypeManager();
			TypedefDataType integerDT = Integer.getDataType(path, manager);
			StructureDataType thisDT = getDataType(path, manager);
			ListingUtils.deleteCreateData(address, thisDT, program);
			long count = MemoryUtils.readNumber(address, integerDT.getLength(), program);
			address = address.add(thisDT.getLength());
			for (int i = 0; i < count; i++) {
				address = TExcDescEntry.putObject(address, path, program);
			}
			return address;
		} catch (MemoryAccessException e) {
			return null;
		}
	}
}
