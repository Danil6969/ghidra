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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.*;

public class TVmtMethodTable_0 {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtMethodTable_0", 0, manager);
		StructureDataType entryDT = TVmtMethodEntry.getDataType(path, manager);
		dt.add(Word.getDataType(path, manager), "Count", "");
		dt.add(new ArrayDataType(entryDT, 0, entryDT.getLength()), "Entry", "");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		try {
			ProgramBasedDataTypeManager manager = program.getDataTypeManager();
			StructureDataType thisDT = getDataType(path, manager);
			ListingUtils.deleteCreateData(address, thisDT, program);
			TypedefDataType wordDT = Word.getDataType(path, manager);
			long count = MemoryUtils.readNumber(address, wordDT.getLength(), program);
			address = address.add(thisDT.getLength());
			for (int i = 0; i < count; i++) {
				address = TVmtMethodEntry.putObject(address, path, program);
			}
			return address;
		} catch (MemoryAccessException e) {
			return null;
		}
	}
}
