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

public class TVmtMethodTable_1 {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtMethodTable_1", 0, manager);
		StructureDataType entryDT = TVmtMethodExEntry.getDataType(path, manager);
		dt.add(Word.getDataType(path, manager), "ExCount", "");
		dt.add(new ArrayDataType(entryDT, 0, entryDT.getLength()), "ExEntry", "");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		try {
			ProgramBasedDataTypeManager manager = program.getDataTypeManager();
			ListingUtils.deleteCreateData(address, getDataType(path, manager), program);
			TypedefDataType wordDT = Word.getDataType(path, manager);
			long count = MemoryUtils.readNumber(address, wordDT.getLength(), program);
			address = address.add(wordDT.getLength());
			for (int i = 0; i < count; i++) {
				StructureDataType entryDT = TVmtMethodExEntry.getDataType(path, manager);
				ListingUtils.deleteCreateData(address, entryDT, program);
				address = address.add(entryDT.getLength());
			}
			ListingUtils.deleteCreateData(address, wordDT, program);
			address = address.add(wordDT.getLength());
			return address;
		} catch (MemoryAccessException e) {
			return null;
		}
	}
}
