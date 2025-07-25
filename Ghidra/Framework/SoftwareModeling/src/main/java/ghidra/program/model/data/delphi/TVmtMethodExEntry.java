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
import ghidra.program.model.util.*;

public class TVmtMethodExEntry {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtMethodExEntry", 0, manager);
		dt.add(PVmtMethodEntry.getDataType(path, manager), "Entry", "");
		dt.add(Word.getDataType(path, manager), "Flags", "");
		dt.add(Smallint.getDataType(path, manager), "VirtualIndex", "");
		return dt;
	}

	public static Address putObject(Address address, CategoryPath path, Program program) {
		ProgramBasedDataTypeManager manager = program.getDataTypeManager();
		StructureDataType thisDT = getDataType(path, manager);
		ListingUtils.deleteCreateData(address, thisDT, program);
		Address vmtMethodEntry = MemoryUtils.readPointer(address, program);
		address = address.add(thisDT.getLength());
		TVmtMethodEntry.putObject(vmtMethodEntry, path, program);
		return address;
	}
}
