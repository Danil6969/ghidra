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

import ghidra.program.model.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation;

public class TVmt {
	public static StructureDataType getDataType(long maxLength, CategoryPath path, DataTypeManager manager) {
		TypedefDataType SizeIntDT = SizeInt.getDataType(path, manager);
		if (SizeIntDT == null) return null;
		PointerDataType pointerDT = PointerDataType.dataType;
		int pointerSize = pointerDT.getLength();
		StructureDataType dt = new StructureDataType(path, "TVmt", 0, manager);
		dt.add(pointerDT, "SelfPtr", "Pointer to self");
		dt.add(pointerDT, "IntfTable", "Pointer to interfaces table");
		dt.add(pointerDT, "AutoTable", "Pointer to Automation interfaces table");
		dt.add(pointerDT, "InitTable", "Pointer to initialization information");
		dt.add(PTypeInfo.getDataType(path, manager), "TypeInfo", "Pointer to class type info record");
		dt.add(PVmtFieldTable.getDataType(path, manager), "FieldTable", "Pointer to table with field information");
		dt.add(PVmtMethodTable.getDataType(path, manager), "MethodTable", "Pointer to table with virtual methods");
		dt.add(pointerDT, "DynamicTable", "Pointer to table with dynamic methods");
		dt.add(PShortString.getDataType(path, manager), "ClassName", "Pointer to shortstring with classname");
		dt.add(SizeIntDT, "InstanceSize", "Class instance size");
		dt.add(pointerDT, "Parent", "Pointer to parent VMT");
		while (dt.getLength() < maxLength - (maxLength % pointerSize)) {
			dt.add(pointerDT);
		}
		while (dt.getLength() < maxLength) {
			dt.add(Undefined.getUndefinedDataType(1));
		}
		return dt;
	}

	public static Address putObject(Address address, long maxLength, CategoryPath path, Program program) {
		ProgramBasedDataTypeManager manager = program.getDataTypeManager();
		StructureDataType TVmtDT = TVmt.getDataType(maxLength, path, manager);
		PointerDataType pointerDT = PointerDataType.dataType;
		PascalString255DataType stringDT = PascalString255DataType.dataType;
		Address startAddress = address;
		ListingUtils.deleteCreateData(address, TVmtDT, program);
		address = address.add(pointerDT.getLength());
		address = address.add(pointerDT.getLength());
		address = address.add(pointerDT.getLength());
		address = address.add(pointerDT.getLength());
		Address vmtTypeInfo = MemoryUtils.readPointer(address, program);
		if (vmtTypeInfo != null) {
			TTypeInfo.putObject(vmtTypeInfo, path, program);
		}
		address = address.add(pointerDT.getLength());
		Address vmtFieldTable = MemoryUtils.readPointer(address, program);
		if (vmtFieldTable != null) {
			TVmtFieldTable_0.putObject(vmtFieldTable, path, program);
		}
		address = address.add(pointerDT.getLength());
		Address vmtMethodTable = MemoryUtils.readPointer(address, program);
		if (vmtMethodTable != null) {
			TVmtMethodTable_0.putObject(vmtMethodTable, path, program);
		}
		address = address.add(pointerDT.getLength());
		address = address.add(pointerDT.getLength());
		Address vmtClassName = MemoryUtils.readPointer(address, program);
		if (vmtClassName != null) {
			ListingUtils.deleteCreateData(vmtClassName, stringDT, program);
		}
		return startAddress.add(maxLength);
	}

	public static boolean isValid(Address address, long maxLength, Relocation[] relocations, Program program) {
		try {
			int pointerSize = PointerDataType.dataType.getLength();
			for (int i = 0; i < 9; i++) {
				if (!MemoryUtils.containsValidPointer(address.add(pointerSize * i), relocations, program)) {
					return false;
				}
			}
			Address nextaddress = address.add(pointerSize * 10);
			nextaddress = nextaddress.add(4);
			while (nextaddress.getOffset() < address.add(maxLength).getOffset()) {
				if (!MemoryUtils.containsValidPointer(nextaddress, relocations, program)) {
					return false;
				}
				nextaddress = nextaddress.add(pointerSize);
			}
			nextaddress = address.add(pointerSize * 4);
			nextaddress = MemoryUtils.readPointer(nextaddress, program);
			long kind = MemoryUtils.readNumber(nextaddress, 1, program);
			if (kind < 0 || kind > 22 ) {
				return false;
			}
			nextaddress = nextaddress.add(1);
			String str1 = MemoryUtils.readPascalString(nextaddress, program);
			if (str1 == null) {
				return false;
			}
			nextaddress = address.add(pointerSize * 8);
			nextaddress = MemoryUtils.readPointer(nextaddress, program);
			String str2 = MemoryUtils.readPascalString(nextaddress, program);
			return str1.equals(str2);
		} catch (MemoryAccessException e) {
			return false; // Shouldn't hit exception during parsing
		}
	}

	public static String getVMTTypeName(Address address, Program program) {
		if (address == null) return null;
		Memory memory = program.getMemory();
		Address fieldaddress = address.add(PointerDataType.dataType.getLength() * 8);
		Address stringaddress = MemoryUtils.readPointer(fieldaddress, program);
		if (stringaddress == null) return null;
		return MemoryUtils.readPascalString(stringaddress, program);
	}
}
