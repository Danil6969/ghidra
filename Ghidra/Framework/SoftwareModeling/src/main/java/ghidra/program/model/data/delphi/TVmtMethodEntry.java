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

public class TVmtMethodEntry {
	public static StructureDataType getDataType(CategoryPath path, DataTypeManager manager) {
		StructureDataType dt = new StructureDataType(path, "TVmtMethodEntry", 0, manager);
		dt.add(Word.getDataType(path, manager), "Len", "");
		dt.add(CodePointer.getDataType(path, manager), "CodeAddress", "");
		dt.add(new ArrayDataType(CharDataType.dataType, 0, 1), "Name", "");
		return dt;
	}
}
