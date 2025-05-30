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

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypedefDataType;

public class PVmtFieldTable {
	public static TypedefDataType getDataType(CategoryPath path, DataTypeManager manager) {
		PointerDataType dt = new PointerDataType(TVmtFieldTable_0.getDataType(path, manager), manager);
		return new TypedefDataType(path, "PVmtFieldTable", dt, manager);
	}
}
