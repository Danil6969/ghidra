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

public class TTypeKind {
	public static EnumDataType getDataType(CategoryPath path, DataTypeManager manager) {
		EnumDataType dt = new EnumDataType(path, "TTypeKind", 1, manager);
		dt.add("tkUnknown", 0);
		dt.add("tkInteger", 1);
		dt.add("tkChar", 2);
		dt.add("tkEnumeration", 3);
		dt.add("tkFloat", 4);
		dt.add("tkString", 5);
		dt.add("tkSet", 6);
		dt.add("tkClass", 7);
		dt.add("tkMethod", 8);
		dt.add("tkWChar", 9);
		dt.add("tkLString", 10);
		dt.add("tkWString", 11);
		dt.add("tkVariant", 12);
		dt.add("tkArray", 13);
		dt.add("tkRecord", 14);
		dt.add("tkInterface", 15);
		dt.add("tkInt64", 16);
		dt.add("tkDynArray", 17);
		dt.add("tkUString", 18);
		dt.add("tkClassRef", 19);
		dt.add("tkPointer", 20);
		dt.add("tkProcedure", 21);
		dt.add("tkMRecord", 22);
		return dt;
	}
}
