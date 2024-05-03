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
package ghidra.program.model.data;

public class UINTPTR_TDataType extends AbstractUnsignedIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined UINTPTR_TDataType instance.*/
	public final static UINTPTR_TDataType dataType = new UINTPTR_TDataType();

	public UINTPTR_TDataType() {
		this(null);
	}

	public UINTPTR_TDataType(DataTypeManager dtm) {
		super("uintptr_t", dtm);
	}

	@Override
	public String getDescription() {
		return "Unsigned Memsize Integer";
	}

	@Override
	public int getLength() {
		return dataMgr.getDataOrganization().getPointerSize();
	}

	@Override
	public INTPTR_TDataType getOppositeSignednessDataType() {
		return INTPTR_TDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public UINTPTR_TDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UINTPTR_TDataType(dtm);
	}

}
