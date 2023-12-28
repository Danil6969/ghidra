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

public class INTPTR_TDataType extends AbstractSignedIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined INTPTR_TDataType instance.*/
	public final static INTPTR_TDataType dataType = new INTPTR_TDataType();

	public INTPTR_TDataType() {
		this(null);
	}

	public INTPTR_TDataType(DataTypeManager dtm) {
		super("intptr_t", dtm);
	}

	@Override
	public String getDescription() {
		return "Signed Memsize Integer";
	}

	@Override
	public int getLength() {
		return dataMgr.getDataOrganization().getPointerSize();
	}

	@Override
	public UINTPTR_TDataType getOppositeSignednessDataType() {
		return UINTPTR_TDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public INTPTR_TDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new INTPTR_TDataType(dtm);
	}

}
