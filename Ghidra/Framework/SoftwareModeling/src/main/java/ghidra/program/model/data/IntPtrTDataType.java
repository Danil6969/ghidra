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

public class IntPtrTDataType extends AbstractSignedIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined IntPtrTDataType instance.*/
	public final static IntPtrTDataType dataType = new IntPtrTDataType();

	public IntPtrTDataType() {
		this(null);
	}

	public IntPtrTDataType(DataTypeManager dtm) {
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
	public UIntPtrTDataType getOppositeSignednessDataType() {
		return UIntPtrTDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public IntPtrTDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new IntPtrTDataType(dtm);
	}

}
