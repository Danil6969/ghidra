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
package ghidra.pcode.memstate;

import ghidra.pcode.utils.SimpleMallocMgr;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.lang.InsufficientBytesException;

import java.util.HashMap;

public class ManagedMemory {

	private ConstantPool cpool;
	private SimpleMallocMgr mallocMgr;
	private HashMap<String, Long> fields = new HashMap<>();

	public ManagedMemory(ConstantPool cpool) {
		this.cpool = cpool;
	}

	public void constructMallocMgr(Address rangeStart, int byteSize) throws AddressOverflowException {
		mallocMgr = new SimpleMallocMgr(rangeStart, byteSize);
	}

	public long getFieldPointer(long objectPointer, String token, int size) throws InsufficientBytesException {
		Long value = fields.get(objectPointer + ";" + token);
		if (value == null) {
			// field not allocated yet
			if (mallocMgr == null)
				throw new IllegalStateException("Malloc manager not set");
			value = mallocMgr.malloc(size).getOffset();
			fields.put(objectPointer + ";" + token, value);
		}
		return value;
	}
}
