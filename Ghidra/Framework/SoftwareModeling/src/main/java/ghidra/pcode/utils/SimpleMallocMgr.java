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
package ghidra.pcode.utils;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.InsufficientBytesException;

/**
 * <code>SimpleMallocMgr</code> provides a simple malloc memory manager to be used by the
 * malloc/free hooked implementations.
 */
public class SimpleMallocMgr {

	private AddressSet allocSet;
	private Map<Address, AddressRange> mallocMap = new HashMap<>();

	/**
	 * <code>SimpleMallocMgr</code> constructor.
	 * @param rangeStart start of the free malloc region (i.e., Heap) which has been
	 * deemed a safe
	 * @param byteSize
	 * @throws AddressOverflowException
	 */
	public SimpleMallocMgr(Address rangeStart, int byteSize) throws AddressOverflowException {
		allocSet = new AddressSet(
				new AddressRangeImpl(rangeStart, rangeStart.addNoWrap(byteSize - 1)));
	}

	public synchronized Address malloc(int byteLength) throws InsufficientBytesException {
		if (byteLength <= 0) {
			throw new IllegalArgumentException("malloc request for " + byteLength);
		}
		for (AddressRange range : allocSet.getAddressRanges()) {
			if (range.getLength() >= byteLength) {
				AddressRange mallocRange = new AddressRangeImpl(range.getMinAddress(),
						range.getMinAddress().add(byteLength - 1));
				mallocMap.put(mallocRange.getMinAddress(), mallocRange);
				allocSet.delete(mallocRange);
				return mallocRange.getMinAddress();
			}
		}
		throw new InsufficientBytesException(
				"SimpleMallocMgr failed to allocate " + byteLength + " bytes");
	}

	public synchronized void free(Address mallocRangeAddr) {
		AddressRange range = mallocMap.remove(mallocRangeAddr);
		if (range == null) {
			throw new IllegalArgumentException(
					"free request for unallocated block at " + mallocRangeAddr);
		}
		allocSet.add(range);
	}
}
