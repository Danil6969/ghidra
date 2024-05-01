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
package ghidra.program.model.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

public class ListingUtils {
	public static Data deleteCreateData(Address address, DataType dataType, Program program) {
		Listing listing = program.getListing();
		if (address == null) return null;
		if (address.getOffset() == 0) return null;
		Data data = listing.getDataAt(address);
		if (dataType == null) {
			if (data != null) {
				listing.clearCodeUnits(address, address, false);
			}
			return null;
		}
		if (data != null) {
			if (data.getDataType().equals(dataType)) return data;
			if (data.getDataType().isEquivalent(dataType)) return data;
		}
		Address clearAddr = address;
		while (true) {
			try {
				data = listing.createData(address, dataType);
				return data; // No further clearing is required so return immediately
			}
			catch (CodeUnitInsertionException e) {}
			data = listing.getDataAt(clearAddr);
			if (data != null) { // May encounter no data at this position so a check is required
				listing.clearCodeUnits(clearAddr, clearAddr, false);
			}
			clearAddr = clearAddr.add(1); // Displace clearing address 1 byte forward and make a next try
		}
	}
}
