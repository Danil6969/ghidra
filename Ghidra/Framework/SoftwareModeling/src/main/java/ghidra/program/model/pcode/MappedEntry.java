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
package ghidra.program.model.pcode;

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

/**
 * A normal mapping of a HighSymbol to a particular Address, consuming a set number of bytes
 */
public class MappedEntry extends SymbolEntry {
	protected VariableStorage storage;

	/**
	 * For use with restoreXML
	 * @param sym is the owning symbol
	 */
	public MappedEntry(HighSymbol sym) {
		super(sym);
	}

	/**
	 * Construct given a symbol, storage, and first-use Address
	 * @param sym is the given symbol
	 * @param store is the given storage
	 * @param addr is the first-use Address (or null)
	 */
	public MappedEntry(HighSymbol sym, VariableStorage store, Address addr) {
		super(sym);
		storage = store;
		pcaddr = addr;
	}

	@Override
	public void decode(Decoder decoder) throws DecoderException {
		if (symbol.type == null) {
			String nm = symbol.name == null ? "null" : symbol.name;
			throw new DecoderException("No data-type found for symbol: " + nm);
		}
		int sz = symbol.type.getLength();
		if (sz == 0) {
			throw new DecoderException(
				"Invalid symbol 0-sized data-type: " + symbol.type.getName());
		}
		int addrel = decoder.openElement(ElementId.ELEM_ADDR);
		storage = AddressXML.decodeStorageFromAttributes(sz, decoder, symbol.function);
		decoder.closeElement(addrel);

		decodeRangeList(decoder);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		int logicalsize = 0; // Assume datatype size and storage size are the same
		int typeLength = symbol.type.getLength();
		if (typeLength != storage.size() && symbol.type instanceof AbstractFloatDataType) {
			logicalsize = typeLength; // Force a logicalsize
		}
		AddressXML.encode(encoder, storage.getVarnodes(), logicalsize);
		encodeRangelist(encoder);
	}

	@Override
	public VariableStorage getStorage() {
		return storage;
	}

	@Override
	public int getSize() {
		return storage.size();
	}

	@Override
	public int getMutability() {
		Address addr = storage.getMinAddress();
		return getMutabilityOfAddress(addr, symbol.getProgram());
	}

	/**
	 * Get the underlying mutability setting of an Address based on the Program
	 * configuration and the MemoryBlock.  Ignore any overrides of Data at the address. 
	 * @param addr is the Address
	 * @param program is the Program containing the Address
	 * @return the mutability
	 */
	public static int getMutabilityOfAddress(Address addr, Program program) {
		if (addr == null) {
			return MutabilitySettingsDefinition.NORMAL;
		}
		if (program.getLanguage().isVolatile(addr)) {
			return MutabilitySettingsDefinition.VOLATILE;
		}
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block != null) {
			if (block.isVolatile()) {
				return MutabilitySettingsDefinition.VOLATILE;
			}
			// if the block says read-only, check the refs to the variable
			if (!block.isWrite()) {
				ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(addr);
				int count = 0;
				while (refIter.hasNext() && count < 100) {
					Reference ref = refIter.next();
					if (ref.getReferenceType().isWrite()) {
						return MutabilitySettingsDefinition.NORMAL;
					}
					count++;
				}
				return MutabilitySettingsDefinition.CONSTANT;
			}
		}
		return MutabilitySettingsDefinition.NORMAL;
	}
}
