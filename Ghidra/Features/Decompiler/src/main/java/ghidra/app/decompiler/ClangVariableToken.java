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
package ghidra.app.decompiler;

import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

/**
 * 
 *
 * Token representing a C variable
 */
public class ClangVariableToken extends ClangToken {
	private Varnode varnode;
	private PcodeOp op;

	public ClangVariableToken(ClangNode par) {
		super(par);
		varnode = null;
		op = null;
	}

	@Override
	public Varnode getVarnode() {
		return varnode;
	}

	@Override
	public PcodeOp getPcodeOp() {
		return op;
	}

	@Override
	public Scalar getScalar() {
		if (varnode == null) {
			return null;
		}

		long offset = varnode.getOffset();
		int sz = varnode.getSize();
		HighVariable high = varnode.getHigh();
		if (!(high instanceof HighConstant)) {
			return null;
		}

		HighConstant constant = (HighConstant) high;
		boolean isSigned = true;
		DataType dt = constant.getDataType();
		if (dt instanceof AbstractIntegerDataType) {
			isSigned = ((AbstractIntegerDataType) dt).isSigned();
		}

		if (sz > 8) {
			// our Scalar can currently only handle long values
			return null;
		}

		return new Scalar(sz * 8, offset, isSigned);
	}

	@Override
	public boolean isVariableRef() {
		return true;
	}

	@Override
	public Address getMinAddress() {
		if (op == null) {
			return null;
		}
		return op.getSeqnum().getTarget();
	}

	@Override
	public Address getMaxAddress() {
		if (op == null) {
			return null;
		}
		return op.getSeqnum().getTarget();
	}

	@Override
	public HighVariable getHighVariable() {
		Varnode inst = getVarnode();
		if (inst != null) {
			HighVariable hvar = inst.getHigh();
			if (hvar != null && hvar.getRepresentative() == null) {
				Varnode[] instances = new Varnode[1];
				instances[0] = inst;
				hvar.attachInstances(instances, inst);
			}
			return inst.getHigh();
		}
		ClangNode parent = Parent();
		if (parent instanceof ClangVariableDecl) {
			return ((ClangVariableDecl) parent).getHighVariable();
		}
		return null;
	}

	@Override
	public HighSymbol getHighSymbol(HighFunction highFunction) {
		Varnode inst = getVarnode();
		if (inst != null) {
			HighVariable hvar = inst.getHigh();
			if (hvar != null) {
				HighSymbol symbol = hvar.getSymbol();
				if (symbol != null) {
					return symbol;
				}
			}
		}
		ClangNode parent = Parent();
		if (parent instanceof ClangVariableDecl) {
			return ((ClangVariableDecl) parent).getHighSymbol();
		}

		if (highFunction == null) {
			return null;
		}
		// Token may be from a variable reference, in which case we have to dig to find the actual symbol
		Address storageAddress = getStorageAddress(highFunction.getAddressFactory());
		if (storageAddress == null) {
			return null;
		}
		HighSymbol symbol = findHighSymbol(storageAddress, highFunction);    // Find symbol via the reference
		if (symbol != null) {
			return symbol;
		}

		Function function = highFunction.getFunction();
		SymbolIterator iter = function.getProgram().getSymbolTable().getSymbols(getText());
		if (!iter.hasNext()) {
			return null;
		}
		Symbol sym = iter.next();
		if (iter.hasNext()) {
			return null;
		}

		if (!(sym instanceof CodeSymbol)) {
			return null;
		}
		Object dataObj = sym.getObject();
		if (!(dataObj instanceof Data)) {
			return null;
		}

		DataType dataType = ((Data) dataObj).getDataType();
		int sz = dataType.getLength();
		symbol = new HighCodeSymbol((CodeSymbol) sym, dataType, sz, highFunction);
		return symbol;
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == AttributeId.ATTRIB_VARREF.id()) {
				int refid = (int) decoder.readUnsignedInteger();
				varnode = pfactory.getRef(refid);
			}
			else if (attribId == AttributeId.ATTRIB_OPREF.id()) {
				int refid = (int) decoder.readUnsignedInteger();
				op = pfactory.getOpRef(refid);
			}
		}
		decoder.rewindAttributes();
		super.decode(decoder, pfactory);
	}

	/**
	 * Get the storage address of the variable, if any.
	 * The variable may be directly referenced by this token, or indirectly referenced as a point.
	 * @param addrFactory is the factory used to construct the Address
	 * @return the storage Address or null if there is no variable attached
	 */
	private Address getStorageAddress(AddressFactory addrFactory) {
		Address storageAddress = null;
		if (varnode != null) {
			storageAddress = varnode.getAddress();
		}
		// op could be a PTRSUB, need to dig it out...
		else {
			storageAddress = HighFunctionDBUtil.getSpacebaseReferenceAddress(addrFactory, op);
		}
		return storageAddress;
	}

	/**
	 * Find the HighSymbol the decompiler associates with a specific address.
	 * @param addr is the specific address
	 * @param highFunction is the decompiler results in which to search for the symbol
	 * @return the matching symbol or null if no symbol exists
	 */
	private static HighSymbol findHighSymbol(Address addr, HighFunction highFunction) {
		HighSymbol highSymbol = null;
		if (addr.isStackAddress()) {
			LocalSymbolMap lsym = highFunction.getLocalSymbolMap();
			highSymbol = lsym.findLocal(addr, null);
		}
		else {
			GlobalSymbolMap gsym = highFunction.getGlobalSymbolMap();
			highSymbol = gsym.getSymbol(addr);
		}
		return highSymbol;
	}
}
