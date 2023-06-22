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
package ghidra.app.plugin.core.analysis;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Float10DataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class X86Analyzer extends ConstantPropagationAnalyzer {

	private final static String PROCESSOR_NAME = "x86";

	public X86Analyzer() {
		super(PROCESSOR_NAME);
	}

	private final byte[] INITARRAY = new byte[] {
		(byte) 0xfe, (byte) 0x8a, (byte) 0x1b, (byte) 0xcd, (byte) 0x4b, // L2T bytes, decimal value is:
		(byte) 0x78, (byte) 0x9a, (byte) 0xd4, (byte) 0x00, (byte) 0x40, // 3.3219280948873623478083405569094566089916042983531951904296875
		(byte) 0xbb, (byte) 0xf0, (byte) 0x17, (byte) 0x5c, (byte) 0x29, // L2E bytes, decimal value is:
		(byte) 0x3b, (byte) 0xaa, (byte) 0xb8, (byte) 0xff, (byte) 0x3f, // 1.442695040888963407279231565549793003810918889939785003662109375
		(byte) 0x34, (byte) 0xc2, (byte) 0x68, (byte) 0x21, (byte) 0xa2, // PI bytes, decimal value is:
		(byte) 0xda, (byte) 0x0f, (byte) 0xc9, (byte) 0x00, (byte) 0x40, // 3.141592653589793238295968524909085317631252110004425048828125
		(byte) 0x98, (byte) 0xf7, (byte) 0xcf, (byte) 0xfb, (byte) 0x84, // LG2 bytes, decimal value is:
		(byte) 0x9a, (byte) 0x20, (byte) 0x9a, (byte) 0xfd, (byte) 0x3f, // 0.30102999566398119519854137404735183736192993819713592529296875
		(byte) 0xab, (byte) 0x79, (byte) 0xcf, (byte) 0xd1, (byte) 0xf7, // LN2 bytes, decimal value is:
		(byte) 0x17, (byte) 0x72, (byte) 0xb1, (byte) 0xfe, (byte) 0x3f, // 0.6931471805599453093744803655607000791860627941787242889404296875
	};

	private void updateFPUConstants(Program program) {
		if (program.getMemory().getBlock("FPUConsts") != null) return;
		try {
			AddressSpace spc = program.getAddressFactory().getAddressSpace("FPUConsts");
			Address start = spc.getAddress(0);
			InputStream in = new ByteArrayInputStream(INITARRAY);
			MemoryBlockUtils.createInitializedBlock(program, false, "FPUConsts", start, in, 50, "", "", true, false, false, new MessageLog(), TaskMonitor.DUMMY);
		} catch (AddressOverflowException e) {
			return;
		}
		try {
			Listing listing = program.getListing();
			SymbolTable symbolTable = program.getSymbolTable();
			AddressSpace spc = program.getAddressFactory().getAddressSpace("FPUConsts");
			Address addr = spc.getAddress(0);
			listing.createData(addr, Float10DataType.dataType);
			symbolTable.createLabel(addr, "L2T", SourceType.ANALYSIS);
			addr = addr.add(10);
			listing.createData(addr, Float10DataType.dataType);
			symbolTable.createLabel(addr, "L2E", SourceType.ANALYSIS);
			addr = addr.add(10);
			listing.createData(addr, Float10DataType.dataType);
			symbolTable.createLabel(addr, "PI" , SourceType.ANALYSIS);
			addr = addr.add(10);
			listing.createData(addr, Float10DataType.dataType);
			symbolTable.createLabel(addr, "LG2", SourceType.ANALYSIS);
			addr = addr.add(10);
			listing.createData(addr, Float10DataType.dataType);
			symbolTable.createLabel(addr, "LN2", SourceType.ANALYSIS);
		} catch (Exception e) {}
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart, AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
		
		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		ConstantPropagationContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor, trustWriteMemOption) {
			
			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				String mnemonic = instr.getMnemonicString();
				if (mnemonic.equals("LEA")) {
					Register reg = instr.getRegister(0);
					if (reg != null) {
						BigInteger val = context.getValue(reg, false);
						if (val != null) {
							long lval = val.longValue();
							Address refAddr = instr.getMinAddress().getNewAddress(lval);
							if ((lval > 4096 || lval < 0) && program.getMemory().contains(refAddr)) {
								if (instr.getOperandReferences(1).length == 0) {
									instr.addOperandReference(1, refAddr, RefType.DATA,
										SourceType.ANALYSIS);
								}
							}
						}
					}
				}
				if (instr.getMnemonicString().equals("FLDL2T")) {
					updateFPUConstants(instr.getProgram());
				}
				if (instr.getMnemonicString().equals("FLDL2E")) {
					updateFPUConstants(instr.getProgram());
				}
				if (instr.getMnemonicString().equals("FLDPI")) {
					updateFPUConstants(instr.getProgram());
				}
				if (instr.getMnemonicString().equals("FLDLG2")) {
					updateFPUConstants(instr.getProgram());
				}
				if (instr.getMnemonicString().equals("FLDLN2")) {
					updateFPUConstants(instr.getProgram());
				}
				return false;
			}

			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop,
					Address address, int size, DataType dataType, RefType refType) {

				// don't allow flow references to locations not in memory if the location is not external.
				if (refType.isFlow() && !instr.getMemory().contains(address) &&
					!address.isExternalAddress()) {
					return false;
				}

				return super.evaluateReference(context, instr, pcodeop, address, size, dataType, refType);
			}
		};
	
		eval.setTrustWritableMemory(trustWriteMemOption)
		    .setMinpeculativeOffset(minSpeculativeRefAddress)
		    .setMaxSpeculativeOffset(maxSpeculativeRefAddress)
		    .setMinStoreLoadOffset(minStoreLoadRefAddress)
		    .setCreateComplexDataFromPointers(createComplexDataFromPointers);
		
		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		return resultSet;
	}
}
