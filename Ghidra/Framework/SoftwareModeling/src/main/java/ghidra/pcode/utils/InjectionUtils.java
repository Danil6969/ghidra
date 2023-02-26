/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Symbol;

import java.util.ArrayList;

public class InjectionUtils {

	//All methods return either non-zero length arrays or null
	//zero-length arrays unused for convenience
	public static PcodeOp[] getEntryPcodeOps (Instruction instr) {
		Program program = instr.getProgram();
		Function func = program.getFunctionManager().getFunctionAt(instr.getMinAddress());
		if (func != null) {
			PrototypeModel callingConvention = func.getCallingConvention();
			if (callingConvention == null) {
				callingConvention = program.getCompilerSpec().getDefaultCallingConvention();
			}

			String injectionName = callingConvention.getName() + "@@inject_uponentry";

			PcodeInjectLibrary snippetLibrary = program.getCompilerSpec().getPcodeInjectLibrary();
			InjectPayload payload = snippetLibrary.getPayload(InjectPayload.CALLMECHANISM_TYPE, injectionName);
			if (payload == null) {
				return null;
			}
			InjectContext con = snippetLibrary.buildInjectContext();
			con.baseAddr = instr.getMinAddress();
			con.nextAddr = con.baseAddr.add(instr.getDefaultFallThroughOffset());
			try {
				PcodeOp[] pcodeOps = payload.getPcode(program, con);
				if(pcodeOps.length == 0) {
					return null;
				}
				return pcodeOps;
			}
			catch (Exception e) {}
		}
		return null;
	}

	public static PcodeOp[] getReturnPcodeOps (Instruction instr, PcodeOp pcode) {
		Program program = instr.getProgram();
		Varnode val = pcode.getInput(0);
		String nm = null;
		Address target = null;
		if (pcode.getOpcode() == PcodeOp.CALL) {
			target = val.getAddress();
		}
		else if (pcode.getOpcode() == PcodeOp.CALLIND) {
			if (val.isConstant()) {
				target = instr.getAddress().getNewAddress(val.getOffset(), true);
			}
		}
		if (target != null) {
			Function func = program.getFunctionManager().getFunctionAt(target);
			if (func != null) {
				PrototypeModel callingConvention = func.getCallingConvention();
				if (callingConvention == null) {
					callingConvention = program.getCompilerSpec().getDefaultCallingConvention();
				}
				nm = callingConvention.getName();
			}
		}
		if (pcode.getOpcode() == PcodeOp.CALL || pcode.getOpcode() == PcodeOp.CALLIND) {
			Symbol[] symbols = program.getSymbolTable().getSymbols(instr.getMinAddress());
			for (Symbol sym : symbols) {
				DataTypeSymbol datsym = null;
				try {
					datsym = HighFunctionDBUtil.readOverride(sym);
				}
				catch (IllegalArgumentException e) {}
				if (datsym != null) {
					FunctionSignature dt = (FunctionSignature) datsym.getDataType();
					nm = dt.getGenericCallingConvention().getDeclarationName();
				}
			}
		}
		if (nm != null) {
			PcodeInjectLibrary snippetLibrary = program.getCompilerSpec().getPcodeInjectLibrary();
			String injectionName = nm + "@@inject_uponreturn";
			InjectPayload payload = snippetLibrary.getPayload(InjectPayload.CALLMECHANISM_TYPE, injectionName);
			if (payload == null) {
				return null;
			}
			InjectContext con = snippetLibrary.buildInjectContext();
			con.baseAddr = instr.getMinAddress();
			con.nextAddr = con.baseAddr.add(instr.getDefaultFallThroughOffset());
			try {
				PcodeOp[] pcodeOps = payload.getPcode(program, con);
				if (pcodeOps.length == 0) {
					return null;
				}
				return pcodeOps;
			}
			catch (Exception e) {}
		}
		return null;
	}

	public static PcodeOp[] getCallotherPcodeOps (Instruction instr, PcodeOp pcode) {
		if (pcode.getOpcode() == PcodeOp.CALLOTHER) {
			Program program = instr.getProgram();
			PcodeInjectLibrary snippetLibrary = program.getCompilerSpec().getPcodeInjectLibrary();
			String injectionName = program.getLanguage().getUserDefinedOpName((int) pcode.getInput(0).getOffset());
			ArrayList<Varnode> inputs = new ArrayList();
			StringBuilder sb = new StringBuilder();
			sb.append("<context>\n");
			sb.append("<addr space=\"" + instr.getAddress().getAddressSpace().getName());
			sb.append("\" offset=\"" + "0x" + instr.getAddress().toString(false).replaceFirst("^0+(?!$)", ""));
			sb.append("\"/><addr/><input>\n");
			for (int i = 1; i < pcode.getNumInputs(); i++) {
				inputs.add(pcode.getInput(i));
				sb.append("<addr space=\"" + pcode.getInput(i).getAddress().getAddressSpace().getName());
				sb.append("\" offset=\"" + "0x" + pcode.getInput(i).getAddress().toString(false).replaceFirst("^0+(?!$)", ""));
				sb.append("\" size=\"" + pcode.getInput(i).getSize() + "\"/>\n");
			}
			sb.append("</input>\n</context>\n");
			String context = sb.toString();
			InjectPayload payload = snippetLibrary.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, injectionName);
			if (payload == null) {
				return null;
			}
			InjectContext con = snippetLibrary.buildInjectContext();
			con.baseAddr = instr.getMinAddress();
			con.nextAddr = con.baseAddr.add(instr.getDefaultFallThroughOffset());
			con.inputlist = inputs;
			if (pcode.getOutput() != null) {
				con.output = new ArrayList();
				con.output.add(pcode.getOutput());
			}
			try {
				PcodeOp[] pcodeOps = payload.getPcode(program, con);
				if (pcodeOps.length == 0)
					pcodeOps = null;
				return pcodeOps;
			}
			catch (Exception e) {}
		}
		return null;
	}

}
