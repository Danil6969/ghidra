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
package ghidra.pcode.emulate.callother;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.utils.Utils;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.program.model.pcode.Varnode;

import java.math.BigInteger;

public class InsertIndexedOpBehavior implements OpBehaviorOther {

	@Override
	public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {

		if (out == null) {
			throw new LowlevelError("CALLOTHER: Insert Indexed op missing required output");
		}

		if (inputs.length != 4) {
			throw new LowlevelError("CALLOTHER: Insert Indexed op requires three varnode input");
		}

		if (inputs[1].isConstant() || inputs[2].isConstant()) { // the index might be constant though
			throw new LowlevelError("CALLOTHER: Insert Indexed op requires non-constant arrays");
		}

		if (inputs[3].getSize() > 8) { // anything sized beyond 8 bytes is rather array than a valid number
			throw new LowlevelError("CALLOTHER: Insert Indexed op requires a numeric index");
		}

		MemoryState memoryState = emu.getMemoryState();
		Varnode in1 = inputs[1];
		Varnode in2 = inputs[2];
		Varnode in3 = inputs[3];

		if (memoryState.getValue(in3) * 8 > Integer.MAX_VALUE || memoryState.getValue(in3) * 8 < 0) {
			// less than zero means that unsigned value is more than 0x7fffffff which is not valid anyway
			throw new LowlevelError("CALLOTHER: Insert Indexed op emulator has encountered a too big index value");
		}

		int shift = (int) memoryState.getValue(in3) * 8;
		if (in1.getSize() > 8 || in2.getSize() > 8 || out.getSize() > 8) {
			BigInteger mask = Utils.calc_bigmask(in2.getSize()).shiftLeft(shift);
			mask = Utils.calc_bigmask(in1.getSize()).andNot(mask);
			BigInteger res = memoryState.getBigInteger(in1, false).and(mask);
			res = res.or(memoryState.getBigInteger(in2, false).shiftLeft(shift));
			memoryState.setValue(out, res);
		}
		else {
			long mask = Utils.calc_mask(in2.getSize()) << (shift);
			mask = Utils.calc_mask(in1.getSize()) & ~mask;
			long res = memoryState.getValue(in1) & mask;
			res = (res | memoryState.getValue(in2)) << (shift);
			memoryState.setValue(out, res);
		}
	}
}
