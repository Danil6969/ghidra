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

public class ExtractIndexedOpBehavior implements OpBehaviorOther {

	@Override
	public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {

		if (out == null) {
			throw new LowlevelError("CALLOTHER: Extract Indexed op missing required output");
		}

		if (inputs.length != 3) {
			throw new LowlevelError("CALLOTHER: Extract Indexed op requires two varnode input");
		}

		if (inputs[1].isConstant()) { // the index might be constant though
			throw new LowlevelError("CALLOTHER: Extract Indexed op requires a non-constant array");
		}

		if (inputs[2].getSize() > 8) { // anything sized beyond 8 bytes is rather array than a valid number
			throw new LowlevelError("CALLOTHER: Extract Indexed op requires a numeric index");
		}

		MemoryState memoryState = emu.getMemoryState();
		Varnode in1 = inputs[1];
		Varnode in2 = inputs[2];

		if (memoryState.getValue(in2) * 8 > Integer.MAX_VALUE || memoryState.getValue(in2) * 8 < 0) {
			// less than zero means that unsigned value is more than 0x7fffffff which is not valid anyway
			throw new LowlevelError("CALLOTHER: Extract Indexed op emulator has encountered a too big index value");
		}

		int shift = (int) memoryState.getValue(in2) * 8;
		if (in1.getSize() > 8 || out.getSize() > 8) {
			BigInteger res = memoryState.getBigInteger(in1, false);
			res = res.shiftRight(shift);
			memoryState.setValue(out, res);
		}
		else {
			long res = memoryState.getValue(in1);
			res = (res >>> (shift)) & Utils.calc_mask(out.getSize());
			memoryState.setValue(out, res);
		}
	}
}
