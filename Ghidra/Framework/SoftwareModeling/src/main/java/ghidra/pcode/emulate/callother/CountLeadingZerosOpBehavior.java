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
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.program.model.pcode.Varnode;

import java.math.BigInteger;

public class CountLeadingZerosOpBehavior implements OpBehaviorOther {

	@Override
	public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {

		if (out == null) {
			throw new LowlevelError("CALLOTHER: Count Leading Zeros op missing required output");
		}

		if (inputs.length != 2 || inputs[1].getSize() == 0 || inputs[1].isConstant()) {
			throw new LowlevelError(
				"CALLOTHER: Count Leading Zeros op requires one non-constant varnode input");
		}

		MemoryState memoryState = emu.getMemoryState();
		Varnode in = inputs[1];
		if (in.getSize() > 8 || out.getSize() > 8) {
			BigInteger value = memoryState.getBigInteger(in, false);
			BigInteger mask = BigInteger.ONE.shiftLeft((in.getSize() * 8) - 1);
			BigInteger count = BigInteger.ZERO;
			while (!mask.equals(BigInteger.ZERO)) {
				if (!(mask.and(value)).equals(BigInteger.ZERO)) {
					break;
				}
				count = count.add(BigInteger.ONE);
				mask = mask.shiftRight(1);
			}

			memoryState.setValue(out, count);
		}
		else {
			long value = memoryState.getValue(in);
			long mask = 1L << ((in.getSize() * 8) - 1);
			long count = 0;
			while (mask != 0) {
				if ((mask & value) != 0) {
					break;
				}
				++count;
				mask >>>= 1;
			}

			memoryState.setValue(out, count);
		}
	}
}
