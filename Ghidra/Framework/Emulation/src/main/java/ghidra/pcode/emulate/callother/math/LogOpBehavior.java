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
package ghidra.pcode.emulate.callother.math;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.floatformat.FloatFormat;
import ghidra.pcode.floatformat.FloatFormatFactory;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.utils.BigDecimalUtil;
import ghidra.program.model.pcode.Varnode;

import java.math.BigDecimal;
import java.math.BigInteger;

public class LogOpBehavior implements OpBehaviorOther {

	@Override
	public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
		MemoryState memoryState = emu.getMemoryState();
		BigInteger in = memoryState.getBigInteger(inputs[1], true);
		FloatFormat format = FloatFormatFactory.getFloatFormat(inputs[1].getSize());
		BigDecimal res = BigDecimalUtil.log(new BigDecimal("2.0"), format.decodeBigFloat(in).toBigDecimal());
		BigInteger encoding = format.getEncoding(format.getBigFloat(res));
		memoryState.setValue(out, encoding);
	}
}
