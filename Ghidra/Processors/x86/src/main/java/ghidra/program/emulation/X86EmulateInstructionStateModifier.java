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
package ghidra.program.emulation;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.*;
import ghidra.pcode.emulate.callother.math.*;

public class X86EmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	public X86EmulateInstructionStateModifier(Emulate emu) {
		super(emu);

		registerPcodeOpBehavior("extractind", new ExtractIndexedOpBehavior());
		registerPcodeOpBehavior("insertind", new InsertIndexedOpBehavior());
		registerPcodeOpBehavior("log2", new LogOpBehavior());
	}

}
