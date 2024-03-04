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
package ghidra.program.model.data;

import ghidra.program.model.lang.CompilerSpec;

/**
 * <code>GenericCallingConvention</code> identifies the generic calling convention
 * associated with a specific function definition.  This can be used to help identify
 * the appropriate compiler-specific function prototype (i.e., calling convention).
 * 
 * @deprecated Calling convention name strings should be used instead of this class.
 * {@link CompilerSpec} provides constants for those included in this enumeration and other
 * setter/getter methods exist for using the string form.
 */
public enum GenericCallingConvention {

	/**
	 * The calling convention has not been identified
	 */
	unknown(""),

	/**
	 * A MS Windows specific calling convention applies in which
	 * the called-function is responsible for purging the stack.
	 */
	stdcall(CompilerSpec.CALLING_CONVENTION_stdcall),

	/**
	 * The standard/default calling convention applies
	 * in which the stack is used to pass parameters
	 */
	cdecl(CompilerSpec.CALLING_CONVENTION_cdecl),

	/**
	 * A standard/default calling convention applies
	 * in which only registers are used to pass parameters
	 */
	fastcall(CompilerSpec.CALLING_CONVENTION_fastcall),

	/**
	 * A C++ instance method calling convention applies
	 */
	thiscall(CompilerSpec.CALLING_CONVENTION_thiscall),

	/**
	 * Similar to fastcall but extended vector registers are used
	 */
	vectorcall(CompilerSpec.CALLING_CONVENTION_vectorcall),

	// Append new conventions to the bottom only so that ordinal values will not change!!
	asm("asm"),
	asmA("__asmA"),
	asmAF("__asmAF"),
	asmAlongcall("__asmA_longcall"),
	asmxgate("__asm_xgate"),
	cdecl16far("__cdecl16far"),
	cdecl16near("__cdecl16near"),
	cdeclf("__cdeclf"),
	keilmxs2p1("__keilmxs2p1"),
	keilmxs3("__keilmxs3"),
	microsoftlto1("__microsoft_lto_1"),
	microsoftlto2("__microsoft_lto_2"),
	microsoftlto3("__microsoft_lto_3"),
	MSABI("MSABI"),
	nonwindowcall("__nonwindowcall"),
	ptrcall("__ptrcall"),
	ptrcall2("__ptrcall2"),
	regcall("__regcall"),
	register("__register"),
	retina("ret_in_a"),
	retinr7("ret_in_r7"),
	stackcall("__stackcall"),
	stdcall16far("__stdcall16far"),
	stdcall16near("__stdcall16near"),
	stdcalldata("__stdcall_data"),
	syscall("syscall");

	private final String declarationName;

	private GenericCallingConvention(String declarationName) {
		this.declarationName = declarationName;
	}

	public String getDeclarationName() {
		return declarationName;
	}

	@Override
	public String toString() {
		return declarationName;
	}

	/**
	 * Returns the GenericCallingConvention corresponding to the specified
	 * type string or unknown if name is not defined.
	 * @param callingConvention calling convention declaration name (e.g., "__stdcall")
	 * @return GenericCallingConvention or {@link #unknown} if not found.
	 */
	public static GenericCallingConvention getGenericCallingConvention(String callingConvention) {
		for (GenericCallingConvention value : GenericCallingConvention.values()) {
			if (value.name().equalsIgnoreCase(callingConvention)) {
				return value;
			}
		}
		return unknown;
	}

	/**
	 * Returns the GenericCallingConvention corresponding to the specified
	 * ordinal.
	 * @param ordinal generic calling convention ordinal
	 * @return GenericCallingConvention
	 */
	public static GenericCallingConvention get(int ordinal) {
		GenericCallingConvention[] values = GenericCallingConvention.values();
		if (ordinal >= 0 && ordinal < values.length) {
			return values[ordinal];
		}
		return unknown;
	}

}
