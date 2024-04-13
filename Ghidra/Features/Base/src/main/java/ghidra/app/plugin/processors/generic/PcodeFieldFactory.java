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
package ghidra.app.plugin.processors.generic;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.pcode.AttributedStringPcodeFormatter;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.pcode.utils.InjectionUtils;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.util.PcodeFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * Pcode field factory.
 */
public class PcodeFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "PCode";

	private final static String GROUP_TITLE = "Pcode Field";
	public final static String MAX_DISPLAY_LINES_MSG =
		GROUP_TITLE + Options.DELIMITER + "Maximum Lines To Display";
	public static final String DISPLAY_RAW_PCODE =
		GROUP_TITLE + Options.DELIMITER + "Display Raw Pcode";
	public final static int MAX_DISPLAY_LINES = 30;

	private AttributedStringPcodeFormatter formatter;

	public PcodeFieldFactory() {
		super(FIELD_NAME);
		setWidth(300);
	}

	public PcodeFieldFactory(String name, FieldFormatModel model,
			ListingHighlightProvider highlightProvider, Options displayOptions,
			Options fieldOptions) {

		super(name, model, highlightProvider, displayOptions, fieldOptions);
		setWidth(300);
		style = displayOptions.getInt(OptionsGui.BYTES.getStyleOptionName(), -1);
		formatter = new AttributedStringPcodeFormatter();

		setOptions(fieldOptions);
		formatter.setFontMetrics(getMetrics());
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel myModel,
			ListingHighlightProvider highlightProvider,
			ToolOptions options, ToolOptions fieldOptions) {
		return new PcodeFieldFactory(FIELD_NAME, myModel, highlightProvider, options, fieldOptions);
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();

		if (!enabled || !(obj instanceof Instruction)) {
			return null;
		}
		Instruction instr = (Instruction) obj;

		List<FieldElement> elements = new ArrayList<>();

		PcodeOp[] arr = instr.getPcode(true);
		arr = processPcodeInject1(arr, instr);
		arr = processPcodeInject2(arr, instr);
		arr = processPcodeInject3(arr, instr);

		addCpoolRefInfo(arr, instr);
		List<AttributedString> pcodeListing = formatter.formatOps(instr.getProgram().getLanguage(),
			instr.getProgram().getAddressFactory(), Arrays.asList(arr));
		int lineCnt = pcodeListing.size();
		for (int i = 0; i < lineCnt; i++) {
			elements.add(new TextFieldElement(pcodeListing.get(i), i, 0));
		}

		if (elements.size() > 0) {
			return ListingTextField.createMultilineTextField(this, proxy, elements,
				startX + varWidth, width, hlProvider);
		}
		return null;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (loc instanceof PcodeFieldLocation) {
			return new FieldLocation(index, fieldNum, ((PcodeFieldLocation) loc).getRow(),
				((PcodeFieldLocation) loc).getCharOffset());
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField listingField) {
		ProxyObj<?> proxy = listingField.getProxy();
		Object obj = proxy.getObject();

		if (!(obj instanceof Instruction)) {
			return null;
		}

		if (row < 0 || col < 0) {
			return null;
		}

		Instruction instr = (Instruction) obj;
		Program program = instr.getProgram();

		List<AttributedString> attributedStrings = formatter.formatOps(program.getLanguage(),
			program.getAddressFactory(), Arrays.asList(instr.getPcode(true)));
		List<String> strings = new ArrayList<>(attributedStrings.size());
		for (AttributedString attributedString : attributedStrings) {
			strings.add(attributedString.getText());
		}

		return new PcodeFieldLocation(program, instr.getMinAddress(), strings, row, col);
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return (CodeUnit.class.isAssignableFrom(proxyObjectClass) &&
			(category == FieldFormatModel.INSTRUCTION_OR_DATA ||
				category == FieldFormatModel.OPEN_DATA));
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.displayOptionsChanged(options, optionName, oldValue, newValue);
		formatter.setFontMetrics(getMetrics());
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.fieldOptionsChanged(options, optionName, oldValue, newValue);

		if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {
			if (optionName.equals(MAX_DISPLAY_LINES_MSG) || optionName.equals(DISPLAY_RAW_PCODE)) {
				setOptions(options);
				model.update();
			}
		}
	}

	private void setOptions(Options fieldOptions) {
		fieldOptions.registerOption(MAX_DISPLAY_LINES_MSG, MAX_DISPLAY_LINES, null,
			"Max number line of pcode to display");
		fieldOptions.registerOption(DISPLAY_RAW_PCODE, false, null,
			"Display raw pcode (for debugging)");
		int maxDisplayLines = fieldOptions.getInt(MAX_DISPLAY_LINES_MSG, MAX_DISPLAY_LINES);
		boolean displayRaw = fieldOptions.getBoolean(DISPLAY_RAW_PCODE, false);
		formatter.setOptions(maxDisplayLines, displayRaw);
	}

	private PcodeOp[] processPcodeInject1(PcodeOp[] mainPcode, Instruction instr) {
		//3)CALLMECHANISM : uponentry
		//formatter.removeComments(instr.getAddress(), "of uponentry injection");
		PcodeOp[] injectionPcode = InjectionUtils.getEntryPcodeOps(instr);
		if (injectionPcode != null) {
			PcodeOp[] arr = new PcodeOp[injectionPcode.length + mainPcode.length];
			//formatter.addComment(instr.getAddress(), 0, "start of uponentry injection");
			System.arraycopy(injectionPcode, 0, arr, 0, injectionPcode.length);
			System.arraycopy(mainPcode, 0, arr, injectionPcode.length, mainPcode.length);
			formatter.addComment(arr[arr.length - 1], "end of uponentry injection");
			return arr;
		}
		return mainPcode;
	}

	private PcodeOp[] processPcodeInject2(PcodeOp[] mainPcode, Instruction instr) {
		//3)CALLMECHANISM : uponreturn
		//formatter.removeComments(instr.getAddress(), "of uponreturn injection");
		PcodeOp[] arr;
		for (int i = 0; i < mainPcode.length; i++) {
			PcodeOp[] injectionPcode = InjectionUtils.getReturnPcodeOps(instr, mainPcode[i]);
			if (injectionPcode != null) {
				arr = mainPcode;
				mainPcode = new PcodeOp[arr.length + injectionPcode.length];
				System.arraycopy(arr, 0, mainPcode, 0, i + 1);
				formatter.addComment(mainPcode[i], "start of uponreturn injection");
				System.arraycopy(injectionPcode, 0, mainPcode, i + 1, injectionPcode.length);
				System.arraycopy(arr, i + 1, mainPcode, i + 1 + injectionPcode.length, arr.length - i - 1);
				formatter.addComment(mainPcode[i + injectionPcode.length], "end of uponreturn injection");
			}
		}
		return mainPcode;
	}

	private PcodeOp[] processPcodeInject3(PcodeOp[] mainPcode, Instruction instr) {
		//2)CALLOTHERFIXUP_TYPE
		//formatter.removeComments(instr.getAddress(), "of callother implementation");
		PcodeOp[] arr;
		for (int i = 0; i < mainPcode.length; i++) {
			PcodeOp[] injectionPcode = InjectionUtils.getCallotherPcodeOps(instr, mainPcode[i]);
			if (injectionPcode != null) {
				arr = mainPcode;
				mainPcode = new PcodeOp[arr.length + injectionPcode.length];
				System.arraycopy(arr, 0, mainPcode, 0, i + 1);
				formatter.addComment(mainPcode[i], "start of callother implementation");
				System.arraycopy(injectionPcode, 0, mainPcode, i + 1, injectionPcode.length);
				formatter.addComment(mainPcode[i + injectionPcode.length], "end of callother implementation");
				System.arraycopy(arr, i + 1, mainPcode, i + 1 + injectionPcode.length, arr.length - i - 1);
			}
		}
		return mainPcode;
	}

	private void addCpoolRefInfo(PcodeOp[] mainPcode, Instruction instr) {
		//formatter.removeComments(instr.getAddress(), "CPOOL");
		Program program = instr.getProgram();
		ConstantPool cpool;
		try {
			cpool = program.getCompilerSpec().getPcodeInjectLibrary().getConstantPool(program);
		} catch (IOException e) {
			cpool = null;
		}
		PcodeOp op;
		for (int i = 0; i < mainPcode.length; i++) {
			op = mainPcode[i];
			if (op.getOpcode() == PcodeOp.CPOOLREF && cpool != null) {
				long[] refs = new long[op.getInputs().length - 1];
				for (int j = 1; j < op.getInputs().length; j++)
					refs[j - 1] = op.getInput(j).getOffset();
				ConstantPool.Record rec = cpool.getRecord(refs);
				formatter.addComment(mainPcode[i], getCpoolComment(rec));
			}
		}
	}

	private String getCpoolComment(ConstantPool.Record record) {
		String EOL = System.getProperty("line.separator");
		StringBuilder sb = new StringBuilder();
		sb.append("//CPOOL tag: ");
		sb.append(resolveTagStr(record.tag));
		sb.append(EOL);
		if (record.token != null) {
			sb.append("//CPOOL token: ");
			sb.append(record.token);
			sb.append(EOL);
		}
		if (record.value != 0) {
			sb.append("//CPOOL value: ");
			sb.append(record.value);
			sb.append(EOL);
		}
		if (record.byteData != null) {
			sb.append("//CPOOL byteData: ");
			sb.append(Arrays.toString(record.byteData));
			sb.append(EOL);
		}
		if (record.type != null) {
			sb.append("//CPOOL type: ");
			sb.append(record.type);
			sb.append(EOL);
		}
		if (record.isConstructor) {
			sb.append("//CPOOL has isConstructor flag");
		}
		return sb.toString();
	}

	private String resolveTagStr(int type) {
		switch (type) {
			case ConstantPool.PRIMITIVE:
				return "primitive";
			case ConstantPool.STRING_LITERAL:
				return "string";
			case ConstantPool.CLASS_REFERENCE:
				return "classref";
			case ConstantPool.POINTER_METHOD:
				return "method";
			case ConstantPool.POINTER_FIELD:
				return "field";
			case ConstantPool.ARRAY_LENGTH:
				return "arraylength";
			case ConstantPool.INSTANCE_OF:
				return "instanceof";
			case ConstantPool.CHECK_CAST:
				return "checkcast";
			default:
				return "unknown";
		}
	}
}
