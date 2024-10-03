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
#include "printgo.hh"
#include "funcdata.hh"

namespace ghidra {

const string PrintGo::KEYWORD_FALLTHROUGH = "fallthrough";

// Constructing this registers the capability
PrintGoCapability PrintGoCapability::printGoCapability;

PrintGoCapability::PrintGoCapability(void)

{
  name = "go-language";
  isdefault = false;
}

PrintLanguage *PrintGoCapability::buildLanguage(Architecture *glb)

{
  return new PrintGo(glb,name);
}

PrintGo::PrintGo(Architecture *glb,const string &nm) : PrintC(glb,nm)

{
  resetDefaultsPrintGo();
  nullToken = "nil";			// Go standard lower-case 'nil'
  if (castStrategy != (CastStrategy *)0)
    delete castStrategy;

  castStrategy = new CastStrategyC();
}

void PrintGo::resetDefaults(void)

{
  PrintC::resetDefaults();
  resetDefaultsPrintGo();
}

void PrintGo::docFunction(const Funcdata *fd)

{
  bool singletonFunction = false;
  if (curscope == (const Scope *)0) {
    singletonFunction = true;
    // Always assume we are in the scope of the parent class
    pushScope(fd->getScopeLocal()->getParent());
  }
  PrintC::docFunction(fd);
  if (singletonFunction)
    popScope();
}

void PrintGo::adjustTypeOperators(void)

{
  scope.print1 = ".";
  shift_right.print1 = ">>";
  TypeOp::selectLanguageOperators(glb->inst,"c");
}

void PrintGo::resetDefaultsPrintGo(void)

{
  option_NULL = true;			// Automatically use 'null' token
  option_convention = false;		// Automatically hide convention name
  mods |= hide_thisparam;		// turn on hiding of 'this' parameter
}

bool PrintGo::fallthroughPrints(FlowBlock *bl2)

{
  PcodeOp *op = bl2->lastOp();
  OpCode opc = op->code();
  if (opc == CPUI_RETURN) return false;
  return true;
}

void PrintGo::emitBlockSwitch(const BlockSwitch *bl)

{
  FlowBlock *bl2;

  pushMod();
  unsetMod(no_branch|only_branch);
  pushMod();
  setMod(no_branch);
  bl->getSwitchBlock()->emit(this);
  popMod();
  emit->tagLine();
  pushMod();
  setMod(only_branch|comma_separate);
  bl->getSwitchBlock()->emit(this);
  popMod();
  emit->openBrace(OPEN_CURLY,option_brace_switch);

  for(int4 i=0;i<bl->getNumCaseBlocks();++i) {
    emitSwitchCase(i,bl);
    int4 id = emit->startIndent();
    if (bl->getGotoType(i)!=0) {
      emit->tagLine();
      emitGotoStatement(bl->getBlock(0),bl->getCaseBlock(i),bl->getGotoType(i));
    }
    else {
      bl2 = bl->getCaseBlock(i);
      int4 id2 = emit->beginBlock(bl2);
      bl2->emit(this);
      if (i!=bl->getNumCaseBlocks()-1) {
	if (!bl->isExit(i)&&fallthroughPrints(bl2)) {	// Blocks that formally don't exit the switch
	  emit->tagLine();
	  emitGotoStatement(bl2,(const FlowBlock *)0,FlowBlock::f_fallthrough_goto); // need an explicit fallthrough statement
	}
      }
      emit->endBlock(id2);
    }
    emit->stopIndent(id);
  }
  emit->tagLine();
  emit->print(CLOSE_CURLY);
  popMod();
}

} // End namespace ghidra
