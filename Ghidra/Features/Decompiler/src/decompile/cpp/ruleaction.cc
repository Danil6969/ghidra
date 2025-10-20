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
#include "constseq.hh"
#include "coreaction.hh"
#include "subflow.hh"
#include "rangeutil.hh"
#include "multiprecision.hh"

namespace ghidra {

/// \class RuleEarlyRemoval
/// \brief Get rid of unused PcodeOp objects where we can guarantee the output is unused
int4 RuleEarlyRemoval::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn;

  if (op->isCall()) return 0;	// Functions automatically consumed
  if (op->isIndirectSource()) return 0;
  vn = op->getOut();
  if (vn == (Varnode *)0) return 0;
  //  if (vn->isPersist()) return 0;
  if (!vn->hasNoDescend()) return 0;
  if (vn->isAutoLive()) return 0;
  AddrSpace *spc = vn->getSpace();
  // local (stack) variables
  if (spc->getType() == IPTR_SPACEBASE) return 0;
  // global (memory) variables
  if (spc->getType() == IPTR_PROCESSOR)
    // exclude register memory
    if (spc->getName() != "register")
      return 0;
  if (spc->doesDeadcode())
    if (!data.deadRemovalAllowedSeen(spc))
      return 0;

  data.opDestroy(op);		// Get rid of unused op
  return 1;
}

// void RuleAddrForceRelease::getOpList(vector<uint4> &oplist) const

// {
//   oplist.push_back(CPUI_COPY);
// }

// int4 RuleAddrForceRelease::applyOp(PcodeOp *op,Funcdata &data)

// {				// Clear addrforce if op->Output is contained in input
//   if (!op->Output()->isAddrForce()) return 0;
//   Varnode *outvn,*invn;
//   PcodeOp *subop;

//   outvn = op->Input(0)();
//   if (outvn->getAddr() != op->Output()->getAddr()) return 0;
//   if (!outvn->isWritten()) return 0;
//   subop = outvn->Def();
//   invn = subop->Input(0);
//   if (subop->code() == CPUI_SUBPIECE) {
//     if (0!=invn->contains(*outvn)) return 0;
//     if (!invn->terminated()) return 0; // Bigger thing is already terminated
//   }
//   else
//     return 0;

//   data.clear_addrforce(invn);	// Clear addrforce for anything contained by input
//   return 1;
// }

/// Given a Varnode term in the expression, check if the last operation producing it
/// is to multiply by a constant.  If so pass back the constant coefficient and
/// return the underlying Varnode. Otherwise pass back the constant 1, and return
/// the original Varnode
/// \param vn is the given Varnode
/// \param coef is the reference for passing back the coefficient
/// \return the underlying Varnode of the term
Varnode *RuleCollectTerms::getMultCoeff(Varnode *vn,uintb &coef)

{
  PcodeOp *testop;
  if (!vn->isWritten()) {
    coef = 1;
    return vn;
  }
  testop = vn->getDef();
  if ((testop->code() != CPUI_INT_MULT)||(!testop->getIn(1)->isConstant())) {
    coef = 1;
    return vn;
  }
  coef = testop->getIn(1)->getOffset();
  return testop->getIn(0);
}

/// \class RuleCollectTerms
/// \brief Collect terms in a sum: `V * c + V * d   =>  V * (c + d)`
void RuleCollectTerms::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ADD);
}

int4 RuleCollectTerms::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *nextop = op->getOut()->loneDescend();
				// Do we have the root of an ADD tree
  if ((nextop!=(PcodeOp *)0)&&(nextop->code()==CPUI_INT_ADD)) return 0;
  
  TermOrder termorder(op);
  termorder.collect();		// Collect additive terms in the expression
  termorder.sortTerms();	// Sort them based on termorder
  Varnode *vn1,*vn2;
  uintb coef1,coef2;
  const vector<AdditiveEdge *> &order( termorder.getSort() );
  int4 i=0;

  if (!order[0]->getVarnode()->isConstant()) {
    for(i=1;i<order.size();++i) {
      vn1 = order[i-1]->getVarnode();
      vn2 = order[i]->getVarnode();
      if (vn2->isConstant()) break;
      vn1 = getMultCoeff(vn1,coef1);
      vn2 = getMultCoeff(vn2,coef2);
      if (vn1 == vn2) {		// Terms that can be combined
	if (isVolatileVarnode(vn1)) return 0;
	if (order[i-1]->getMultiplier() != (PcodeOp *)0)
	  return data.distributeIntMultAdd(order[i-1]->getMultiplier()) ? 1 : 0;
	if (order[i]->getMultiplier() != (PcodeOp *)0)
	  return data.distributeIntMultAdd(order[i]->getMultiplier()) ? 1 : 0;
	coef1 = (coef1 + coef2) & calc_mask(vn1->getSize()); // The new coefficient
	Varnode *newcoeff = data.newConstant(vn1->getSize(),coef1);
	Varnode *zerocoeff = data.newConstant(vn1->getSize(),0);
	data.opSetInput(order[i-1]->getOp(),zerocoeff,order[i-1]->getSlot());
	if (coef1 == 0)
	  data.opSetInput(order[i]->getOp(),newcoeff,order[i]->getSlot());
	else {
	  nextop = data.newOp(2,order[i]->getOp()->getAddr());
	  vn2 = data.newUniqueOut(vn1->getSize(),nextop);
	  data.opSetOpcode(nextop,CPUI_INT_MULT);
	  data.opSetInput(nextop,vn1,0);
	  data.opSetInput(nextop,newcoeff,1);
	  data.opInsertBefore(nextop,order[i]->getOp());
	  data.opSetInput(order[i]->getOp(),vn2,order[i]->getSlot());
	}
	return 1;
      }
    }
  }
  coef1 = 0;
  int4 nonzerocount = 0;		// Count non-zero constants
  int4 lastconst=0;
  for(int4 j=order.size()-1;j>=i;--j) {
    if (order[j]->getMultiplier() != (PcodeOp *)0) continue;
    vn1 = order[j]->getVarnode();
    uintb val = vn1->getOffset();
    if (val != 0) {
      nonzerocount += 1;
      coef1 += val; // Sum up all the constants
      lastconst = j;
    }
  }
  if (nonzerocount <= 1) return 0; // Must sum at least two things
  vn1 = order[lastconst]->getVarnode();
  if (isVolatileVarnode(vn1)) return 0;
  coef1 &= calc_mask(vn1->getSize());
				// Lump all the non-zero constants into one varnode
  for(int4 j=lastconst+1;j<order.size();++j)
    if (order[j]->getMultiplier() == (PcodeOp *)0)
      data.opSetInput(order[j]->getOp(),data.newConstant(vn1->getSize(),0),order[j]->getSlot());
  data.opSetInput(order[lastconst]->getOp(),data.newConstant(vn1->getSize(),coef1),order[lastconst]->getSlot());
  
  return 1;
}

bool RuleCollectTerms::isVolatileVarnode(Varnode *vn)

{
  AddrSpace *spc = vn->getSpace();
  spacetype type = spc->getType();
  if (type == IPTR_CONSTANT) return false;
  if (type == IPTR_PROCESSOR) {
    const Translate *trans = spc->getTrans();
    uintb off = vn->getOffset();
    uintb sz = vn->getSize();
    const string &nm = trans->getRegisterName(spc, off, sz);
    if (!nm.empty()) return false; // Register (if valid) is not volatile (multithreaded)
    return true;
  }
  return false;
}

/// \class RuleSelectCse
/// \brief Look for common sub-expressions (built out of a restricted set of ops)
void RuleSelectCse::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
  oplist.push_back(CPUI_INT_SRIGHT); // For division optimization corrections
}

int4 RuleSelectCse::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getIn(0);
  list<PcodeOp *>::const_iterator iter;
  OpCode opc = op->code();
  PcodeOp *otherop;
  uintm hash;
  vector< pair<uintm,PcodeOp *> > list;
  vector<Varnode *> vlist;
  
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    otherop = *iter;
    if (otherop->code() != opc) continue;
    hash = otherop->getCseHash();
    if (hash == 0) continue;
    list.push_back(pair<uintm,PcodeOp *>(hash,otherop));
  }
  if (list.size()<=1) return 0;
  data.cseEliminateList(list,vlist);
  if (vlist.empty()) return 0;
  return 1;
}

/// \class RulePiece2Zext
/// \brief Concatenation with 0 becomes an extension:  `V = concat(#0,W)  =>  V = zext(W)`
void RulePiece2Zext::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PIECE);
}

int4 RulePiece2Zext::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *rootVn = op->getOut();
  while (true) {
    PcodeOp *lone = rootVn->loneDescend();
    if (lone == (PcodeOp *)0) break;
    if (lone->code() != CPUI_PIECE) break;
    rootVn = lone->getOut();
  }
  if (rootVn->getSize() > sizeof(uintb)) return 0;

  Varnode *constvn = op->getIn(0);	// Constant must be most significant bits
  if (!constvn->isConstant()) return 0;	// Must append with constant
  if (constvn->getOffset() != 0) return 0; // of value 0
  data.opRemoveInput(op,0);	// Remove the constant
  data.opSetOpcode(op,CPUI_INT_ZEXT);
  return 1;
}

/// \class RulePiece2Sext
/// \brief Concatenation with sign bits becomes an extension: `concat( V s>> #0x1f , V)  => sext(V)`
void RulePiece2Sext::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PIECE);
}

int4 RulePiece2Sext::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *shiftout,*x;
  PcodeOp *shiftop;

  shiftout = op->getIn(0);
  if (!shiftout->isWritten()) return 0;
  shiftop = shiftout->getDef();
  if (shiftop->code() != CPUI_INT_SRIGHT) return 0;
  if (!shiftop->getIn(1)->isConstant()) return 0;
  int4 n = shiftop->getIn(1)->getOffset();
  x = shiftop->getIn(0);
  if (x != op->getIn(1)) return 0;
  if (n != 8*x->getSize() -1) return 0;

  data.opRemoveInput(op,0);
  data.opSetOpcode(op,CPUI_INT_SEXT);
  return 1;
}

/// \class RuleBxor2NotEqual
/// \brief Eliminate BOOL_XOR:  `V ^^ W  =>  V != W`
void RuleBxor2NotEqual::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_BOOL_XOR);
}

int4 RuleBxor2NotEqual::applyOp(PcodeOp *op,Funcdata &data)

{
  data.opSetOpcode(op,CPUI_INT_NOTEQUAL);
  return 1;
}

/// \class RuleOrMask
/// \brief Simplify INT_OR with full mask:  `V = W | 0xffff  =>  V = W`
void RuleOrMask::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_OR);
}

int4 RuleOrMask::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 size = op->getOut()->getSize();
  if (size > sizeof(uintb)) return 0; // FIXME: uintb should be arbitrary precision
  Varnode *constvn;

  constvn = op->getIn(1);
  if (!constvn->isConstant()) return 0;
  uintb val = constvn->getOffset();
  uintb mask = calc_mask(size);
  if ((val&mask) != mask) return 0;
  data.opSetOpcode(op,CPUI_COPY);
  data.opSetInput(op,constvn,0);
  data.opRemoveInput(op,1);
  return 1;
}

/// \class RuleAndMask
/// \brief Collapse unnecessary INT_AND
void RuleAndMask::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
}

int4 RuleAndMask::applyOp(PcodeOp *op,Funcdata &data)

{
  uintb mask1,mask2,andmask;
  int4 size = op->getOut()->getSize();
  Varnode *vn;

  PcodeOp *def = op->getIn(0)->getDef();
  // Must check some ops which may produce unpredictable mask values
  if (def != (PcodeOp *)0) {
    if (def->code() == CPUI_INT_ADD) return 0;
  }
  if (size > sizeof(uintb)) return 0; // FIXME: uintb should be arbitrary precision
  mask1 = op->getIn(0)->getNZMask();
  if (mask1 == 0)
    andmask = 0;
  else {
    mask2 = op->getIn(1)->getNZMask();
    andmask = mask1 & mask2;
  }

  if (andmask==0)		// Result of AND is always zero
    vn = data.newConstant( size, 0);
  else if ((andmask & op->getOut()->getConsume())==0)
    vn = data.newConstant( size, 0);
  else if (andmask == mask1) {
    if (!op->getIn(1)->isConstant()) return 0;
    vn = op->getIn(0);		// Result of AND is equal to input(0)
  }
  else
    return 0;
  if (!vn->isHeritageKnown()) return 0;

  data.opSetOpcode(op,CPUI_COPY);
  data.opRemoveInput(op,1);
  data.opSetInput(op,vn,0);
  return 1;
}

/// \class RuleOrConsume
/// \brief Simply OR with unconsumed input:  `V = A | B  =>  V = B  if  nzm(A) & consume(V) == 0
void RuleOrConsume::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_OR);
  oplist.push_back(CPUI_INT_XOR);
}

int4 RuleOrConsume::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *outvn = op->getOut();
  int4 size = outvn->getSize();
  if (size > sizeof(uintb)) return 0; // FIXME: uintb should be arbitrary precision
  uintb consume = outvn->getConsume();
  if ((consume & op->getIn(0)->getNZMask()) == 0) {
    data.opRemoveInput(op,0);
    data.opSetOpcode(op, CPUI_COPY);
    return 1;
  }
  else if ((consume & op->getIn(1)->getNZMask()) == 0) {
    data.opRemoveInput(op,1);
    data.opSetOpcode(op, CPUI_COPY);
    return 1;
  }
  return 0;
}

/// \class RuleOrCollapse
/// \brief Collapse unnecessary INT_OR
///
/// Replace V | c with c, if any bit not set in c,
/// is also not set in V   i.e. NZM(V) | c == c
void RuleOrCollapse::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_OR);
}

int4 RuleOrCollapse::applyOp(PcodeOp *op,Funcdata &data)

{
  uintb val,mask;
  int4 size = op->getOut()->getSize();
  Varnode *vn;

  vn = op->getIn(1);
  if (!vn->isConstant()) return 0;
  if (size > sizeof(uintb)) return 0; // FIXME: uintb should be arbitrary precision
  mask = op->getIn(0)->getNZMask();
  val = vn->getOffset();
  if ((mask | val)!=val) return 0; // first param may turn on other bits

  data.opSetOpcode(op,CPUI_COPY);
  data.opRemoveInput(op,0);
  return 1;
}

/// \class RuleAndOrLump
/// \brief Collapse constants in logical expressions:  `(V & c) & d  =>  V & (c & d)`
void RuleAndOrLump::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
  oplist.push_back(CPUI_INT_OR);
  oplist.push_back(CPUI_INT_XOR);
}

int4 RuleAndOrLump::applyOp(PcodeOp *op,Funcdata &data)

{
  OpCode opc;
  Varnode *vn1,*basevn;
  PcodeOp *op2;

  opc = op->code();
  if (!op->getIn(1)->isConstant()) return 0;
  vn1 = op->getIn(0);
  if (!vn1->isWritten()) return 0;
  op2 = vn1->getDef();
  if (op2->code() != opc) return 0; // Must be same op
  if (!op2->getIn(1)->isConstant()) return 0;
  basevn = op2->getIn(0);
  if (basevn->isFree()) return 0;
  
  uintb val = op->getIn(1)->getOffset();
  uintb val2 = op2->getIn(1)->getOffset();
  if (opc == CPUI_INT_AND)
    val &= val2;
  else if (opc == CPUI_INT_OR)
    val |= val2;
  else if (opc == CPUI_INT_XOR)
    val ^= val2;

  data.opSetInput(op,basevn,0);
  data.opSetInput(op,data.newConstant(basevn->getSize(),val),1);
  return 1;
}

/// \class RuleNegateIdentity
/// \brief Apply INT_NEGATE identities:  `V & ~V  => #0,  V | ~V  ->  #-1`
void RuleNegateIdentity::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_NEGATE);
}

int4 RuleNegateIdentity::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getIn(0);
  Varnode *outVn = op->getOut();
  list<PcodeOp *>::const_iterator iter;
  for(iter=outVn->beginDescend();iter!=outVn->endDescend();++iter) {
    PcodeOp *logicOp = *iter;
    OpCode opc = logicOp->code();
    if (opc != CPUI_INT_AND && opc != CPUI_INT_OR && opc != CPUI_INT_XOR)
      continue;
    int4 slot = logicOp->getSlot(outVn);
    if (logicOp->getIn(1-slot) != vn) continue;
    uintb value = 0;
    if (opc != CPUI_INT_AND)
      value = calc_mask(vn->getSize());
    data.opSetInput(logicOp,data.newConstant(vn->getSize(),value),0);
    data.opRemoveInput(logicOp,1);
    data.opSetOpcode(logicOp,CPUI_COPY);
    return 1;
  }
  return 0;
}

/// \class RuleShiftBitops
/// \brief Shifting away all non-zero bits of one-side of a logical/arithmetic op
///
/// `( V & 0xf000 ) << 4   =>   #0 << 4`
/// `( V + 0xf000 ) << 4   =>    V << 4`
void RuleShiftBitops::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_LEFT);
  oplist.push_back(CPUI_INT_RIGHT);
  oplist.push_back(CPUI_SUBPIECE);
  oplist.push_back(CPUI_INT_MULT);
}

int4 RuleShiftBitops::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *constvn = op->getIn(1);
  if (!constvn->isConstant()) return 0;	// Must be a constant shift
  Varnode *vn = op->getIn(0);
  if (!vn->isWritten()) return 0;
  if (vn->getSize() > sizeof(uintb)) return 0;	// FIXME: Can't exceed uintb precision
  int4 sa;
  bool leftshift;

  switch(op->code()) {
  case CPUI_INT_LEFT:
    sa = (int4) constvn->getOffset();
    leftshift = true;
    break;
  case CPUI_INT_RIGHT:
    sa = (int4) constvn->getOffset();
    leftshift = false;
    break;
  case CPUI_SUBPIECE:
    sa = (int4) constvn->getOffset();
    sa = sa * 8;
    leftshift = false;
    break;
  case CPUI_INT_MULT:
    sa = leastsigbit_set(constvn->getOffset());
    if (sa == -1) return 0;
    leftshift = true;
    break;
  default:
    return 0;			// Never reaches here
  }

  PcodeOp *bitop = vn->getDef();
  switch(bitop->code()) {
  case CPUI_INT_AND:
  case CPUI_INT_OR:
  case CPUI_INT_XOR:
    break;
  case CPUI_INT_MULT:
  case CPUI_INT_ADD:
    if (!leftshift) return 0;
    break;
  default:
    return 0;
  }
  
  int4 i;
  for(i=0;i<bitop->numInput();++i) {
    uintb nzm = bitop->getIn(i)->getNZMask();
    uintb mask = calc_mask(op->getOut()->getSize());
    if (leftshift)
      nzm = pcode_left(nzm,sa);
    else
      nzm = pcode_right(nzm,sa);
    if ((nzm&mask)==(uintb)0) break;
  }
  if (i==bitop->numInput()) return 0;
  switch(bitop->code()) {
  case CPUI_INT_MULT:
  case CPUI_INT_AND:
    vn = data.newConstant(vn->getSize(),0);
    data.opSetInput(op,vn,0);	// Result will be zero
    break;
  case CPUI_INT_ADD:
  case CPUI_INT_XOR:
  case CPUI_INT_OR:
    vn = bitop->getIn(1-i);
    if (!vn->isHeritageKnown()) return 0;
    data.opSetInput(op,vn,0);
    break;
  default:
    break;
  }
  return 1;
}

/// \class RuleRightShiftAnd
/// \brief Simplify INT_RIGHT and INT_SRIGHT ops where an INT_AND mask becomes unnecessary
///
/// - `( V & 0xf000 ) >> 24   =>   V >> 24`
/// - `( V & 0xf000 ) s>> 24  =>   V s>> 24`
void RuleRightShiftAnd::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_RIGHT);
  oplist.push_back(CPUI_INT_SRIGHT);
}

int4 RuleRightShiftAnd::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *constVn = op->getIn(1);
  if (!constVn->isConstant()) return 0;
  Varnode *inVn = op->getIn(0);
  if (!inVn->isWritten()) return 0;
  PcodeOp *andOp = inVn->getDef();
  if (andOp->code() != CPUI_INT_AND) return 0;
  Varnode *maskVn = andOp->getIn(1);
  if (!maskVn->isConstant()) return 0;

  int4 sa = (int4)constVn->getOffset();
  uintb mask = maskVn->getOffset() >> sa;
  Varnode *rootVn = andOp->getIn(0);
  uintb full = calc_mask(rootVn->getSize()) >> sa;
  if (full != mask) return 0;
  if (rootVn->isFree()) return 0;
  data.opSetInput(op, rootVn, 0);	// Bypass the INT_AND
  return 1;
}

/// \class RuleIntLessEqual
/// \brief Convert LESSEQUAL to LESS:  `V <= c  =>  V < (c+1)`
void RuleIntLessEqual::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_LESSEQUAL);
  oplist.push_back(CPUI_INT_SLESSEQUAL);
}

int4 RuleIntLessEqual::applyOp(PcodeOp *op,Funcdata &data)

{
  if (data.replaceLessequal(op))
    return 1;
  return 0;
}

/// \class RuleEquality
/// \brief Collapse INT_EQUAL and INT_NOTEQUAL:  `f(V,W) == f(V,W)  =>  true`
///
/// If both inputs to an INT_EQUAL or INT_NOTEQUAL op are functionally equivalent,
/// the op can be collapsed to a COPY of a \b true or \b false.
void RuleEquality::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_EQUAL);
  oplist.push_back(CPUI_INT_NOTEQUAL);
}

int4 RuleEquality::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn;
  if (!functionalEquality(op->getIn(0),op->getIn(1)))
    return 0;

  data.opSetOpcode(op,CPUI_COPY);
  data.opRemoveInput(op,1);
  vn = data.newConstant(1,(op->code()==CPUI_INT_EQUAL) ? 1: 0);
  data.opSetInput(op,vn,0);
  return 1;
}

bool RuleTermOrder::form1(PcodeOp *op,Funcdata &data)

{
  Varnode *vn1 = op->getIn(0);
  Varnode *vn2 = op->getIn(1);

  if (!vn1->isConstant()) return false;
  if (vn2->isConstant()) return false;
  data.opSwapInput(op,0,1);	// Reverse the order of the terms
  return true;
}

bool RuleTermOrder::form2(PcodeOp *op,Funcdata &data)

{
  Varnode *vn1 = op->getIn(0);
  Varnode *vn2 = op->getIn(1);

  if (op->code() != CPUI_INT_ADD) return false;
  PcodeOp *inOp1 = vn1->getDef();
  if (inOp1 != (PcodeOp *)0) {
    if (inOp1->code() == CPUI_INT_MULT) return false;
  }
  PcodeOp *inOp2 = vn2->getDef();
  if (inOp2 == (PcodeOp *)0) return false;
  if (inOp2->code() != CPUI_INT_MULT) return false;
  data.opSwapInput(op,0,1);
  return true;
}

bool RuleTermOrder::form3(PcodeOp *op,Funcdata &data)

{
  Varnode *vn1 = op->getIn(0);
  Varnode *vn2 = op->getIn(1);

  if (op->code() != CPUI_INT_ADD) return false;
  if (!vn1->isConstant()) {
    if (vn1->isFree()) return false;
  }
  PcodeOp *inop = vn2->getDef();
  if (inop == (PcodeOp *)0) return false;
  if (inop->code() != CPUI_INT_ADD) return false;
  Varnode *invn1 = inop->getIn(0);
  if (!invn1->isConstant()) {
    if (invn1->isFree()) return false;
  }
  Varnode *invn2 = inop->getIn(1);
  if (!invn2->isConstant()) {
    if (invn2->isFree()) return false;
  }
  PcodeOp *newop = data.newOpBefore(op,CPUI_INT_ADD,vn1,invn1);
  data.opSetInput(op,newop->getOut(),0);
  data.opSetInput(op,invn2,1);
  return true;
}

/// \class RuleTermOrder
/// \brief Order the inputs to commutative operations
///
/// Constants always come last in particular which eliminates
/// some of the combinatorial explosion of expression variations.
/// Forms include:
///  - `c + V  =>  V + c`
///  - `V + (W * X)  =>  (W * X) + V`
///  - `V + (W + X)  =>  (V + W) + X`
void RuleTermOrder::getOpList(vector<uint4> &oplist) const

{
				// FIXME:  All the commutative ops
				// Use the TypeOp::commutative function
  uint4 list[]={ CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_ADD, CPUI_INT_CARRY,
		 CPUI_INT_SCARRY, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR,
		 CPUI_INT_MULT, CPUI_BOOL_XOR, CPUI_BOOL_AND, CPUI_BOOL_OR,
		 CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_ADD,
		 CPUI_FLOAT_MULT };
  oplist.insert(oplist.end(),list,list+16);
}

int4 RuleTermOrder::applyOp(PcodeOp *op,Funcdata &data)

{
  if (form1(op,data)) return 1;
  if (form2(op,data)) return 1;
  //if (form3(op,data)) return 1;
  return 0;
}

/// \brief Compute minimum and maximum bytes being used
///
/// For bytes in given Varnode pass back the largest and smallest index (lsb=0)
/// consumed by an immediate descendant.
/// \param vn is the given Varnode
/// \param maxByte will hold the index of the maximum byte
/// \param minByte will hold the index of the minimum byte
void RulePullsubMulti::minMaxUse(Varnode *vn,int4 &maxByte,int4 &minByte)

{
  list<PcodeOp *>::const_iterator iter,enditer;
  enditer = vn->endDescend();

  int4 inSize = vn->getSize();
  maxByte = -1;
  minByte = inSize;
  for(iter=vn->beginDescend();iter!=enditer;++iter) {
    PcodeOp *op = *iter;
    OpCode opc = op->code();
    if (opc == CPUI_SUBPIECE) {
      int4 min = (int4)op->getIn(1)->getOffset();
      int4 max = min + op->getOut()->getSize() - 1;
      if (min < minByte)
	minByte = min;
      if (max > maxByte)
	maxByte = max;
    }
    else {	// By default assume all bytes are used
      maxByte = inSize - 1;
      minByte = 0;
      return;
    }
  }
}

/// Replace given Varnode with (smaller) \b newVn in all descendants
///
/// If minMaxUse() indicates not all bytes are used, this should always succeed
/// \param origVn is the given Varnode
/// \param newVn is the new Varnode to replace with
/// \param maxByte is the maximum byte immediately used in \b origVn
/// \param minByte is the minimum byte immediately used in \b origVn
/// \param data is the function being analyzed
void RulePullsubMulti::replaceDescendants(Varnode *origVn,Varnode *newVn,int4 maxByte,int4 minByte,Funcdata &data)

{
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = origVn->beginDescend();
  enditer = origVn->endDescend();
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;
    if (op->code() == CPUI_SUBPIECE) {
      int4 truncAmount = (int4)op->getIn(1)->getOffset();
      int4 outSize = op->getOut()->getSize();
      data.opSetInput(op,newVn,0);
      if (newVn->getSize() == outSize) {
	if (truncAmount != minByte)
	  throw LowlevelError("Could not perform -replaceDescendants-");
	data.opSetOpcode(op, CPUI_COPY);
	data.opRemoveInput(op, 1);
      }
      else if (newVn->getSize() > outSize) {
	int4 newTrunc = truncAmount - minByte;
	if (newTrunc < 0)
	  throw LowlevelError("Could not perform -replaceDescendants-");
	if (newTrunc != truncAmount) {
	  data.opSetInput(op, data.newConstant(4, (uintb)newTrunc), 1);
	}
      }
      else
	throw LowlevelError("Could not perform -replaceDescendants-");
    }
    else
      throw LowlevelError("Could not perform -replaceDescendants-");
  }
}

/// \brief Return \b true if given size is a suitable truncated size
///
/// \param size is the given size
/// \return \b true if it is acceptable
bool RulePullsubMulti::acceptableSize(int4 size)

{
  if (size == 0) return false;
  if (size >= 8) return true;
  if (size == 1 || size == 2 || size == 4 || size == 8)
    return true;
  return false;
}

/// \brief  Build a SUBPIECE of given base Varnode
///
/// The PcodeOp is constructed and inserted near the definition of the base Varnode.
/// \param basevn is the given base Varnode
/// \param outsize is the required truncated size in bytes
/// \param shift is the number of least significant bytes to truncate
/// \param data is the function being analyzed
/// \return the output Varnode of the new SUBPIECE
Varnode *RulePullsubMulti::buildSubpiece(Varnode *basevn,uint4 outsize,uint4 shift,Funcdata &data)

{
  Address newaddr;
  PcodeOp *new_op;
  Varnode *outvn;

  if (basevn->isInput()) {
    BlockBasic *bb = (BlockBasic *)data.getBasicBlocks().getBlock(0);
    newaddr = bb->getStart();
  }
  else {
    if (!basevn->isWritten()) throw LowlevelError("Undefined pullsub");
    newaddr = basevn->getDef()->getAddr();
  }
  Address smalladdr1;
  bool usetmp = false;
  if (basevn->getAddr().isJoin()) {
    usetmp = true;
    JoinRecord *joinrec = data.getArch()->findJoin(basevn->getOffset());
    if (joinrec->numPieces() > 1) { // If only 1 piece (float extension) automatically use unique
      uint4 skipleft = shift;
      for(int4 i=joinrec->numPieces()-1;i>=0;--i) { // Move from least significant to most
	const VarnodeData &vdata(joinrec->getPiece(i));
	if (skipleft >= vdata.size) {
	  skipleft -= vdata.size;
	}
	else {
	  if (skipleft + outsize > vdata.size)
	    break;
	  if (vdata.space->isBigEndian())
	    smalladdr1 = vdata.getAddr() + (vdata.size - (outsize + skipleft));
	  else
	    smalladdr1 = vdata.getAddr() + skipleft;
	  usetmp = false;
	  break;
	}
      }
    }
  }
  else {
    if (!basevn->getSpace()->isBigEndian())
      smalladdr1 = basevn->getAddr()+shift;
    else
      smalladdr1 = basevn->getAddr()+(basevn->getSize()-(shift+outsize));
  }
				// Build new subpiece near definition of basevn
  new_op = data.newOp(2,newaddr);
  data.opSetOpcode(new_op,CPUI_SUBPIECE);
  if (usetmp)
    outvn = data.newUniqueOut(outsize,new_op);
  else {
    smalladdr1.renormalize(outsize);
    outvn = data.newVarnodeOut(outsize,smalladdr1,new_op);
  }
  data.opSetInput(new_op,basevn,0);
  data.opSetInput(new_op,data.newConstant(4,shift),1);

  if (basevn->isInput())
    data.opInsertBegin(new_op,(BlockBasic *)data.getBasicBlocks().getBlock(0));
  else
    data.opInsertAfter(new_op,basevn->getDef());
  return outvn;
}

/// \brief Find a predefined SUBPIECE of a base Varnode
///
/// Given a Varnode and desired dimensions (size and shift), search for a preexisting
/// truncation defined in the same block as the original Varnode or return NULL
/// \param basevn is the base Varnode
/// \param outsize is the desired truncation size
/// \param shift if the desired truncation shift
/// \return the truncated Varnode or NULL
Varnode *RulePullsubMulti::findSubpiece(Varnode *basevn,uint4 outsize,uint4 shift)

{
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *prevop;

  for(iter=basevn->beginDescend();iter!=basevn->endDescend();++iter) {
    prevop = *iter;
    if (prevop->code() != CPUI_SUBPIECE) continue; // Find previous SUBPIECE
				// Make sure output is defined in same block as vn_piece
    if (basevn->isInput() && (prevop->getParent()->getIndex()!=0)) continue;
    if (!basevn->isWritten()) continue;
    if (basevn->getDef()->getParent() != prevop->getParent()) continue;
				// Make sure subpiece matches form
    if ((prevop->getIn(0) == basevn)&&
	(prevop->getOut()->getSize() == outsize)&&
	(prevop->getIn(1)->getOffset()==shift)) {
      return prevop->getOut();
    }
  }
  return (Varnode *)0;
}

/// \class RulePullsubMulti
/// \brief Pull SUBPIECE back through MULTIEQUAL
void RulePullsubMulti::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RulePullsubMulti::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 maxByte,minByte,newSize;

  Varnode *vn = op->getIn(0);
  if (!vn->isWritten()) return 0;
  PcodeOp *mult = vn->getDef();
  if (mult->code()!=CPUI_MULTIEQUAL) return 0;
  // We only pull up, do not pull "down" to bottom of loop
  if (mult->getParent()->hasLoopIn()) return 0;
  minMaxUse(vn, maxByte, minByte);		// Figure out what part of -vn- is used
  newSize = maxByte - minByte + 1;
  if (maxByte < minByte || (newSize >= vn->getSize()))
    return 0;	// If all or none is getting used, nothing to do
  if (!acceptableSize(newSize)) return 0;
  Varnode *outvn = op->getOut();
  if (outvn->isPrecisLo()||outvn->isPrecisHi()) return 0; // Don't pull apart a double precision object

  // Make sure we don't new add SUBPIECE ops that aren't going to cancel in some way
  int4 branches = mult->numInput();
  uintb consume = calc_mask(newSize) << 8*minByte;
  consume = ~consume;			// Check for use of bits outside of what gets truncated later
  for(int4 i=0;i<branches;++i) {
    Varnode *inVn = mult->getIn(i);
    if ((consume & inVn->getConsume()) != 0) {	// Check if bits not truncated are still used
      // Check if there's an extension that matches the truncation
      if (minByte == 0 && inVn->isWritten()) {
	PcodeOp *defOp = inVn->getDef();
	OpCode opc = defOp->code();
	if (opc == CPUI_INT_ZEXT || opc == CPUI_INT_SEXT) {
	  if (newSize == defOp->getIn(0)->getSize())
	    continue;		// We have matching extension, so new SUBPIECE will cancel anyway
	}
      }
      return 0;
    }
  }

  Address smalladdr2;
  if (!vn->getSpace()->isBigEndian())
    smalladdr2 = vn->getAddr()+minByte;
  else
    smalladdr2 = vn->getAddr()+(vn->getSize()-maxByte-1);

  vector<Varnode *> params;

  for(int4 i=0;i<branches;++i) {
    Varnode *vn_piece = mult->getIn(i);
  // We have to be wary of exponential splittings here, do not pull the SUBPIECE
  // up the MULTIEQUAL if another related SUBPIECE has already been pulled
  // Search for a previous SUBPIECE
    Varnode *vn_sub = findSubpiece(vn_piece,newSize,minByte);
    if (vn_sub == (Varnode *)0) // Couldn't find previous subpieceing
      vn_sub = buildSubpiece(vn_piece,newSize,minByte,data);
    params.push_back(vn_sub);
  }
				// Build new multiequal near original multiequal
  PcodeOp *new_multi = data.newOp(params.size(),mult->getAddr());
  smalladdr2.renormalize(newSize);
  Varnode *new_vn = data.newVarnodeOut(newSize,smalladdr2,new_multi);
  data.opSetOpcode(new_multi,CPUI_MULTIEQUAL);
  data.opSetAllInput(new_multi,params);
  data.opInsertBegin(new_multi,mult->getParent());

  replaceDescendants(vn, new_vn, maxByte, minByte, data);
  return 1;
}

/// \class RulePullsubIndirect
/// \brief Pull-back SUBPIECE through INDIRECT
void RulePullsubIndirect::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RulePullsubIndirect::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 maxByte,minByte,newSize;

  Varnode *vn = op->getIn(0);
  if (!vn->isWritten()) return 0;
  PcodeOp *indir = vn->getDef();
  if (indir->code()!=CPUI_INDIRECT) return 0;
  if (indir->getIn(1)->getSpace()->getType()!=IPTR_IOP) return 0;

  PcodeOp *targ_op = PcodeOp::getOpFromConst(indir->getIn(1)->getAddr());
  if (targ_op->isDead()) return 0;
  if (vn->isAddrForce()) return 0;
  RulePullsubMulti::minMaxUse(vn, maxByte, minByte);
  newSize = maxByte - minByte + 1;
  if (maxByte < minByte || (newSize >= vn->getSize()))
    return 0;
  if (!RulePullsubMulti::acceptableSize(newSize)) return 0;
  Varnode *outvn = op->getOut();
  if (outvn->isPrecisLo()||outvn->isPrecisHi()) return 0; // Don't pull apart double precision object

  uintb consume = calc_mask(newSize) << 8 * minByte;
  consume = ~consume;
  if ((consume & indir->getIn(0)->getConsume())!=0) return 0;

  Varnode *small2;
  Address smalladdr2;
  PcodeOp *new_ind;

  if (!vn->getSpace()->isBigEndian())
    smalladdr2 = vn->getAddr()+minByte;
  else
    smalladdr2 = vn->getAddr()+(vn->getSize()-maxByte-1);

  if (indir->isIndirectCreation()) {
    bool possibleout = !indir->getIn(0)->isIndirectZero();
    new_ind = data.newIndirectCreation(targ_op,smalladdr2,newSize,possibleout);
    small2 = new_ind->getOut();
  }
  else {
    Varnode *basevn = indir->getIn(0);
    Varnode *small1 = RulePullsubMulti::findSubpiece(basevn,newSize,op->getIn(1)->getOffset());
    if (small1 == (Varnode *)0)
      small1 = RulePullsubMulti::buildSubpiece(basevn,newSize,op->getIn(1)->getOffset(),data);
    // Create new indirect near original indirect
    new_ind = data.newOp(2,indir->getAddr());
    data.opSetOpcode(new_ind,CPUI_INDIRECT);
    small2 = data.newVarnodeOut(newSize,smalladdr2,new_ind);
    data.opSetInput(new_ind,small1,0);
    data.opSetInput(new_ind,data.newVarnodeIop(targ_op),1);
    data.opInsertBefore(new_ind,indir);
  }

  RulePullsubMulti::replaceDescendants(vn, small2, maxByte, minByte, data);
  return 1;
}

/// \brief Find a previously existing MULTIEQUAL taking given inputs
///
/// The MULTIEQUAL must be in the given block \b bb.
/// If the MULTIEQUAL does not exist, check if the inputs have
/// level 1 functional equality and if a common sub-expression is present in the block
/// \param in1 is the first input
/// \param in2 is the second input
/// \param bb is the given block to search in
/// \param earliest is the earliest of the inputs
/// \return the discovered MULTIEQUAL or the equivalent sub-expression
PcodeOp *RulePushMulti::findSubstitute(Varnode *in1,Varnode *in2,BlockBasic *bb,PcodeOp *earliest)

{
  list<PcodeOp *>::const_iterator iter,enditer;
  iter = in1->beginDescend();
  enditer = in1->endDescend();
  while(iter != enditer) {
    PcodeOp *op = *iter;
    ++iter;
    if (op->getParent() != bb) continue;
    if (op->code() != CPUI_MULTIEQUAL) continue;
    if (op->getIn(0) != in1) continue;
    if (op->getIn(1) != in2) continue;
    return op;
  }
  if (in1 == in2) return (PcodeOp *)0;
  Varnode *buf1[2];
  Varnode *buf2[2];
  if (0!=functionalEqualityLevel(in1,in2,buf1,buf2)) return (PcodeOp *)0;
  PcodeOp *op1 = in1->getDef();	// in1 and in2 must be written to not be equal and pass functional equality test
  PcodeOp *op2 = in2->getDef();
  for(int4 i=0;i<op1->numInput();++i) {
    Varnode *vn = op1->getIn(i);
    if (vn->isConstant()) continue;
    if (vn == op2->getIn(i))	// Find matching inputs to op1 and op2,
      return Funcdata::cseFindInBlock(op1,vn,bb,earliest); // search for cse of op1 in bb
  }

  return (PcodeOp *)0;
}

/// \class RulePushMulti
/// \brief Simplify MULTIEQUAL operations where the branches hold the same value
///
/// Look for a two-branch MULTIEQUAL where both inputs are constructed in
/// functionally equivalent ways.  Remove (the reference to) one construction
/// and move the other into the merge block.
void RulePushMulti::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_MULTIEQUAL);
}

int4 RulePushMulti::applyOp(PcodeOp *op,Funcdata &data)

{
  if (op->numInput() != 2) return 0;
  
  Varnode *in1 = op->getIn(0);
  Varnode *in2 = op->getIn(1);

  if (!in1->isWritten()) return 0;
  if (!in2->isWritten()) return 0;
  if (in1->isSpacebase()) return 0;
  if (in2->isSpacebase()) return 0;
  Varnode *buf1[2];
  Varnode *buf2[2];
  int4 res = functionalEqualityLevel(in1,in2,buf1,buf2);
  if (res < 0) return 0;
  if (res > 1) return 0;
  PcodeOp *op1 = in1->getDef();
  if (op1->code() == CPUI_SUBPIECE) return 0; // SUBPIECE is pulled not pushed

  BlockBasic *bl = op->getParent();
  PcodeOp *earliest = bl->earliestUse(op->getOut());
  if (op1->code() == CPUI_COPY) { // Special case of MERGE of 2 shadowing varnodes
    if (res==0) return 0;
    PcodeOp *substitute = findSubstitute(buf1[0],buf2[0],bl,earliest);
    if (substitute == (PcodeOp *)0) return 0;
    // Eliminate this op in favor of the shadowed merge
    data.totalReplace(op->getOut(),substitute->getOut());
    data.opDestroy(op);
    return 1;
  }
  PcodeOp *op2 = in2->getDef();
  if (in1->loneDescend() != op) return 0;
  if (in2->loneDescend() != op) return 0;

  Varnode *outvn = op->getOut();

  data.opSetOutput(op1,outvn);	// Move MULTIEQUAL output to op1, which will be new unified op
  data.opUninsert(op1);		// Move the unified op
  if (res == 1) {
    int4 slot1 = op1->getSlot(buf1[0]);
    PcodeOp *substitute = findSubstitute(buf1[0],buf2[0],bl,earliest);
    if (substitute == (PcodeOp *)0) {
      substitute = data.newOp(2,op->getAddr());
      data.opSetOpcode(substitute,CPUI_MULTIEQUAL);
      // Try to preserve the storage location if the input varnodes share it
      // But don't propagate addrtied varnode (thru MULTIEQUAL)
      if ((buf1[0]->getAddr() == buf2[0]->getAddr())&&(!buf1[0]->isAddrTied()))
	data.newVarnodeOut(buf1[0]->getSize(),buf1[0]->getAddr(),substitute);
      else
	data.newUniqueOut(buf1[0]->getSize(),substitute);
      data.opSetInput(substitute,buf1[0],0);
      data.opSetInput(substitute,buf2[0],1);
      data.opInsertBegin(substitute,bl);
    }
    data.opSetInput(op1,substitute->getOut(),slot1); // Replace input to the unified op with the unified varnode
    data.opInsertAfter(op1,substitute);	// Complete move of unified op into merge block
  }
  else
    data.opInsertBegin(op1,bl);	// Complete move of unified op into merge block
  data.opDestroy(op);		// Destroy the MULTIEQUAL
  data.opDestroy(op2);		// Remove the duplicate (in favor of the unified)
  return 1;
}

/// \class RuleNotDistribute
/// \brief Distribute BOOL_NEGATE:  `!(V && W)  =>  !V || !W`
void RuleNotDistribute::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_BOOL_NEGATE);
}

int4 RuleNotDistribute::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *compop = op->getIn(0)->getDef();
  PcodeOp *newneg1,*newneg2;
  Varnode *newout1,*newout2;
  OpCode opc;

  if (compop == (PcodeOp *)0) return 0;
  switch(compop->code()) {
  case CPUI_BOOL_AND:
    opc = CPUI_BOOL_OR;
    break;
  case CPUI_BOOL_OR:
    opc = CPUI_BOOL_AND;
    break;
  default:
    return 0;
  }
  
  newneg1 = data.newOp(1,op->getAddr());
  newout1 = data.newUniqueOut(1,newneg1);
  data.opSetOpcode(newneg1,CPUI_BOOL_NEGATE);
  data.opSetInput(newneg1,compop->getIn(0),0);
  data.opInsertBefore(newneg1,op);

  newneg2 = data.newOp(1,op->getAddr());
  newout2 = data.newUniqueOut(1,newneg2);
  data.opSetOpcode(newneg2,CPUI_BOOL_NEGATE);
  data.opSetInput(newneg2,compop->getIn(1),0);
  data.opInsertBefore(newneg2,op);
  
  data.opSetOpcode(op,opc);
  data.opSetInput(op,newout1,0);
  data.opInsertInput(op,newout2,1);
  return 1;
}

/// \class RuleHighOrderAnd
/// \brief Simplify INT_AND when applied to aligned INT_ADD:  `(V + c) & 0xfff0  =>  V + (c & 0xfff0)`
///
/// If V and W are aligned to a mask, then
/// `((V + c) + W) & 0xfff0   =>   (V + (c & 0xfff0)) + W`
void RuleHighOrderAnd::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
}

int4 RuleHighOrderAnd::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *xalign;
  Varnode *cvn1 = op->getIn(1);
  if (!cvn1->isConstant()) return 0;
  if (!op->getIn(0)->isWritten()) return 0;
  PcodeOp *addop = op->getIn(0)->getDef();
  if (addop->code() != CPUI_INT_ADD) return 0;

  uintb val = cvn1->getOffset();
  int4 size = cvn1->getSize();
  // Check that cvn1 is of the form    11110000
  if (((val-1)|val) != calc_mask(size)) return 0;

  Varnode *cvn2 = addop->getIn(1);
  if (cvn2->isConstant()) {
    xalign = addop->getIn(0);
    if (xalign->isFree()) return 0;
    uintb mask1 = xalign->getNZMask();
    // addop->Input(0) must be unaffected by the AND
    if ((mask1 & val)!=mask1) return 0;

    data.opSetOpcode(op,CPUI_INT_ADD);
    data.opSetInput(op,xalign,0);
    val = val & cvn2->getOffset();
    data.opSetInput(op,data.newConstant(size,val),1);
    return 1;
  }
  else {
    if (addop->getOut()->loneDescend() != op) return 0;
    for(int4 i=0;i<2;++i) {
      Varnode *zerovn = addop->getIn(i);
      uintb mask2 = zerovn->getNZMask();
      if ((mask2 & val)!=mask2) continue; // zerovn must be unaffected by the AND operation
      Varnode *nonzerovn = addop->getIn(1-i);
      if (!nonzerovn->isWritten()) continue;
      PcodeOp *addop2 = nonzerovn->getDef();
      if (addop2->code() != CPUI_INT_ADD) continue;
      if (nonzerovn->loneDescend() != addop) continue;
      cvn2 = addop2->getIn(1);
      if (!cvn2->isConstant()) continue;
      xalign = addop2->getIn(0);
      mask2 = xalign->getNZMask();
      if ((mask2 & val)!=mask2) continue;
      val = val & cvn2->getOffset();
      data.opSetInput(addop2,data.newConstant(size,val),1);
      // Convert the AND to a COPY
      data.opRemoveInput(op,1);
      data.opSetOpcode(op,CPUI_COPY);
      return 1;
    }
  }
  return 0;
}

/// \class RuleAndDistribute
/// \brief Distribute INT_AND through INT_OR if result is simpler
void RuleAndDistribute::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
}

int4 RuleAndDistribute::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *orvn,*othervn,*newvn1,*newvn2;
  PcodeOp *orop = (PcodeOp *)0;
  PcodeOp *newop1,*newop2;
  uintb ormask1,ormask2,othermask,fullmask;
  int4 i,size;

  size = op->getOut()->getSize();
  if (size > sizeof(uintb)) return 0; // FIXME: uintb should be arbitrary precision
  fullmask = calc_mask(size);
  for(i=0;i<2;++i) {
    othervn = op->getIn(1-i);
    if (!othervn->isHeritageKnown()) continue;
    orvn = op->getIn(i);
    orop = orvn->getDef();
    if (orop == (PcodeOp *)0) continue;
    if (orop->code() != CPUI_INT_OR) continue;
    if (!orop->getIn(0)->isHeritageKnown()) continue;
    if (!orop->getIn(1)->isHeritageKnown()) continue;
    othermask = othervn->getNZMask();
    if (othermask == 0) continue; // This case picked up by andmask
    if (othermask == fullmask) continue; // Nothing useful from distributing
    ormask1 = orop->getIn(0)->getNZMask();
    if ((ormask1 & othermask)==0) break; // AND would cancel if distributed
    ormask2 = orop->getIn(1)->getNZMask();
    if ((ormask2 & othermask)==0) break; // AND would cancel if distributed
    if (othervn->isConstant()) {
      if ((ormask1 & othermask) == ormask1) break; // AND is trivial if distributed
      if ((ormask2 & othermask) == ormask2) break;
    }
  }
  if (i==2) return 0;
				// Do distribution
  newop1 = data.newOp(2,op->getAddr()); // Distribute AND
  newvn1 = data.newUniqueOut(size,newop1);
  data.opSetOpcode(newop1,CPUI_INT_AND);
  data.opSetInput(newop1, orop->getIn(0), 0); // To first input of original OR
  data.opSetInput(newop1, othervn, 1);
  data.opInsertBefore(newop1, op);

  newop2 = data.newOp(2,op->getAddr()); // Distribute AND
  newvn2 = data.newUniqueOut(size,newop2);
  data.opSetOpcode(newop2,CPUI_INT_AND);
  data.opSetInput(newop2, orop->getIn(1), 0); // To second input of original OR
  data.opSetInput(newop2, othervn, 1);
  data.opInsertBefore(newop2, op);

  data.opSetInput( op, newvn1, 0); // new OR's inputs are outputs of new ANDs
  data.opSetInput( op, newvn2, 1);
  data.opSetOpcode(op, CPUI_INT_OR);
  
  return 1;
}

/// \class RuleLessOne
/// \brief Transform INT_LESS of 0 or 1:  `V < 1  =>  V == 0,  V <= 0  =>  V == 0`
void RuleLessOne::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_LESS);
  oplist.push_back(CPUI_INT_LESSEQUAL);
}

int4 RuleLessOne::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *constvn = op->getIn(1);

  if (!constvn->isConstant()) return 0;
  uintb val = constvn->getOffset();
  if ((op->code()==CPUI_INT_LESS)&&(val != 1)) return 0;
  if ((op->code()==CPUI_INT_LESSEQUAL)&&(val != 0)) return 0;

  data.opSetOpcode(op,CPUI_INT_EQUAL);
  if (val != 0)
    data.opSetInput(op,data.newConstant(constvn->getSize(),0),1);
  return 1;
}

void RuleRangeMeld::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_BOOL_OR);
  oplist.push_back(CPUI_BOOL_AND);
}

/// \class RuleRangeMeld
/// \brief Merge range conditions of the form: `V s< c, c s< V, V == c, V != c`
///
/// Look for combinations of these forms based on BOOL_AND and BOOL_OR, such as
///
///   \<range1>&&\<range2> OR \<range1>||\<range2>
///
/// Try to union or intersect the ranges to produce
/// a more concise expression.
int4 RuleRangeMeld::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *sub1,*sub2;
  Varnode *vn1,*vn2;
  Varnode *A1,*A2;
  int4 restype;

  vn1 = op->getIn(0);
  if (!vn1->isWritten()) return 0;
  vn2 = op->getIn(1);
  if (!vn2->isWritten()) return 0;
  sub1 = vn1->getDef();
  if (!sub1->isBoolOutput())
    return 0;
  sub2 = vn2->getDef();
  if (!sub2->isBoolOutput())
    return 0;

  CircleRange range1(true);
  Varnode *markup = (Varnode *)0;
  A1 = range1.pullBack(sub1,&markup,false);
  if (A1 == (Varnode *)0) return 0;
  CircleRange range2(true);
  A2 = range2.pullBack(sub2,&markup,false);
  if (A2 == (Varnode *)0) return 0;
  if (sub1->code() == CPUI_BOOL_NEGATE) { // Do an extra pull back, if the last step is a '!'
    if (!A1->isWritten()) return 0;
    A1 = range1.pullBack(A1->getDef(),&markup,false);
    if (A1 == (Varnode *)0) return 0;
  }
  if (sub2->code() == CPUI_BOOL_NEGATE) { // Do an extra pull back, if the last step is a '!'
    if (!A2->isWritten()) return 0;
    A2 = range2.pullBack(A2->getDef(),&markup,false);
    if (A2 == (Varnode *)0) return 0;
  }
  if (!functionalEquality(A1,A2)) {
    if (A2->getSize() == A1->getSize()) return 0;
    if ((A1->getSize() < A2->getSize())&&(A2->isWritten()))
      A2 = range2.pullBack(A2->getDef(),&markup,false);
    else if (A1->isWritten())
      A1 = range1.pullBack(A1->getDef(),&markup,false);
    if (A1 != A2) return 0;
  }
  if (!A1->isHeritageKnown()) return 0;

  if (op->code() == CPUI_BOOL_AND)
    restype = range1.intersect(range2);
  else
    restype = range1.circleUnion(range2);
  
  if (restype == 0) {
    OpCode opc;
    uintb resc;
    int4 resslot;
    restype = range1.translate2Op(opc,resc,resslot);
    if (restype == 0) {
      Varnode *newConst = data.newConstant(A1->getSize(),resc);
      if (markup != (Varnode *)0) {		// We have potential constant markup
	newConst->copySymbolIfValid(markup);	// Propagate the markup into our new constant
      }
      data.opSetOpcode(op,opc);
      data.opSetInput(op,A1,1-resslot);
      data.opSetInput(op,newConst,resslot);
      return 1;
    }
  }

  if (restype == 2) return 0;	// Cannot represent
  if (restype == 1) {		// Pieces covers everything, condition is always true
    data.opSetOpcode(op,CPUI_COPY);
    data.opRemoveInput(op,1);
    data.opSetInput(op,data.newConstant(1,1),0);
  }
  else if (restype == 3) {	// Nothing left in intersection, condition is always false
    data.opSetOpcode(op,CPUI_COPY);
    data.opRemoveInput(op,1);
    data.opSetInput(op,data.newConstant(1,0),0);
  }
  return 1;
}

/// \class RuleFloatRange
/// \brief Merge range conditions of the form: `V f< c, c f< V, V f== c` etc.
///
/// Convert `(V f< W)||(V f== W)   =>   V f<= W` (and similar variants)
void RuleFloatRange::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_BOOL_OR);
  oplist.push_back(CPUI_BOOL_AND);
}

int4 RuleFloatRange::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *cmp1,*cmp2;
  Varnode *vn1,*vn2;

  vn1 = op->getIn(0);
  if (!vn1->isWritten()) return 0;
  vn2 = op->getIn(1);
  if (!vn2->isWritten()) return 0;
  cmp1 = vn1->getDef();
  cmp2 = vn2->getDef();
  OpCode opccmp1 = cmp1->code();
  // Set cmp1 to LESS or LESSEQUAL operator, cmp2 is the "other" operator
  if ((opccmp1!=CPUI_FLOAT_LESS)&&(opccmp1!=CPUI_FLOAT_LESSEQUAL)) {
    cmp1 = cmp2;
    cmp2 = vn1->getDef();
    opccmp1 = cmp1->code();
  }
  OpCode resultopc = CPUI_COPY;
  if (opccmp1==CPUI_FLOAT_LESS) {
    if ((cmp2->code() == CPUI_FLOAT_EQUAL)&&(op->code()==CPUI_BOOL_OR))
      resultopc = CPUI_FLOAT_LESSEQUAL;
  }
  else if (opccmp1==CPUI_FLOAT_LESSEQUAL) {
    if ((cmp2->code() == CPUI_FLOAT_NOTEQUAL)&&(op->code()==CPUI_BOOL_AND))
      resultopc = CPUI_FLOAT_LESS;
  }

  if (resultopc == CPUI_COPY) return 0;

  // Make sure both operators are comparing the same things
  Varnode *nvn1,*cvn1;
  int4 slot1 = 0;
  nvn1 = cmp1->getIn(slot1);	// Set nvn1 to a non-constant off of cmp1
  if (nvn1->isConstant()) {
    slot1 = 1;
    nvn1 = cmp1->getIn(slot1);
    if (nvn1->isConstant()) return 0;
  }
  if (nvn1->isFree()) return 0;
  cvn1 = cmp1->getIn(1-slot1);	// Set cvn1 to the "other" slot off of cmp1
  int4 slot2;
  if (nvn1 != cmp2->getIn(0)) {
    slot2 = 1;
    if (nvn1 != cmp2->getIn(1))
      return 0;
  }
  else
    slot2 = 0;
  Varnode *matchvn = cmp2->getIn(1-slot2);
  if (cvn1->isConstant()) {
    if (!matchvn->isConstant()) return 0;
    if (matchvn->getOffset() != cvn1->getOffset()) return 0;
  }
  else if (cvn1 != matchvn)
    return 0;
  else if (cvn1->isFree())
    return 0;

  // Collapse the 2 comparisons into 1 comparison
  data.opSetOpcode(op,resultopc);
  data.opSetInput(op,nvn1,slot1);
  if (cvn1->isConstant())
    data.opSetInput(op,data.newConstant(cvn1->getSize(),cvn1->getOffset()),1-slot1);
  else
    data.opSetInput(op,cvn1,1-slot1);
  return 1;
}

/// \class RuleAndCommute
/// \brief Commute INT_AND with INT_LEFT and INT_RIGHT: `(V << W) & d  =>  (V & (W >> c)) << c`
///
/// This makes sense to do if W is constant and there is no other use of (V << W)
/// If W is \b not constant, it only makes sense if the INT_AND is likely to cancel
/// with a specific INT_OR or PIECE
void RuleAndCommute::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
}

int4 RuleAndCommute::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *orvn,*shiftvn,*othervn,*newvn1,*newvn2,*savn;
  PcodeOp *orop,*shiftop,*newop1,*newop2;
  uintb ormask1,ormask2,othermask,fullmask;
  OpCode opc = CPUI_INT_OR; // Unnecessary initialization
  int4 sa,i,size;

  orvn = othervn = savn = (Varnode *)0; // Unnecessary initialization
  size = op->getOut()->getSize();
  if (size > sizeof(uintb)) return 0; // FIXME: uintb should be arbitrary precision
  fullmask = calc_mask(size);
  for(i=0;i<2;++i) {
    shiftvn = op->getIn(i);
    shiftop = shiftvn->getDef();
    if (shiftop == (PcodeOp *)0) continue;
    opc = shiftop->code();
    if ((opc != CPUI_INT_LEFT)&&(opc!=CPUI_INT_RIGHT)) continue;
    savn = shiftop->getIn(1);
    if (!savn->isConstant()) continue;
    sa = (int4)savn->getOffset();

    othervn = op->getIn(1-i);
    if (!othervn->isHeritageKnown()) continue;
    othermask = othervn->getNZMask();
      // Check if AND is only zeroing bits which are already
      // zeroed by the shift, in which case andmask takes
      // care of it
    if (opc==CPUI_INT_RIGHT) {
      if ((fullmask>>sa)==othermask) continue;
      othermask <<= sa;		// Calc mask as it will be after commute
    }
    else {
      if (((fullmask<<sa)&&fullmask)==othermask) continue;
      othermask >>= sa;		// Calc mask as it will be after commute
    }
    if (othermask == 0) continue; // Handled by andmask
    if (othermask == fullmask) continue;

    orvn = shiftop->getIn(0);
    if ((opc==CPUI_INT_LEFT)&&(othervn->isConstant())) {
      //  (v & #c) << #sa     if preferred to (v << #sa) & #(c << sa)
      // because the mask is right/least justified, so it makes sense as a normalization
      // NOTE: if the shift is right(>>) then performing the AND first does NOT give a justified mask
      // NOTE: if we don't check that AND is masking with a constant, RuleAndCommute causes an infinite
      //       sequence of transforms
      if (shiftvn->loneDescend() == op) break; // If there is no other use of shift, always do the commute
    }

    if (!orvn->isWritten()) continue;
    orop = orvn->getDef();

    if (orop->code() == CPUI_INT_OR) {
      ormask1 = orop->getIn(0)->getNZMask();
      if ((ormask1 & othermask)==0) break;
      ormask2 = orop->getIn(1)->getNZMask();
      if ((ormask2 & othermask)==0) break;
      if (othervn->isConstant()) {
	if ((ormask1 & othermask) == ormask1) break;
	if ((ormask2 & othermask) == ormask2) break;
      }
    }
    else if (orop->code() == CPUI_PIECE) {
      ormask1 = orop->getIn(1)->getNZMask();	// Low part of piece
      if ((ormask1 & othermask)==0) break;
      ormask2 = orop->getIn(0)->getNZMask();	// High part
      ormask2 <<= orop->getIn(1)->getSize() * 8;
      if ((ormask2 & othermask)==0) break;
    }
    else
      continue;
  }
  if (i==2) return 0;
				// Do the commute
  newop1 = data.newOp(2,op->getAddr());
  newvn1 = data.newUniqueOut(size,newop1);
  data.opSetOpcode(newop1,(opc==CPUI_INT_LEFT)?CPUI_INT_RIGHT:CPUI_INT_LEFT);
  data.opSetInput(newop1, othervn, 0);
  data.opSetInput(newop1, savn, 1);
  data.opInsertBefore(newop1, op);

  newop2 = data.newOp(2,op->getAddr());
  newvn2 = data.newUniqueOut(size,newop2);
  data.opSetOpcode(newop2,CPUI_INT_AND);
  data.opSetInput(newop2, orvn, 0);
  data.opSetInput(newop2, newvn1, 1);
  data.opInsertBefore(newop2, op);
  
  data.opSetInput(op, newvn2, 0);
  data.opSetInput(op, savn, 1);
  data.opSetOpcode(op, opc);

  return 1;
}

/// \class RuleAndPiece
/// \brief Convert PIECE to INT_ZEXT where appropriate: `V & concat(W,X)  =>  zext(X)`
///
/// Conversion to INT_ZEXT works if we know the upper part of the result is zero.
///
/// Similarly if the lower part is zero:  `V & concat(W,X)  =>  V & concat(#0,X)`
void RuleAndPiece::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
}

int4 RuleAndPiece::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *piecevn,*othervn,*highvn,*lowvn,*newvn,*newvn2;
  PcodeOp *pieceop,*newop;
  uintb othermask,maskhigh,masklow;
  OpCode opc = CPUI_PIECE;	// Unnecessary initialization
  int4 i,size;

  size = op->getOut()->getSize();
  highvn = lowvn = (Varnode *)0; // Unnecessary initialization
  for(i=0;i<2;++i) {
    piecevn = op->getIn(i);
    if (!piecevn->isWritten()) continue;
    pieceop = piecevn->getDef();
    if (pieceop->code() != CPUI_PIECE) continue;
    othervn = op->getIn(1-i);
    othermask = othervn->getNZMask();
    if (othermask == calc_mask(size)) continue;
    if (othermask == 0) continue; // Handled by andmask
    highvn = pieceop->getIn(0);
    if (!highvn->isHeritageKnown()) continue;
    lowvn = pieceop->getIn(1);
    if (!lowvn->isHeritageKnown()) continue;
    maskhigh = highvn->getNZMask();
    masklow = lowvn->getNZMask();
    if ((maskhigh & (othermask>>(lowvn->getSize()*8)))==0) {
      if ((maskhigh==0)&&(highvn->isConstant())) continue; // Handled by piece2zext
      opc = CPUI_INT_ZEXT;
      break;
    }
    else if ((masklow & othermask)==0) {
      if (lowvn->isConstant()) continue; // Nothing to do
      opc = CPUI_PIECE;
      break;
    }
  }
  if (i==2) return 0;
  if (opc == CPUI_INT_ZEXT) {	// Change PIECE(a,b) to ZEXT(b)
    newop = data.newOp(1,op->getAddr());
    data.opSetOpcode(newop,opc);
    data.opSetInput(newop, lowvn, 0);
   }
   else {			// Change PIECE(a,b) to PIECE(a,#0)
     newvn2 = data.newConstant(lowvn->getSize(),0);
     newop = data.newOp(2,op->getAddr());
     data.opSetOpcode(newop,opc);
     data.opSetInput(newop, highvn, 0);
     data.opSetInput(newop, newvn2, 1);
   }
  newvn = data.newUniqueOut(size,newop);
  data.opInsertBefore(newop, op);
  data.opSetInput(op,newvn,i);
  return 1;
}

/// \class RuleAndZext
/// \brief Convert INT_AND to INT_ZEXT where appropriate: `sext(X) & 0xffff  =>  zext(X)`
///
/// Similarly `concat(Y,X) & 0xffff  =>  zext(X)`
void RuleAndZext::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
}

int4 RuleAndZext::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *cvn1 = op->getIn(1);
  if (!cvn1->isConstant()) return 0;
  if (!op->getIn(0)->isWritten()) return 0;
  PcodeOp *otherop = op->getIn(0)->getDef();
  OpCode opc = otherop->code();
  Varnode *rootvn;
  if (opc == CPUI_INT_SEXT)
    rootvn = otherop->getIn(0);
  else if (opc == CPUI_PIECE)
    rootvn = otherop->getIn(1);
  else
    return 0;
  uintb mask = calc_mask(rootvn->getSize());
  if (mask != cvn1->getOffset())
    return 0;
  if (rootvn->isFree())
    return 0;
  if (rootvn->getSize() > sizeof(uintb))	// FIXME: Should be arbitrary precision
    return 0;
  data.opSetOpcode(op, CPUI_INT_ZEXT);
  data.opRemoveInput(op, 1);
  data.opSetInput(op, rootvn, 0);
  return 1;
}

/// \class RuleAndCompare
/// \brief Simplify INT_ZEXT and SUBPIECE in masked comparison: `zext(V) & c == 0  =>  V & (c & mask) == 0`
///
/// Similarly:  `sub(V,c) & d == 0  =>  V & (d & mask) == 0`
void RuleAndCompare::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_EQUAL);
  oplist.push_back(CPUI_INT_NOTEQUAL);
}

int4 RuleAndCompare::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!data.hasTypeRecoveryStarted()) return 0;
  if (!op->getIn(1)->isConstant()) return 0;
  if (op->getIn(1)->getOffset() != 0) return 0;

  Varnode *andvn,*subvn,*basevn,*constvn;
  PcodeOp *andop,*subop;
  uintb andconst,baseconst;

  andvn = op->getIn(0);
  if (!andvn->isWritten()) return 0;
  andop = andvn->getDef();
  if (andop->code() != CPUI_INT_AND) return 0;
  if (!andop->getIn(1)->isConstant()) return 0;
  subvn = andop->getIn(0);
  if (!subvn->isWritten()) return 0;
  subop = subvn->getDef();
  switch(subop->code()) {
  case CPUI_SUBPIECE:
    basevn = subop->getIn(0);
    baseconst = andop->getIn(1)->getOffset();
    andconst  = baseconst << subop->getIn(1)->getOffset() * 8;
    break;
  case CPUI_INT_ZEXT:
    basevn = subop->getIn(0);
    baseconst = andop->getIn(1)->getOffset();
    andconst = baseconst & calc_mask(basevn->getSize());
    break;
  default:
    return 0;
  }

  if (basevn->getSize() > sizeof(uintb)) return 0; // No array masking is allowed
  Datatype *ct = basevn->getTypeReadFacing(subop);
  int4 sz = subvn->getSize();
  if (!validateDatatype(ct,sz)) return 0;
  if (baseconst == calc_mask(andvn->getSize())) return 0;	// Degenerate AND
  if (basevn->isFree()) return 0;

  constvn = data.newConstant(basevn->getSize(),andconst);
  if (baseconst == andconst)			// If no effective change in constant (except varnode size)
    constvn->copySymbol(andop->getIn(1));	// Keep any old symbol
  // New version of and with bigger inputs
  PcodeOp *newop = data.newOp(2,andop->getAddr());
  data.opSetOpcode(newop,CPUI_INT_AND);
  Varnode *newout = data.newUniqueOut(basevn->getSize(),newop);
  data.opSetInput(newop,basevn,0);
  data.opSetInput(newop,constvn,1);
  data.opInsertBefore(newop,andop);

  data.opSetInput(op,newout,0);
  data.opSetInput(op,data.newConstant(basevn->getSize(),0),1);
  return 1;
}

bool RuleAndCompare::validateDatatype(Datatype *dt,int4 sz)

{
  int8 newoff;
  Datatype *subdt = dt->getSubType(0,&newoff);
  if (subdt == (Datatype *)0) return true;
  if (newoff != 0) return true;
  if (subdt->getSize() < sz) return true;
  if (subdt->getMetatype() == TYPE_INT) return false;
  if (subdt->getMetatype() == TYPE_UINT) return false;
  if (subdt->getMetatype() == TYPE_BOOL) return false;
  if (subdt->getMetatype() == TYPE_FLOAT) return false;
  if (subdt->getMetatype() == TYPE_PTR) return false;
  return validateDatatype(subdt,sz);
}

/// \class RuleDoubleSub
/// \brief Simplify chained SUBPIECE:  `sub( sub(V,c), d)  =>  sub(V, c+d)`
void RuleDoubleSub::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleDoubleSub::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *op2;
  Varnode *vn;
  int4 offset1,offset2;

  vn = op->getIn(0);
  if (!vn->isWritten()) return 0;
  op2 = vn->getDef();
  if (op2->code() != CPUI_SUBPIECE) return 0;
  offset1 = op->getIn(1)->getOffset();
  offset2 = op2->getIn(1)->getOffset();

  data.opSetInput(op,op2->getIn(0),0);	// Skip middleman
  data.opSetInput(op,data.newConstant(4,offset1+offset2), 1);
  return 1;
}

/// \class RuleDoubleShift
/// \brief Simplify chained shifts INT_LEFT and INT_RIGHT
///
/// INT_MULT is considered a shift if it multiplies by a constant power of 2.
/// The shifts can combine or cancel. Combined shifts may zero out result.
///
///    - `(V << c) << d  =>  V << (c+d)`
///    - `(V << c) >> c` =>  V & 0xff`
void RuleDoubleShift::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_LEFT);
  oplist.push_back(CPUI_INT_RIGHT);
  oplist.push_back(CPUI_INT_MULT);
}

int4 RuleDoubleShift::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *secvn,*newvn;
  PcodeOp *secop;
  OpCode opc1,opc2;
  int4 sa1,sa2,size;
  uintb mask;

  if (!op->getIn(1)->isConstant()) return 0;
  secvn = op->getIn(0);
  if (!secvn->isWritten()) return 0;
  secop = secvn->getDef();
  opc2 = secop->code();
  if ((opc2!=CPUI_INT_LEFT)&&(opc2!=CPUI_INT_RIGHT)&&(opc2!=CPUI_INT_MULT))
    return 0;
  if (!secop->getIn(1)->isConstant()) return 0;
  opc1 = op->code();
  size = secvn->getSize();
  if (!secop->getIn(0)->isHeritageKnown()) return 0;

  if (opc1 == CPUI_INT_MULT) {
    uintb val = op->getIn(1)->getOffset();
    sa1 = leastsigbit_set(val);
    if ((val>>sa1) != (uintb)1) return 0; // Not multiplying by a power of 2
    opc1 = CPUI_INT_LEFT;
  }
  else
    sa1 = op->getIn(1)->getOffset();
  if (opc2 == CPUI_INT_MULT) {
    uintb val = secop->getIn(1)->getOffset();
    sa2 = leastsigbit_set(val);
    if ((val>>sa2) != (uintb)1) return 0; // Not multiplying by a power of 2
    opc2 = CPUI_INT_LEFT;
  }
  else
    sa2 = secop->getIn(1)->getOffset();
  if (opc1 == opc2) {
    if (sa1 + sa2 < 8*size) {
      newvn = data.newConstant(4,sa1+sa2);
      data.opSetOpcode(op,opc1);
      data.opSetInput(op,secop->getIn(0),0);
      data.opSetInput(op,newvn,1);
    }
    else {
      newvn = data.newConstant(size,0);
      data.opSetOpcode(op,CPUI_COPY);
      data.opSetInput(op,newvn,0);
      data.opRemoveInput(op,1);
    }
  }
  else if (sa1 == sa2 && size <= sizeof(uintb)) {	// FIXME:  precision
    mask = calc_mask(size);
    if (opc1 == CPUI_INT_LEFT) {
      // The INT_LEFT is highly likely to be a multiply, so don't collapse to an INT_AND if there
      // are other uses of the intermediate value.
      if (secvn->loneDescend() == (PcodeOp *)0) return 0;
      mask = (mask<<sa1) & mask;
    }
    else
      mask = (mask>>sa1) & mask;
    newvn = data.newConstant(size,mask);
    data.opSetOpcode(op,CPUI_INT_AND);
    data.opSetInput(op,secop->getIn(0),0);
    data.opSetInput(op,newvn,1);
  }
  else
    return 0;
  return 1;
}

/// \class RuleDoubleArithShift
/// \brief Simplify two sequential INT_SRIGHT: `(x s>> c) s>> d   =>  x s>> saturate(c + d)`
///
/// Division optimization in particular can produce a sequence of signed right shifts.
/// The shift amounts add up to the point where the sign bit has saturated the entire result.
void RuleDoubleArithShift::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SRIGHT);
}

int4 RuleDoubleArithShift::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *constD = op->getIn(1);
  if (!constD->isConstant()) return 0;
  Varnode *shiftin = op->getIn(0);
  if (!shiftin->isWritten()) return 0;
  PcodeOp *shift2op = shiftin->getDef();
  if (shift2op->code() != CPUI_INT_SRIGHT) return 0;
  Varnode *constC = shift2op->getIn(1);
  if (!constC->isConstant()) return 0;
  Varnode *inVn = shift2op->getIn(0);
  if (inVn->isFree()) return 0;
  int4 max = op->getOut()->getSize() * 8 - 1;	// This is maximum possible shift.
  int4 sa = (int4)constC->getOffset() + (int4)constD->getOffset();
  if (sa <= 0) return 0;	// Something is wrong
  if (sa > max)
    sa = max;			// Shift amount has saturated
  data.opSetInput(op, inVn, 0);
  data.opSetInput(op, data.newConstant(4, sa),1);
  return 1;
}

/// \class RuleConcatShift
/// \brief Simplify INT_RIGHT canceling PIECE: `concat(V,W) >> c  =>  zext(V)`
///
/// Right shifts (signed and unsigned) can throw away the least significant part
/// of a concatentation.  The result is a (sign or zero) extension of the most significant part.
/// Depending on the original shift amount, the extension may still need to be shifted.
void RuleConcatShift::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_RIGHT);
  oplist.push_back(CPUI_INT_SRIGHT);
}

int4 RuleConcatShift::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(1)->isConstant()) return 0;

  Varnode *shiftin = op->getIn(0);
  if (!shiftin->isWritten()) return 0;
  PcodeOp *concat = shiftin->getDef();
  if (concat->code() != CPUI_PIECE) return 0;
  
  int4 sa = op->getIn(1)->getOffset();
  int4 leastsize = concat->getIn(1)->getSize() * 8;
  if (sa < leastsize) return 0;	// Does shift throw away least sig part
  Varnode *mainin = concat->getIn(0);
  if (mainin->isFree()) return 0;
  sa -= leastsize;
  OpCode extcode = (op->code() == CPUI_INT_RIGHT) ? CPUI_INT_ZEXT : CPUI_INT_SEXT;
  if (sa == 0) {		// Exact cancelation
    data.opRemoveInput(op,1);	// Remove thrown away least
    data.opSetOpcode(op,extcode); // Change to extension
    data.opSetInput(op,mainin,0);
  }
  else {
    // Create a new extension op
    PcodeOp *extop = data.newOp(1,op->getAddr());
    data.opSetOpcode(extop,extcode);
    Varnode *newvn = data.newUniqueOut(shiftin->getSize(),extop);
    data.opSetInput(extop,mainin,0);

    // Adjust the shift amount
    data.opSetInput(op,newvn,0);
    data.opSetInput(op,data.newConstant(op->getIn(1)->getSize(),sa),1);
    data.opInsertBefore(extop,op);
  }
  return 1;
}

/// \class RuleLeftRight
/// \brief Transform canceling INT_RIGHT or INT_SRIGHT of INT_LEFT
///
/// This works for both signed and unsigned right shifts. The shift
/// amount must be a multiple of 8.
///
/// `(V << c) s>> c  =>  sext( sub(V, #0) )`
void RuleLeftRight::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_RIGHT);
  oplist.push_back(CPUI_INT_SRIGHT);
}

int4 RuleLeftRight::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(1)->isConstant()) return 0;

  Varnode *shiftin = op->getIn(0);
  if (!shiftin->isWritten()) return 0;
  PcodeOp *leftshift = shiftin->getDef();
  if (leftshift->code() != CPUI_INT_LEFT) return 0;
  if (!leftshift->getIn(1)->isConstant()) return 0;
  uintb sa = op->getIn(1)->getOffset();
  if (leftshift->getIn(1)->getOffset() != sa) return 0; // Left shift must be by same amount

  if ((sa & 7) != 0) return 0;	// Must be multiple of 8
  int4 isa = (int4)(sa>>3);
  int4 tsz = shiftin->getSize() - isa;
  if ((tsz!=1)&&(tsz!=2)&&(tsz!=4)&&(tsz!=8)) return 0;
  
  if (shiftin->loneDescend() != op) return 0;
  Address addr = shiftin->getAddr();
  if (addr.isBigEndian())
    addr = addr + isa;
  data.opUnsetInput(op,0);
  data.opUnsetOutput(leftshift);
  addr.renormalize(tsz);
  Varnode *newvn = data.newVarnodeOut(tsz,addr,leftshift);
  data.opSetOpcode(leftshift,CPUI_SUBPIECE);
  data.opSetInput(leftshift, data.newConstant( leftshift->getIn(1)->getSize(), 0), 1);
  data.opSetInput(op, newvn, 0);
  data.opRemoveInput(op,1);	// Remove the right-shift constant
  data.opSetOpcode( op, (op->code() == CPUI_INT_SRIGHT) ? CPUI_INT_SEXT : CPUI_INT_ZEXT);
  return 1;
}

/// \class RuleShiftCompare
/// \brief Transform shifts in comparisons:  `V >> c == d  =>  V == (d << c)`
///
/// Similarly: `V << c == d  =>  V & mask == (d >> c)`
///
/// The rule works on both INT_EQUAL and INT_NOTEQUAL.
void RuleShiftCompare::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_EQUAL);
  oplist.push_back(CPUI_INT_NOTEQUAL);
}

int4 RuleShiftCompare::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *shiftvn,*constvn,*savn,*mainvn;
  PcodeOp *shiftop;
  int4 sa;
  uintb constval,nzmask,newconst;
  OpCode opc;
  bool isleft;

  shiftvn = op->getIn(0);
  constvn = op->getIn(1);
  if (!constvn->isConstant()) return 0;
  if (!shiftvn->isWritten()) return 0;
  shiftop = shiftvn->getDef();
  opc = shiftop->code();
  if (opc==CPUI_INT_LEFT) {
    isleft = true;
    savn = shiftop->getIn(1);
    if (!savn->isConstant()) return 0;
    sa = savn->getOffset();
  }
  else if (opc == CPUI_INT_RIGHT) {
    isleft = false;
    savn = shiftop->getIn(1);
    if (!savn->isConstant()) return 0;
    sa = savn->getOffset();
  // There are definitely some situations where you don't want this rule to apply, like jump
  // table analysis where the switch variable is a bit field.
  // When shifting to the right, this is a likely shift out of a bitfield, which we would want to keep
  // We only apply when we know we will eliminate a variable
    if (shiftvn->loneDescend() != op) return 0;
  }
  else if (opc == CPUI_INT_MULT) {
    isleft = true;
    savn = shiftop->getIn(1);
    if (!savn->isConstant()) return 0;
    uintb val = savn->getOffset();
    sa = leastsigbit_set(val);
    if ((val>>sa) != (uintb)1) return 0; // Not multiplying by a power of 2
  }
  else if (opc == CPUI_INT_DIV) {
    isleft = false;
    savn = shiftop->getIn(1);
    if (!savn->isConstant()) return 0;
    uintb val = savn->getOffset();
    sa = leastsigbit_set(val);
    if ((val>>sa) != (uintb)1) return 0; // Not dividing by a power of 2
    if (shiftvn->loneDescend() != op) return 0;
  }
  else
    return 0;
  
  if (sa==0) return 0;
  mainvn = shiftop->getIn(0);
  if (mainvn->isFree()) return 0;
  if (mainvn->getSize() > sizeof(uintb)) return 0;	// FIXME: uintb should be arbitrary precision

  constval = constvn->getOffset();
  nzmask = mainvn->getNZMask();
  if (isleft) {
    newconst = constval >> sa;
    if ((newconst << sa) != constval) return 0;	// Information lost in constval
    uintb tmp = (nzmask << sa) & calc_mask(shiftvn->getSize());
    if ((tmp>>sa)!=nzmask) {	// Information is lost in main
      // We replace the LEFT with and AND mask
      // This must be the lone use of the shift
      if (shiftvn->loneDescend() != op) return 0;
      sa = 8*shiftvn->getSize() - sa;
      tmp = (((uintb)1) << sa)-1;
      Varnode *newmask = data.newConstant(constvn->getSize(),tmp);
      PcodeOp *newop = data.newOp(2,op->getAddr());
      data.opSetOpcode(newop,CPUI_INT_AND);
      Varnode *newtmpvn = data.newUniqueOut(constvn->getSize(),newop);
      data.opSetInput(newop, mainvn, 0);
      data.opSetInput(newop, newmask, 1);
      data.opInsertBefore(newop,shiftop);
      data.opSetInput(op,newtmpvn,0);
      data.opSetInput(op,data.newConstant(constvn->getSize(),newconst),1);
      return 1;
    }
  }
  else {
    if (((nzmask >> sa)<<sa)!=nzmask) return 0;	// Information is lost
    newconst = (constval << sa) & calc_mask(shiftvn->getSize());
    if ((newconst>>sa)!=constval) return 0; // Information is lost in constval
  }
  Varnode *newconstvn = data.newConstant(constvn->getSize(),newconst);
  data.opSetInput(op,mainvn,0);
  data.opSetInput(op,newconstvn,1);
  return 1;
}

// void RuleShiftLess::getOpList(vector<uint4> &oplist) const

// {
//   oplist.push_back(CPUI_INT_LESS);
//   oplist.push_back(CPUI_INT_LESSEQUAL);
// }

// int4 RuleShiftLess::applyOp(PcodeOp *op,Funcdata &data)

// { //  a >> #sa  <  #c   =>  a <  #d,  where #d = #c << #sa   OR
//   //  a >> #sa  <= #c   =>  a <= #d,  where #d = #c << #sa + (1<<#sa)-1
//   Varnode *shiftvn,*constvn,*savn,*mainvn;
//   PcodeOp *shiftop;
//   int4 sa;
//   OpCode opc;
//   uintb constval,shiftval;
//   bool zerofill = true;
//   bool isless = true;

//   shiftvn = op->getIn(0);
//   constvn = op->getIn(1);
//   if (!constvn->isConstant()) {
//     constvn = shiftvn;
//     if (!constvn->isConstant()) return 0;
//     zerofill = !zerofill;
//     isless = false;
//     shiftvn = op->getIn(0);
//   }
//   if (!shiftvn->isWritten()) return 0;
//   shiftop = shiftvn->getDef();
//   opc = shiftop->code();
//   if (opc==CPUI_INT_RIGHT) {
//     savn = shiftop->getIn(1);
//     if (!savn->isConstant()) return 0;
//     sa = savn->getOffset();
//   }
//   else if (opc == CPUI_INT_DIV) {
//     savn = shiftop->getIn(1);
//     if (!savn->isConstant()) return 0;
//     uintb val = savn->getOffset();
//     sa = leastsigbit_set(val);
//     if ((val>>sa) != (uintb)1) return 0; // Not dividing by a power of 2
//   }
//   else
//     return 0;
//   mainvn = shiftop->getIn(0);
//   if (mainvn->isFree()) return 0;
//   if (mainvn->getSize() > sizeof(uintb)) return 0; // FIXME: uintb should be arbitrary precision

//   if (sa >= mainvn->getSize() *8) return 0;
//   constval = constvn->getOffset();
//   shiftval = (constval << sa) & calc_mask(mainvn->getSize());
//   if ((shiftval >> sa) != constval) {
//     // In this case, its impossible for there to be anything but a zero bit in mainvn at the
//     // high-order bit of constval, so the test degenerates to always true or always false;
//     data.opRemoveInput(op,0);
//     data.opSetOpcode(op,CPUI_COPY);
//     mainvn = data.newConstant( 1, zerofill ? 1 : 0);
//     data.opSetInput(op,mainvn,0);
//     return 1;
//   }
//   if (op->code() == CPUI_INT_LESSEQUAL)
//     zerofill = !zerofill;
//   if (!zerofill) {		// When shifting constval, rather than filling with zeroes, fill with ones
//     uintb fillval = (uintb)1 << sa;
//     fillval -= 1;
//     shiftval += fillval;
//   }
//   Varnode *newconstvn = data.newConstant(constvn->getSize(),shiftval);
//   if (isless) {
//     data.opSetInput(op,mainvn,0);
//     data.opSetInput(op,newconstvn,1);
//   }
//   else {
//     data.opSetInput(op,mainvn,1);
//     data.opSetInput(op,newconstvn,0);
//   }
//   return 1;
// }

/// \class RuleLessEqual
/// \brief Simplify 'less than or equal':  `V < W || V == W  =>  V <= W`
///
/// Similarly: `V < W || V != W  =>  V != W`
///
/// Handle INT_SLESS variants as well.
void RuleLessEqual::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_BOOL_OR);
}

int4 RuleLessEqual::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *compvn1,*compvn2,*vnout1,*vnout2;
  PcodeOp *op_less,*op_equal;
  OpCode opc,equalopc;
  
  vnout1 = op->getIn(0);
  if (!vnout1->isWritten()) return 0;
  vnout2 = op->getIn(1);
  if (!vnout2->isWritten()) return 0;
  op_less = vnout1->getDef();
  opc = op_less->code();
  if ((opc != CPUI_INT_LESS)&&(opc!=CPUI_INT_SLESS)) {
    op_equal = op_less;
    op_less = vnout2->getDef();
    opc = op_less->code();
    if ((opc != CPUI_INT_LESS)&&(opc!=CPUI_INT_SLESS))
      return 0;
  }
  else
    op_equal = vnout2->getDef();
  equalopc = op_equal->code();
  if ((equalopc != CPUI_INT_EQUAL)&&( equalopc != CPUI_INT_NOTEQUAL))
    return 0;
  
  compvn1 = op_less->getIn(0);
  compvn2 = op_less->getIn(1);
  if (!compvn1->isHeritageKnown()) return 0;
  if (!compvn2->isHeritageKnown()) return 0;
  if (((*compvn1 != *op_equal->getIn(0))||(*compvn2 != *op_equal->getIn(1)))&&
      ((*compvn1 != *op_equal->getIn(1))||(*compvn2 != *op_equal->getIn(0))))
    return 0;

  if (equalopc == CPUI_INT_NOTEQUAL) { // op_less is redundant
    data.opSetOpcode(op, CPUI_COPY); // Convert OR to COPY
    data.opRemoveInput(op,1);
    data.opSetInput(op,op_equal->getOut(),0); // Taking the NOTEQUAL output
  }
  else {
    data.opSetInput(op,compvn1,0);
    data.opSetInput(op,compvn2,1);
    data.opSetOpcode(op, (opc==CPUI_INT_SLESS) ? CPUI_INT_SLESSEQUAL : CPUI_INT_LESSEQUAL);
  }

  return 1;
}

/// \class RuleLessNotEqual
/// \brief Simplify INT_LESSEQUAL && INT_NOTEQUAL:  `V <= W && V != W  =>  V < W`
///
/// Handle INT_SLESSEQUAL variant.
void RuleLessNotEqual::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_BOOL_AND);
}

int4 RuleLessNotEqual::applyOp(PcodeOp *op,Funcdata &data)

{				// Convert [(s)lessequal AND notequal] to (s)less
  Varnode *compvn1,*compvn2,*vnout1,*vnout2;
  PcodeOp *op_less,*op_equal;
  OpCode opc;
  
  vnout1 = op->getIn(0);
  if (!vnout1->isWritten()) return 0;
  vnout2 = op->getIn(1);
  if (!vnout2->isWritten()) return 0;
  op_less = vnout1->getDef();
  opc = op_less->code();
  if ((opc != CPUI_INT_LESSEQUAL)&&(opc!=CPUI_INT_SLESSEQUAL)) {
    op_equal = op_less;
    op_less = vnout2->getDef();
    opc = op_less->code();
    if ((opc != CPUI_INT_LESSEQUAL)&&(opc!=CPUI_INT_SLESSEQUAL))
      return 0;
  }
  else
    op_equal = vnout2->getDef();
  if (op_equal->code() != CPUI_INT_NOTEQUAL) return 0;
  
  compvn1 = op_less->getIn(0);
  compvn2 = op_less->getIn(1);
  if (!compvn1->isHeritageKnown()) return 0;
  if (!compvn2->isHeritageKnown()) return 0;
  if (((*compvn1 != *op_equal->getIn(0))||(*compvn2 != *op_equal->getIn(1)))&&
      ((*compvn1 != *op_equal->getIn(1))||(*compvn2 != *op_equal->getIn(0))))
    return 0;

  data.opSetInput(op,compvn1,0);
  data.opSetInput(op,compvn2,1);
  data.opSetOpcode(op, (opc==CPUI_INT_SLESSEQUAL) ? CPUI_INT_SLESS : CPUI_INT_LESS);

  return 1;
}

/// \class RuleTrivialArith
/// \brief Simplify trivial arithmetic expressions
///
/// All forms are binary operations where both inputs hold the same value.
///   - `V == V  =>  true`
///   - `V != V  =>  false`
///   - `V < V   => false`
///   - `V <= V  => true`
///   - `V & V   => V`
///   - `V | V  => V`
///   - `V ^ V   => #0`
///
/// Handles other signed, boolean, and floating-point variants.
void RuleTrivialArith::getOpList(vector<uint4> &oplist) const

{
  uint4 list[]={ CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_LESS, CPUI_BOOL_XOR, CPUI_BOOL_AND, CPUI_BOOL_OR,
		 CPUI_INT_EQUAL, CPUI_INT_SLESSEQUAL, CPUI_INT_LESSEQUAL,
		 CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR,
                 CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL };
  oplist.insert(oplist.end(),list,list+16);
}
  
int4 RuleTrivialArith::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn;
  Varnode *in0,*in1;

  if (op->numInput() != 2) return 0;
  in0 = op->getIn(0);
  in1 = op->getIn(1);
  if (in0 != in1) {		// Inputs must be identical
    if (!in0->isWritten()) return 0;
    if (!in1->isWritten()) return 0;
    if (!in0->getDef()->isCseMatch(in1->getDef())) return 0; // or constructed identically
  }
  switch(op->code()) {

  case CPUI_INT_NOTEQUAL:	// Boolean 0
  case CPUI_INT_SLESS:
  case CPUI_INT_LESS:
  case CPUI_BOOL_XOR:
  case CPUI_FLOAT_NOTEQUAL:
  case CPUI_FLOAT_LESS:
    vn = data.newConstant(1,0);
    break;
  case CPUI_INT_EQUAL:		// Boolean 1
  case CPUI_INT_SLESSEQUAL:
  case CPUI_INT_LESSEQUAL:
  case CPUI_FLOAT_EQUAL:
  case CPUI_FLOAT_LESSEQUAL:
    vn = data.newConstant(1,1);
    break;
  case CPUI_INT_XOR:		// Same size 0
    //  case CPUI_INT_SUB:
    vn = data.newConstant(op->getOut()->getSize(),0);
    break;
  case CPUI_BOOL_AND:		// Identity
  case CPUI_BOOL_OR:
  case CPUI_INT_AND:
  case CPUI_INT_OR:
    vn = (Varnode *)0;
    break;
  default:
    return 0;
  }
    
  data.opRemoveInput(op,1);
  data.opSetOpcode(op,CPUI_COPY);
  if (vn != (Varnode *)0)
    data.opSetInput(op,vn,0);

  return 1;
}

/// \class RuleTrivialBool
/// \brief Simplify boolean expressions when one side is constant
///
///   - `V && false  =>  false`
///   - `V && true   =>  V`
///   - `V || false  =>  V`
///   - `V || true   =>  true`
///   - `V ^^ true   =>  !V`
///   - `V ^^ false  =>  V`
void RuleTrivialBool::getOpList(vector<uint4> &oplist) const

{
  uint4 list[] = { CPUI_BOOL_AND, CPUI_BOOL_OR, CPUI_BOOL_XOR };
  oplist.insert(oplist.end(),list,list+3);
}

int4 RuleTrivialBool::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vnconst = op->getIn(1);
  Varnode *vn;
  uintb val;
  OpCode opc;

  if (!vnconst->isConstant()) return 0;
  val = vnconst->getOffset();

  switch(op->code()) {
  case CPUI_BOOL_XOR:
    vn = op->getIn(0);
    opc = (val==1) ? CPUI_BOOL_NEGATE : CPUI_COPY;
    break;
  case CPUI_BOOL_AND:
    opc = CPUI_COPY;
    if (val==1)
      vn = op->getIn(0);
    else
      vn = data.newConstant(1,0); // Copy false
    break;
  case CPUI_BOOL_OR:
    opc = CPUI_COPY;
    if (val==1)
      vn = data.newConstant(1,1);
    else
      vn = op->getIn(0);
    break;
  default:
    return 0;
  }

  data.opRemoveInput(op,1);
  data.opSetOpcode(op,opc);
  data.opSetInput(op,vn,0);
  return 1;
}

/// \class RuleZextEliminate
/// \brief Eliminate INT_ZEXT in comparisons:  `zext(V) == c  =>  V == c`
///
/// The constant Varnode changes size and must not lose any non-zero bits.
/// Handle other variants with INT_NOTEQUAL, INT_LESS, and INT_LESSEQUAL
///   - `zext(V) != c =>  V != c`
///   - `zext(V) < c  =>  V < c`
///   - `zext(V) <= c =>  V <= c`
void RuleZextEliminate::getOpList(vector<uint4> &oplist) const

{
  uint4 list[] = {CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL,
		  CPUI_INT_LESS,CPUI_INT_LESSEQUAL };
  oplist.insert(oplist.end(),list,list+4);
}

int4 RuleZextEliminate::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *zext;
  Varnode *vn1,*vn2,*newvn;
  uintb val;
  int4 smallsize,zextslot,otherslot;

				// vn1 equals ZEXTed input
				// vn2 = other input
  vn1 = op->getIn(0);
  vn2 = op->getIn(1);
  zextslot = 0;
  otherslot = 1;
  if ((vn2->isWritten())&&(vn2->getDef()->code()==CPUI_INT_ZEXT)) {
    vn1 = vn2;
    vn2 = op->getIn(0);
    zextslot = 1;
    otherslot = 0;
  }
  else if ((!vn1->isWritten())||(vn1->getDef()->code()!=CPUI_INT_ZEXT))
    return 0;
  
  if (!vn2->isConstant()) return 0;
  zext = vn1->getDef();
  if (!zext->getIn(0)->isHeritageKnown()) return 0;
  if (vn1->loneDescend() != op) return 0;	// Make sure extension is not used for anything else
  smallsize = zext->getIn(0)->getSize();
  val = vn2->getOffset();
  if ((val>>(8*smallsize))==0) { // Is zero extension unnecessary
    newvn = data.newConstant(smallsize,val);
    newvn->copySymbolIfValid(vn2);
    data.opSetInput(op,zext->getIn(0),zextslot);
    data.opSetInput(op,newvn,otherslot);
    return 1;
  }
				// Should have else for doing 
				// constant comparison here and now
  return 0;
}

/// \class RuleSlessToLess
/// \brief Convert INT_SLESS to INT_LESS when comparing positive values
///
/// This also works converting INT_SLESSEQUAL to INT_LESSEQUAL.
/// We use the non-zero mask to verify the sign bit is zero.
void RuleSlessToLess::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SLESS);
  oplist.push_back(CPUI_INT_SLESSEQUAL);
}

int4 RuleSlessToLess::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getIn(0);
  int4 sz = vn->getSize();
  if (signbit_negative(vn->getNZMask(),sz)) return 0;
  if (signbit_negative(op->getIn(1)->getNZMask(),sz)) return 0;
  
  if (op->code() == CPUI_INT_SLESS)
    data.opSetOpcode(op,CPUI_INT_LESS);
  else
    data.opSetOpcode(op,CPUI_INT_LESSEQUAL);
  return 1;
}

/// \class RuleZextSless
/// \brief Transform INT_ZEXT and INT_SLESS:  `zext(V) s< c  =>  V < c`
void RuleZextSless::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SLESS);
  oplist.push_back(CPUI_INT_SLESSEQUAL);
}

int4 RuleZextSless::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *zext;
  Varnode *vn1,*vn2;
  int4 smallsize,zextslot,otherslot;
  uintb val;

  vn1 = op->getIn(0);
  vn2 = op->getIn(1);
  zextslot = 0;
  otherslot = 1;
  if ((vn2->isWritten())&&(vn2->getDef()->code()==CPUI_INT_ZEXT)) {
    vn1 = vn2;
    vn2 = op->getIn(0);
    zextslot = 1;
    otherslot = 0;
  }
  else if ((!vn1->isWritten())||(vn1->getDef()->code()!=CPUI_INT_ZEXT))
    return 0;

  if (!vn2->isConstant()) return 0;
  zext = vn1->getDef();
  if (!zext->getIn(0)->isHeritageKnown()) return 0;

  smallsize = zext->getIn(0)->getSize();
  val = vn2->getOffset();
  if ((val>>(8*smallsize-1))!=0) return 0; // Is zero extension unnecessary, sign bit must also be 0

  Varnode *newvn = data.newConstant(smallsize,val);
  data.opSetInput(op,zext->getIn(0),zextslot);
  data.opSetInput(op,newvn,otherslot);;
  data.opSetOpcode(op,(op->code()==CPUI_INT_SLESS)? CPUI_INT_LESS : CPUI_INT_LESSEQUAL);
  return 1;
}

/// \class RuleBitUndistribute
/// \brief Undo distributed operations through INT_AND, INT_OR, and INT_XOR
///
///  - `zext(V) & zext(W)  =>  zext( V & W )`
///  - `(V >> X) | (W >> X)  =>  (V | W) >> X`
///
/// Works with INT_ZEXT, INT_SEXT, INT_LEFT, INT_RIGHT, and INT_SRIGHT.
void RuleBitUndistribute::getOpList(vector<uint4> &oplist) const

{
  uint4 list[]= { CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR };
  oplist.insert(oplist.end(),list,list+3);
}

int4 RuleBitUndistribute::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn1 = op->getIn(0);
  Varnode *vn2 = op->getIn(1);
  Varnode *in1,*in2,*vnextra;
  OpCode opc;

  if (!vn1->isWritten()) return 0;
  if (!vn2->isWritten()) return 0;

  opc = vn1->getDef()->code();
  if (vn2->getDef()->code() != opc) return 0;
  switch(opc) {
  case CPUI_INT_ZEXT:
  case CPUI_INT_SEXT:
    // Test for full equality of extension operation
    in1 = vn1->getDef()->getIn(0);
    if (in1->isFree()) return 0;
    in2 = vn2->getDef()->getIn(0);
    if (in2->isFree()) return 0;
    if (in1->getSize() != in2->getSize()) return 0;
    data.opRemoveInput(op,1);
    break;
  case CPUI_INT_LEFT:
  case CPUI_INT_RIGHT:
  case CPUI_INT_SRIGHT:
    // Test for full equality of shift operation
    in1 = vn1->getDef()->getIn(1);
    in2 = vn2->getDef()->getIn(1);
    if (in1->isConstant() && in2->isConstant()) {
      if (in1->getOffset() != in2->getOffset())
	return 0;
      vnextra = data.newConstant(in1->getSize(),in1->getOffset());
    }
    else if (in1 != in2)
      return 0;
    else {
      if (in1->isFree()) return 0;
      vnextra = in1;
    }
    in1 = vn1->getDef()->getIn(0);
    if (in1->isFree()) return 0;
    in2 = vn2->getDef()->getIn(0);
    if (in2->isFree()) return 0;
    data.opSetInput(op,vnextra,1);
    break;
  default:
    return 0;
  }

  PcodeOp *newext = data.newOp(2,op->getAddr());
  Varnode *smalllogic = data.newUniqueOut(in1->getSize(),newext);
  data.opSetInput(newext,in1,0);
  data.opSetInput(newext,in2,1);
  data.opSetOpcode(newext,op->code());
  
  data.opSetOpcode(op,opc);
  data.opSetInput(op,smalllogic,0);
  data.opInsertBefore(newext,op);
  return 1;
}

/// \class RuleBooleanNegate
/// \brief Simplify comparisons with boolean values:  `V == false  =>  !V,  V == true  =>  V`
///
/// Works with both INT_EQUAL and INT_NOTEQUAL.  Both sides of the comparison
/// must be boolean values.
void RuleBooleanNegate::getOpList(vector<uint4> &oplist) const

{
  uint4 list[]= { CPUI_INT_NOTEQUAL, CPUI_INT_EQUAL };
  oplist.insert(oplist.end(),list,list+2);
}

int4 RuleBooleanNegate::applyOp(PcodeOp *op,Funcdata &data)

{
  OpCode opc;
  Varnode *constvn;
  Varnode *subbool;
  bool negate;
  uintb val;

  opc = op->code();
  constvn = op->getIn(1);
  subbool = op->getIn(0);
  if (!constvn->isConstant()) return 0;
  val = constvn->getOffset();
  if ((val!=0)&&(val!=1))
    return 0;
  negate = (opc==CPUI_INT_NOTEQUAL);
  if (val==0)
    negate = !negate;

  if (!subbool->isBooleanValue(data.isTypeRecoveryOn())) return 0;

  data.opRemoveInput(op,1);	// Remove second parameter
  data.opSetInput(op,subbool,0); // Keep original boolean parameter
  if (negate)
    data.opSetOpcode(op,CPUI_BOOL_NEGATE);
  else
    data.opSetOpcode(op,CPUI_COPY);
  
  return 1;
}

/// \class RuleBoolZext
/// \brief Simplify boolean expressions of the form zext(V) * -1
///
///   - `(zext(V) * -1) + 1  =>  zext( !V )`
///   - `(zext(V) * -1) == -1  =>  V == true`
///   - `(zext(V) * -1) != -1  =>  V != true`
///   - `(zext(V) * -1) & (zext(W) * -1)  =>  zext(V && W) * -1`
///   - `(zext(V) * -1) | (zext(W) * -1)  =>  zext(V || W) * -1`
void RuleBoolZext::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ZEXT);
}

int4 RuleBoolZext::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *boolVn1,*boolVn2;
  PcodeOp *multop1,*actionop;
  PcodeOp *zextop2,*multop2;
  uintb coeff,val;
  OpCode opc;
  int4 size;

  boolVn1 = op->getIn(0);
  if (!boolVn1->isBooleanValue(data.isTypeRecoveryOn())) return 0;

  multop1 = op->getOut()->loneDescend();
  if (multop1 == (PcodeOp *)0) return 0;
  if (multop1->code() != CPUI_INT_MULT) return 0;
  if (!multop1->getIn(1)->isConstant()) return 0;
  coeff = multop1->getIn(1)->getOffset();
  if (coeff != calc_mask(multop1->getIn(1)->getSize()))
    return 0;
  size = multop1->getOut()->getSize();

  // If we reached here, we are Multiplying extended boolean by -1
  actionop = multop1->getOut()->loneDescend();
  if (actionop == (PcodeOp *)0) return 0;
  switch(actionop->code()) {
  case CPUI_INT_ADD:
    if (!actionop->getIn(1)->isConstant()) return 0;
    if (actionop->getIn(1)->getOffset() == 1) {
      Varnode *vn;
      PcodeOp *newop = data.newOp(1,op->getAddr());
      data.opSetOpcode(newop,CPUI_BOOL_NEGATE);	// Negate the boolean
      vn = data.newUniqueOut(1,newop);
      data.opSetInput(newop,boolVn1,0);
      data.opInsertBefore(newop,op);
      data.opSetInput(op,vn,0);
      data.opRemoveInput(actionop,1); // eliminate the INT_ADD operator
      data.opSetOpcode(actionop,CPUI_COPY);
      data.opSetInput(actionop,op->getOut(),0);	// propagate past the INT_MULT operator
      return 1;
    }
    return 0;
  case CPUI_INT_EQUAL:
  case CPUI_INT_NOTEQUAL:
    
    if (actionop->getIn(1)->isConstant()) {
      val = actionop->getIn(1)->getOffset();
    }
    else
      return 0;

    // Change comparison of extended boolean to 0 or -1
    // to comparison of unextended boolean to 0 or 1
    if (val==coeff)
      val = 1;
    else if (val != 0)
      return 0;			// Not comparing with 0 or -1

    data.opSetInput(actionop,boolVn1,0);
    data.opSetInput(actionop,data.newConstant(1,val),1);
    return 1;
  case CPUI_INT_AND:
    opc = CPUI_BOOL_AND;
    break;
  case CPUI_INT_OR:
    opc = CPUI_BOOL_OR;
    break;
  case CPUI_INT_XOR:
    opc = CPUI_BOOL_XOR;
    break;
  default:
    return 0;
  }

  // Apparently doing logical ops with extended boolean

  // Check that the other side is also an extended boolean
  multop2 = (multop1 == actionop->getIn(0)->getDef()) ? actionop->getIn(1)->getDef():actionop->getIn(0)->getDef();
  if (multop2==(PcodeOp *)0) return 0;
  if (multop2->code() != CPUI_INT_MULT) return 0;
  if (!multop2->getIn(1)->isConstant()) return 0;
  coeff = multop2->getIn(1)->getOffset();
  if (coeff != calc_mask(size))
    return 0;
  zextop2 = multop2->getIn(0)->getDef();
  if (zextop2 == (PcodeOp *)0) return 0;
  if (zextop2->code() != CPUI_INT_ZEXT) return 0;
  boolVn2 = zextop2->getIn(0);
  if (!boolVn2->isBooleanValue(data.isTypeRecoveryOn())) return 0;

  // Do the boolean calculation on unextended boolean values
  // and then extend the result
  PcodeOp *newop = data.newOp(2,actionop->getAddr());
  Varnode *newres = data.newUniqueOut(1,newop);
  data.opSetOpcode(newop,opc);
  data.opSetInput(newop, boolVn1, 0);
  data.opSetInput(newop, boolVn2, 1);
  data.opInsertBefore(newop,actionop);

  PcodeOp *newzext = data.newOp(1,actionop->getAddr());
  Varnode *newzout = data.newUniqueOut(size,newzext);
  data.opSetOpcode(newzext,CPUI_INT_ZEXT);
  data.opSetInput(newzext,newres,0);
  data.opInsertBefore(newzext,actionop);

  data.opSetOpcode(actionop,CPUI_INT_MULT);
  data.opSetInput(actionop,newzout,0);
  data.opSetInput(actionop,data.newConstant(size,coeff),1);
  return 1;
}

/// \class RuleLogic2Bool
/// \brief Convert logical to boolean operations:  `V & W  =>  V && W,  V | W  => V || W`
///
/// Verify that the inputs to the logical operator are booleans, then convert
/// INT_AND to BOOL_AND, INT_OR to BOOL_OR etc.
void RuleLogic2Bool::getOpList(vector<uint4> &oplist) const

{			      
  uint4 list[]= { CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR };
  oplist.insert(oplist.end(),list,list+3);
}

int4 RuleLogic2Bool::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *boolVn;

  boolVn = op->getIn(0);
  if (!boolVn->isBooleanValue(data.isTypeRecoveryOn())) return 0;
  Varnode *in1 = op->getIn(1);
  if (in1->isConstant()) {
    if (in1->getOffset()>(uintb)1) // If one side is a constant 0 or 1, this is boolean
      return 0;
  }
  else if (!in1->isBooleanValue(data.isTypeRecoveryOn())) {
    return 0;
  }
  switch(op->code()) {
  case CPUI_INT_AND:
    data.opSetOpcode(op,CPUI_BOOL_AND);
    break;
  case CPUI_INT_OR:
    data.opSetOpcode(op,CPUI_BOOL_OR);
    break;
  case CPUI_INT_XOR:
    data.opSetOpcode(op,CPUI_BOOL_XOR);
    break;
  default:
    return 0;
  }
  return 1;
}

bool RuleIndirectCollapse::hasJumptable(Varnode *vn)

{
  list<PcodeOp *>::const_iterator iter;
  for (iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    OpCode opc = op->code();
    switch (opc) {
      case CPUI_BRANCHIND:
	return true;
      // Trace further
      case CPUI_COPY:
      case CPUI_LOAD:
      case CPUI_INT_ZEXT:
      case CPUI_INT_SEXT:
      case CPUI_INT_ADD:
      case CPUI_INT_MULT:
      case CPUI_SUBPIECE:
	if (hasJumptable(op->getOut()))
	  return true;
	continue;
      case CPUI_INT_LESS:
      case CPUI_INT_LESSEQUAL:
      case CPUI_INDIRECT:
      default:
	continue;
    }
  }
  return false;
}

Varnode *RuleIndirectCollapse::getInitVarnode(Varnode *vn)

{
  if (visitedVn.find(vn) != visitedVn.end()) return (Varnode *)0;
  visitedVn.insert(vn);
  if (vn->isConstant()) return vn;
  PcodeOp *op = vn->getDef();
  if (op == (PcodeOp *)0) return (Varnode *)0;
  OpCode opc = op->code();
  Varnode *initvn = (Varnode *)0;
  int4 num = op->numInput();
  switch (opc) {
    case CPUI_COPY:
      initvn = getInitVarnode(op->getIn(0));
      if (initvn != (Varnode *)0)
	return initvn;
    case CPUI_MULTIEQUAL:
      for (int4 i=0;i<num;++i) {
	initvn = getInitVarnode(op->getIn(i));
	if (initvn != (Varnode *)0)
	  return initvn;
      }
    case CPUI_INDIRECT:
    default:
      return (Varnode *)0;
  }
  return (Varnode *)0;
}

bool RuleIndirectCollapse::protectJumptable(PcodeOp *op)

{
  Varnode *out = op->getOut();
  if (!out->getSpace()->isFormalStackSpace()) return false;
  if (!hasJumptable(out)) return false;
  Varnode *initvn = getInitVarnode(op->getIn(0));
  if (initvn == (Varnode *)0) return false;
  uintb off = initvn->getOffset();
  // Should not contain a valid pointer
  if (off != 0) return false;
  return true;
}

/// \class RuleIndirectCollapse
/// \brief Remove a CPUI_INDIRECT if its blocking PcodeOp is dead
void RuleIndirectCollapse::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INDIRECT);
}

int4 RuleIndirectCollapse::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *indop;

  visitedVn.clear();
  if (op->getIn(1)->getSpace()->getType()!=IPTR_IOP) return 0;
  indop = PcodeOp::getOpFromConst(op->getIn(1)->getAddr());

				// Is the indirect effect gone?
  if (!indop->isDead()) {
    if (indop->code() == CPUI_COPY) { // STORE resolved to a COPY
      Varnode *vn1 = indop->getOut();
      Varnode *vn2 = op->getOut();
      int4 res = vn1->characterizeOverlap(*vn2);
      if (res > 0) { // Copy has an effect of some sort
	if (res == 2) { // vn1 and vn2 are the same storage
	  // Convert INDIRECT to COPY
	  data.opUninsert(op);
	  data.opSetInput(op,vn1,0);
	  data.opRemoveInput(op,1);
	  data.opSetOpcode(op,CPUI_COPY);
	  data.opInsertAfter(op, indop);
	  return 1;
	}
	if (vn1->contains(*vn2) == 0) {	// INDIRECT output is properly contained in COPY output
	  // Convert INDIRECT to a SUBPIECE
	  uintb trunc;
	  if (vn1->getSpace()->isBigEndian())
	    trunc = vn1->getOffset() + vn1->getSize() - (vn2->getOffset() + vn2->getSize());
	  else
	    trunc = vn2->getOffset() - vn1->getOffset();
	  data.opUninsert(op);
	  data.opSetInput(op,vn1,0);
	  data.opSetInput(op,data.newConstant(4,trunc),1);
	  data.opSetOpcode(op, CPUI_SUBPIECE);
	  data.opInsertAfter(op, indop);
	  return 1;
	}
	data.warning("Ignoring partial resolution of indirect",indop->getAddr());
	return 0;		// Partial overlap, not sure what to do
      }
    }
    else if (op->getOut()->hasNoLocalAlias()) {
      if (op->isIndirectCreation() || op->noIndirectCollapse())
	return 0;
      // Sometimes we need to protect switch variable which is on the stack
      if (protectJumptable(op))
	return 0;
    }
    else if (indop->usesSpacebasePtr()) {
      if (indop->code() == CPUI_STORE) {
	const LoadGuard *guard = data.getStoreGuard(indop);
	if (guard != (const LoadGuard *)0) {
	  if (guard->isGuarded(op->getOut()->getAddr()))
	    return 0;
	}
	else {
	  // A marked STORE that is not guarded should eventually get converted to a COPY
	  // so we keep the INDIRECT until that happens
	  return 0;
	}
      }
    }
    else
      return 0;	
  }

  data.totalReplace(op->getOut(),op->getIn(0));
  data.opDestroy(op);		// Get rid of the INDIRECT
  return 1;
}

/// \class RuleMultiCollapse
/// \brief Collapse MULTIEQUAL whose inputs all trace to the same value
void RuleMultiCollapse::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_MULTIEQUAL);
}

int4 RuleMultiCollapse::applyOp(PcodeOp *op,Funcdata &data)

{
  vector<Varnode *> skiplist,matchlist;
  Varnode *defcopyr,*copyr;
  bool func_eq,nofunc;
  PcodeOp *newop;
  int4 j;

  for(int4 i=0;i<op->numInput();++i)	// Everything must be heritaged before collapse
    if (!op->getIn(i)->isHeritageKnown()) return 0;

  func_eq = false;		// Start assuming absolute equality of branches
  nofunc = false;		// Functional equalities are initially allowed
  defcopyr = (Varnode *)0;
  j = 0;
  for(int4 i=0;i<op->numInput();++i)
    matchlist.push_back(op->getIn(i));
  for(int4 i=0;i<op->numInput();++i) { // Find base branch to match
    copyr = matchlist[i];
    if ((!copyr->isWritten())||(copyr->getDef()->code()!=CPUI_MULTIEQUAL)) {
      defcopyr = copyr;
      break;
    }
  }

  bool success = true;
  op->getOut()->setMark();
  skiplist.push_back(op->getOut());
  while( j < matchlist.size() ) {
    copyr = matchlist[j++];
    if (copyr->isMark()) continue; // A varnode we have seen before
				// indicates a loop construct, where the
				// value is recurring in the loop without change
				// so we treat this as equal to all other branches
				// I.e. skip this varnode
    if (defcopyr == (Varnode *)0) { // This is now the defining branch
      defcopyr = copyr;		// all other branches must match
      if (defcopyr->isWritten()) {
	if (defcopyr->getDef()->code()==CPUI_MULTIEQUAL)
	  nofunc = true;	// MULTIEQUAL cannot match by functional equal
      }
      else
	nofunc = true;		// Unwritten cannot match by functional equal
    }
    else if (defcopyr == copyr) continue; // A matching branch
    else if ((defcopyr!=copyr)&&(!nofunc)&&functionalEquality(defcopyr,copyr)) {
				// Cannot match MULTIEQUAL by functional equality
      //      if (nofunc) return 0;	// Not allowed to match by func equal
      func_eq = true;		// Now matching by functional equality
      continue;
    }
    else if ((copyr->isWritten())&&(copyr->getDef()->code()==CPUI_MULTIEQUAL)) {
				// If the non-matching branch is a MULTIEQUAL
      newop = copyr->getDef();
      skiplist.push_back(copyr); // We give the branch one last chance and
      copyr->setMark();
      for(int4 i=0;i<newop->numInput();++i) // add its inputs to list of things to match
	matchlist.push_back(newop->getIn(i));
    }
    else {			// A non-matching branch
      success = false;
      break;
    }
  }
  if (success) {
    for(j=0;j<skiplist.size();++j) { // Collapse everything in the skiplist
      copyr = skiplist[j];
      copyr->clearMark();
      op = copyr->getDef();
      if (func_eq) {		// We have only functional equality
	PcodeOp *earliest = op->getParent()->earliestUse(op->getOut());
	newop = defcopyr->getDef();	// We must copy newop (defcopyr)
	PcodeOp *substitute = (PcodeOp *)0;
	for(int4 i=0;i<newop->numInput();++i) {
	  Varnode *invn = newop->getIn(i);
	  if (!invn->isConstant()) {
	    substitute = Funcdata::cseFindInBlock(newop,invn,op->getParent(),earliest); // Has newop already been copied in this block
	    break;
	  }
	}
	if (substitute != (PcodeOp *)0) { // If it has already been copied,
	  data.totalReplace(copyr,substitute->getOut()); // just use copy's output as substitute for op
	  data.opDestroy(op);
	}
	else {			// Otherwise, create a copy
	  bool needsreinsert = (op->code() == CPUI_MULTIEQUAL);
	  vector<Varnode *> parms;
	  for(int4 i=0;i<newop->numInput();++i)
	    parms.push_back(newop->getIn(i)); // Copy parameters
	  data.opSetAllInput(op,parms);
	  data.opSetOpcode(op,newop->code()); // Copy opcode
	  if (needsreinsert) {	// If the op is no longer a MULTIEQUAL
	    BlockBasic *bl = op->getParent();
	    data.opUninsert(op);
	    data.opInsertBegin(op,bl); // Insert AFTER any other MULTIEQUAL
	  }
	}
      }
      else {			// We have absolute equality
	data.totalReplace(copyr,defcopyr); // Replace all refs to copyr with defcopyr
	data.opDestroy(op);	// Get rid of the MULTIEQUAL
      }
    }
    return 1;
  }
  for(j=0;j<skiplist.size();++j)
    skiplist[j]->clearMark();
  return 0;
}

/// \class RuleSborrow
/// \brief Simplify signed comparisons using INT_SBORROW
///
/// - `sborrow(V,0)  =>  false`
/// - `sborrow(V,W) != (V + (W * -1) s< 0)  =>  V s< W`
/// - `sborrow(V,W) != (0 s< V + (W * -1))  =>  W s< V`
/// - `sborrow(V,W) == (0 s< V + (W * -1))  =>  V s<= W`
/// - `sborrow(V,W) == (V + (W * -1) s< 0)  =>  W s<= V`
///
/// Supports variations where W is constant.
void RuleSborrow::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SBORROW);
}

int4 RuleSborrow::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *svn = op->getOut();
  Varnode *cvn,*avn,*bvn;
  list<PcodeOp *>::const_iterator iter;
  PcodeOp *compop,*signop,*addop;
  int4 zside;

				// Check for trivial case
  if ((op->getIn(1)->isConstant()&&op->getIn(1)->getOffset()==0)||
      (op->getIn(0)->isConstant()&&op->getIn(0)->getOffset()==0)) {
    data.opSetOpcode(op,CPUI_COPY);
    data.opSetInput(op,data.newConstant(1,0),0);
    data.opRemoveInput(op,1);
    return 1;
  }
  for(iter=svn->beginDescend();iter!=svn->endDescend();++iter) {
    compop = *iter;
    if ((compop->code()!=CPUI_INT_EQUAL)&&(compop->code()!=CPUI_INT_NOTEQUAL))
      continue;
    cvn = (compop->getIn(0)==svn) ? compop->getIn(1) : compop->getIn(0);
    if (!cvn->isWritten()) continue;
    signop = cvn->getDef();
    if (signop->code() != CPUI_INT_SLESS) continue;
    if (!signop->getIn(0)->constantMatch(0)) {
      if (!signop->getIn(1)->constantMatch(0)) continue;
      zside = 1;
    }
    else
      zside = 0;
    if (!signop->getIn(1-zside)->isWritten()) continue;
    addop = signop->getIn(1-zside)->getDef();
    if (addop->code() == CPUI_INT_ADD) {
      avn = op->getIn(0);
      if (functionalEquality(avn,addop->getIn(0)))
	bvn = addop->getIn(1);
      else if (functionalEquality(avn,addop->getIn(1)))
	bvn = addop->getIn(0);
      else
	continue;
    }
    else
      continue;
    if (bvn->isConstant()) {
      Address flip(bvn->getSpace(),uintb_negate(bvn->getOffset()-1,bvn->getSize()));
      bvn = op->getIn(1);
      if (flip != bvn->getAddr()) continue;
    }
    else if (bvn->isWritten()) {
      PcodeOp *otherop = bvn->getDef();
      if (otherop->code() == CPUI_INT_MULT) {
	if (!otherop->getIn(1)->isConstant()) continue;
	if (otherop->getIn(1)->getOffset() != calc_mask(otherop->getIn(1)->getSize())) continue;
	bvn = otherop->getIn(0);
      }
      else if (otherop->code()==CPUI_INT_2COMP)
	bvn = otherop->getIn(0);
      if (!functionalEquality(bvn,op->getIn(1))) continue;
    }
    else
      continue;
    if (compop->code() == CPUI_INT_NOTEQUAL) {
      data.opSetOpcode(compop,CPUI_INT_SLESS);	// Replace all this with simple less than
      data.opSetInput(compop,avn,1-zside);
      data.opSetInput(compop,bvn,zside);
    }
    else {
      data.opSetOpcode(compop,CPUI_INT_SLESSEQUAL);
      data.opSetInput(compop,avn,zside);
      data.opSetInput(compop,bvn,1-zside);
    }
    return 1;
  }
  return 0;
}

/// \class RuleTrivialShift
/// \brief Simplify trivial shifts:  `V << 0  =>  V,  V << #64  =>  0`
void RuleTrivialShift::getOpList(vector<uint4> &oplist) const

{
  uint4 list[] = { CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT };
  oplist.insert(oplist.end(),list,list+3);
}

int4 RuleTrivialShift::applyOp(PcodeOp *op,Funcdata &data)

{
  uintb val;
  Varnode *constvn = op->getIn(1);
  if (!constvn->isConstant()) return 0;	// Must shift by a constant
  val = constvn->getOffset();
  if (val!=0) {
    Varnode *replace;
    if (val < 8*op->getIn(0)->getSize()) return 0;	// Non-trivial
    if (op->code() == CPUI_INT_SRIGHT) return 0; // Cant predict signbit
    replace = data.newConstant(op->getIn(0)->getSize(),0);
    data.opSetInput(op,replace,0);
  }
  data.opRemoveInput(op,1);
  data.opSetOpcode(op,CPUI_COPY);
  return 1;
}

/// \class RuleSignShift
/// \brief Normalize sign-bit extraction:  `V >> 0x1f   =>  (V s>> 0x1f) * -1`
///
/// A logical shift of the sign-bit gets converted to an arithmetic shift if it is involved
/// in an arithmetic expression or a comparison.
void RuleSignShift::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_RIGHT);
}

int4 RuleSignShift::applyOp(PcodeOp *op,Funcdata &data)

{
  uintb val;
  Varnode *constVn = op->getIn(1);
  if (!constVn->isConstant()) return 0;
  val = constVn->getOffset();
  Varnode *inVn = op->getIn(0);
  if (val != 8*inVn->getSize() -1) return 0;
  if (inVn->isFree()) return 0;

  bool doConversion = false;
  Varnode *outVn = op->getOut();
  list<PcodeOp *>::const_iterator iter = outVn->beginDescend();
  while(iter != outVn->endDescend()) {
    PcodeOp *arithOp = *iter;
    ++iter;
    switch(arithOp->code()) {
      case CPUI_INT_EQUAL:
      case CPUI_INT_NOTEQUAL:
	if (arithOp->getIn(1)->isConstant())
	  doConversion = true;
	break;
      case CPUI_INT_ADD:
      case CPUI_INT_MULT:
        doConversion = true;
        break;
      default:
        break;
    }
    if (doConversion)
      break;
  }
  if (!doConversion)
    return 0;
  PcodeOp *shiftOp = data.newOp(2,op->getAddr());
  data.opSetOpcode(shiftOp, CPUI_INT_SRIGHT);
  Varnode *uniqueVn = data.newUniqueOut(inVn->getSize(), shiftOp);
  data.opSetInput(op,uniqueVn,0);
  data.opSetInput(op,data.newConstant(inVn->getSize(),calc_mask(inVn->getSize())),1);
  data.opSetOpcode(op, CPUI_INT_MULT);
  data.opSetInput(shiftOp,inVn,0);
  data.opSetInput(shiftOp,constVn,1);
  data.opInsertBefore(shiftOp, op);
  return 1;
}

/// \class RuleTestSign
/// \brief Convert sign-bit test to signed comparison:  `(V s>> 0x1f) != 0   =>  V s< 0`
void RuleTestSign::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SRIGHT);
}

/// \brief Find INT_EQUAL or INT_NOTEQUAL taking the sign bit as input
///
/// Trace the given sign-bit varnode to any comparison operations and pass them
/// back in the given array.
/// \param vn is the given sign-bit varnode
/// \param res is the array for holding the comparison op results
void RuleTestSign::findComparisons(Varnode *vn,vector<PcodeOp *> &res)

{
  list<PcodeOp *>::const_iterator iter1;
  iter1 = vn->beginDescend();
  while(iter1 != vn->endDescend()) {
    PcodeOp *op = *iter1;
    ++iter1;
    OpCode opc = op->code();
    if (opc == CPUI_INT_EQUAL || opc == CPUI_INT_NOTEQUAL) {
      if (op->getIn(1)->isConstant())
	res.push_back(op);
    }
  }
}

int4 RuleTestSign::applyOp(PcodeOp *op,Funcdata &data)

{
  uintb val;
  Varnode *constVn = op->getIn(1);
  if (!constVn->isConstant()) return 0;
  val = constVn->getOffset();
  Varnode *inVn = op->getIn(0);
  if (val != 8*inVn->getSize() -1) return 0;
  Varnode *outVn = op->getOut();

  if (inVn->isFree()) return 0;
  vector<PcodeOp *> compareOps;
  findComparisons(outVn, compareOps);
  int4 resultCode = 0;
  for(int4 i=0;i<compareOps.size();++i) {
    PcodeOp *compareOp = compareOps[i];
    Varnode *compVn = compareOp->getIn(0);
    int4 compSize = compVn->getSize();

    uintb offset = compareOp->getIn(1)->getOffset();
    int4 sgn;
    if (offset == 0)
      sgn = 1;
    else if (offset == calc_mask(compSize))
      sgn = -1;
    else
      continue;
    if (compareOp->code() == CPUI_INT_NOTEQUAL)
      sgn = -sgn;	// Complement the domain

    Varnode *zeroVn = data.newConstant(inVn->getSize(), 0);
    if (sgn == 1) {
      data.opSetInput(compareOp, inVn, 1);
      data.opSetInput(compareOp, zeroVn, 0);
      data.opSetOpcode(compareOp, CPUI_INT_SLESSEQUAL);
    }
    else {
      data.opSetInput(compareOp, inVn, 0);
      data.opSetInput(compareOp, zeroVn, 1);
      data.opSetOpcode(compareOp, CPUI_INT_SLESS);
    }
    resultCode = 1;
  }
  return resultCode;
}

/// \class RuleIdentityEl
/// \brief Collapse operations using identity element:  `V + 0  =>  V`
///
/// Similarly:
///   - `V ^ 0  =>  V`
///   - `V | 0  =>  V`
///   - `V || 0 =>  V`
///   - `V ^^ 0 =>  V`
///   - `V * 1  =>  V`
void RuleIdentityEl::getOpList(vector<uint4> &oplist) const

{
  uint4 list[]= { CPUI_INT_ADD, CPUI_INT_XOR, CPUI_INT_OR,
		  CPUI_BOOL_XOR, CPUI_BOOL_OR, CPUI_INT_MULT };
  oplist.insert(oplist.end(),list,list+6);
}

int4 RuleIdentityEl::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *constvn;
  uintb val;

  constvn = op->getIn(1);
  if (!constvn->isConstant()) return 0;
  val = constvn->getOffset();
  if ((val == 0)&&(op->code() != CPUI_INT_MULT)) {
    data.opSetOpcode(op,CPUI_COPY);
    data.opRemoveInput(op,1); // Remove identity from operation
    return 1;
  }
  if (op->code() != CPUI_INT_MULT) return 0;
  if (val == 1) {
    data.opSetOpcode(op,CPUI_COPY);
    data.opRemoveInput(op,1);
    return 1;
  }
  if (val == 0) {		// Multiply by zero
    data.opSetOpcode(op,CPUI_COPY);
    data.opRemoveInput(op,0);
	return 1;
  }
  return 0;
}

/// \class RuleShift2Mult
/// \brief Convert INT_LEFT to INT_MULT:  `V << 2  =>  V * 4`
///
/// This only applies if the result is involved in an arithmetic expression.
void RuleShift2Mult::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_LEFT);
}

int4 RuleShift2Mult::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 flag;
  list<PcodeOp *>::const_iterator desc;
  Varnode *vn,*constvn;
  PcodeOp *arithop;
  OpCode opc;
  int4 val;

  flag = 0;
  vn = op->getOut();
  constvn = op->getIn(1);
  if (!constvn->isConstant()) return 0; // Shift amount must be a constant
  val = constvn->getOffset();
  if (val >= 32)		// FIXME: This is a little arbitrary. Anything
				// this big is probably not an arithmetic multiply
    return 0;
  arithop = op->getIn(0)->getDef();
  desc = vn->beginDescend();
  for(;;) {
    if (arithop != (PcodeOp *)0) {
      opc = arithop->code();
      if ((opc==CPUI_INT_ADD)||(opc==CPUI_INT_SUB)||(opc==CPUI_INT_MULT)) {
	flag = 1;
	break;
      }
    }
    if (desc == vn->endDescend()) break;
    arithop = *desc++;
  }
      
  if (flag==0) return 0;
  constvn = data.newConstant(vn->getSize(),((uintb)1)<<val);
  data.opSetInput(op,constvn,1);
  data.opSetOpcode(op,CPUI_INT_MULT);
  return 1;
}

/// \class RuleShiftPiece
/// \brief Convert "shift and add" to PIECE:  (zext(V) << 16) + zext(W)  =>  concat(V,W)
///
/// The \e add operation can be INT_ADD, INT_OR, or INT_XOR. If the extension size is bigger
/// than the concatenation size, the concatenation can be zero extended.
/// This also supports other special forms where a value gets
/// concatenated with its own sign extension bits.
///
///  - `(zext(V s>> 0x1f) << 0x20) + zext(V)  =>  sext(V)`
///  - `(zext(W s>> 0x1f) << 0x20) + X        =>  sext(W) where W = sub(X,0)`
void RuleShiftPiece::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_OR);
  oplist.push_back(CPUI_INT_XOR);
  oplist.push_back(CPUI_INT_ADD);
}

int4 RuleShiftPiece::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *shiftop,*zextloop,*zexthiop;
  Varnode *vn1,*vn2;
  
  vn1 = op->getIn(0);
  if (!vn1->isWritten()) return 0;
  vn2 = op->getIn(1);
  if (!vn2->isWritten()) return 0;
  shiftop = vn1->getDef();
  zextloop = vn2->getDef();
  if (shiftop->code() != CPUI_INT_LEFT) {
    if (zextloop->code() != CPUI_INT_LEFT) return 0;
    PcodeOp *tmpop = zextloop;
    zextloop = shiftop;
    shiftop = tmpop;
  }
  if (!shiftop->getIn(1)->isConstant()) return 0;
  vn1 = shiftop->getIn(0);
  if (!vn1->isWritten()) return 0;
  zexthiop = vn1->getDef();
  if ((zexthiop->code() != CPUI_INT_ZEXT)&&
      (zexthiop->code()!= CPUI_INT_SEXT))
    return 0;
  vn1 = zexthiop->getIn(0);
  if (vn1->isConstant()) {
    if (vn1->getSize() < sizeof(uintb))
      return 0;		// Normally we let ZEXT of a constant collapse naturally
    // But if the ZEXTed constant is too big, this won't happen
  }
  else if (vn1->isFree())
    return 0;
  int4 sa = shiftop->getIn(1)->getOffset();
  int4 concatsize = sa + 8*vn1->getSize();
  if (op->getOut()->getSize() * 8 < concatsize) return 0;
  if (zextloop->code() != CPUI_INT_ZEXT) {
    // This is a special case triggered by CDQ: IDIV
    // This would be handled by the base case, but it interacts with RuleSubZext sometimes
    if (!vn1->isWritten()) return 0;
    PcodeOp *rShiftOp = vn1->getDef();			// Look for s<< #c forming the high piece
    if (rShiftOp->code() != CPUI_INT_SRIGHT) return 0;
    if (!rShiftOp->getIn(1)->isConstant()) return 0;
    vn2 = rShiftOp->getIn(0);
    if (!vn2->isWritten()) return 0;
    PcodeOp *subop = vn2->getDef();
    if (subop->code() != CPUI_SUBPIECE) return 0;	// SUBPIECE connects high and low parts
    if (subop->getIn(1)->getOffset() != 0) return 0;	//    (must be low part)
    Varnode *bigVn = zextloop->getOut();
    if (subop->getIn(0) != bigVn) return 0;	// Verify we have link thru SUBPIECE with low part
    int4 rsa = (int4)rShiftOp->getIn(1)->getOffset();
    if (rsa != vn2->getSize() * 8 -1) return 0;	// Arithmetic shift must copy sign-bit thru whole high part
    if ((bigVn->getNZMask() >> sa) != 0) return 0;	// The original most significant bytes must be zero
    if (sa != 8*(vn2->getSize())) return 0;
    data.opSetOpcode(op,CPUI_INT_SEXT);		// Original op is simply a sign extension of low part
    data.opSetInput(op,vn2,0);
    data.opRemoveInput(op,1);
    return 1;
  }
  vn2 = zextloop->getIn(0);
  if (vn2->isFree()) return 0;
  if (sa != 8*(vn2->getSize())) return 0;
  if (concatsize == op->getOut()->getSize() * 8) {
    data.opSetOpcode(op,CPUI_PIECE);
    data.opSetInput(op,vn1,0);
    data.opSetInput(op,vn2,1);
  }
  else {
    PcodeOp *newop = data.newOp(2,op->getAddr());
    data.newUniqueOut(concatsize/8,newop);
    data.opSetOpcode(newop,CPUI_PIECE);
    data.opSetInput(newop,vn1,0);
    data.opSetInput(newop,vn2,1);
    data.opInsertBefore(newop,op);
    data.opSetOpcode(op,zexthiop->code());
    data.opRemoveInput(op,1);
    data.opSetInput(op,newop->getOut(),0);
  }
  return 1;
}

/// \class RuleCollapseConstants
/// \brief Collapse constant expressions
int4 RuleCollapseConstants::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 i;
  Varnode *vn;

  if (!op->isCollapsible()) return 0; // Expression must be collapsible

  if (op->getOut()->numDescend() > 1) {
    data.splitUses(op->getOut());
    return 1;
  }

  Address newval;
  bool markedInput = false;
  try {
    newval = data.getArch()->getConstant(op->collapse(markedInput));
  }
  catch(LowlevelError &err) {
    data.opMarkNoCollapse(op); // Dont know how or dont want to collapse further
    return 0;
  }

  vn = data.newVarnode(op->getOut()->getSize(),newval); // Create new collapsed constant
  if (markedInput) {
    op->collapseConstantSymbol(vn);
  }
  for(i=op->numInput()-1;i>0;--i)
    data.opRemoveInput(op,i);	// unlink old constants
  data.opSetInput(op,vn,0);	// Link in new collapsed constant
  data.opSetOpcode(op,CPUI_COPY); // Change ourselves to a copy

  return 1;
}

/// \class RuleTransformCpool
/// \brief Transform CPOOLREF operations by looking up the value in the constant pool
///
/// If a reference into the constant pool is a constant, convert the CPOOLREF to
/// a COPY of the constant.  Otherwise just append the type id of the reference to the top.
void RuleTransformCpool::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_CPOOLREF);
}

int4 RuleTransformCpool::applyOp(PcodeOp *op,Funcdata &data)

{
  if (op->isCpoolTransformed()) return 0;		// Already visited
  data.opMarkCpoolTransformed(op);	// Mark our visit
  vector<uintb> refs;
  for(int4 i=1;i<op->numInput();++i)
    refs.push_back(op->getIn(i)->getOffset());
  const CPoolRecord *rec = data.getArch()->cpool->getRecord(refs);	// Recover the record
  if (rec != (const CPoolRecord *)0) {
    if (rec->getTag() == CPoolRecord::instance_of) {
      data.opMarkCalculatedBool(op);
    }
    else if (rec->getTag() == CPoolRecord::primitive) {
      int4 sz = op->getOut()->getSize();
      Varnode *cvn = data.newConstant(sz,rec->getValue() & calc_mask(sz));
      cvn->updateType(rec->getType(),true,true);
      while(op->numInput() > 1) {
	data.opRemoveInput(op,op->numInput()-1);
      }
      data.opSetOpcode(op,CPUI_COPY);
      data.opSetInput(op,cvn,0);
      return 1;
    }
    data.opInsertInput(op,data.newConstant(4,rec->getTag()),op->numInput());
  }
  return 1;
}

/// \class RulePropagateCopy
/// \brief Propagate the input of a COPY to all the places that read the output
int4 RulePropagateCopy::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 i;
  PcodeOp *copyop;
  Varnode *vn,*invn;

  if (op->isReturnCopy()) return 0;
  for(i=0;i<op->numInput();++i) {
    vn = op->getIn(i);
    if (!vn->isWritten()) continue; // Varnode must be written to

    copyop = vn->getDef();
    if (copyop->code()!=CPUI_COPY)
      continue;			// not a propagating instruction
    if (copyop->isStaticCastCopy(data)) continue;

    invn = copyop->getIn(0);
    if (!invn->isHeritageKnown()) continue; // Don't propagate free's away from their first use
    if (invn == vn)
      throw LowlevelError("Self-defined varnode");
    if (op->isMarker()) {
      if (invn->isConstant()) continue;		// Don't propagate constants into markers
      if (vn->isAddrForce()) continue;		// Don't propagate if we are keeping the COPY anyway
      if (invn->isAddrTied() && op->getOut()->isAddrTied() && 
	  (op->getOut()->getAddr() != invn->getAddr()))
	continue;		// We must not allow merging of different addrtieds
    }
    data.opSetInput(op,invn,i); // otherwise propagate just a single copy
    return 1;
  }
  return 0;
}

/// \class Rule2Comp2Mult
/// \brief Eliminate INT_2COMP:  `-V  =>  V * -1`
void Rule2Comp2Mult::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_2COMP);
}

int4 Rule2Comp2Mult::applyOp(PcodeOp *op,Funcdata &data)

{
  data.opSetOpcode(op,CPUI_INT_MULT);
  int4 size = op->getIn(0)->getSize();
  Varnode *negone = data.newConstant(size,calc_mask(size));
  data.opInsertInput(op,negone,1);
  return 1;
}

/// \class RuleCarryElim
/// \brief Transform INT_CARRY using a constant:  `carry(V,c)  =>  -c <= V`
///
/// There is a special case when the constant is zero:
///   - `carry(V,0)  => false`
void RuleCarryElim::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_CARRY);
}

int4 RuleCarryElim::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn1,*vn2;

  vn2 = op->getIn(1);
  if (!vn2->isConstant()) return 0;
  vn1 = op->getIn(0);
  if (vn1->isFree()) return 0;
  uintb off = vn2->getOffset();
  if (off == 0) {		// Trivial case
    data.opRemoveInput(op,1);	// Go down to 1 input
    data.opSetInput(op,data.newConstant(1,0),0);	// Put a boolean "false" as input to COPY
    data.opSetOpcode(op,CPUI_COPY);
    return 1;
  }
  off = (-off) & calc_mask(vn2->getSize()); // Take twos-complement of constant

  data.opSetOpcode(op,CPUI_INT_LESSEQUAL);
  data.opSetInput(op,vn1,1);	// Move other input to second position
  data.opSetInput(op,data.newConstant(vn1->getSize(),off),0); // Put the new constant in first position
  return 1;
}

/// \class RuleSub2Add
/// \brief Eliminate INT_SUB:  `V - W  =>  V + W * -1`
void RuleSub2Add::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SUB);
}

int4 RuleSub2Add::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *newop;
  Varnode *vn,*newvn;

  vn = op->getIn(1);		// Parameter being subtracted
  newop = data.newOp(2,op->getAddr());
  data.opSetOpcode(newop,CPUI_INT_MULT);
  newvn = data.newUniqueOut(vn->getSize(),newop);
  data.opSetInput( op, newvn, 1); // Replace vn's reference first
  data.opSetInput(newop, vn, 0);
  data.opSetInput(newop, data.newConstant(vn->getSize(),calc_mask(vn->getSize())),1);
  data.opSetOpcode(op, CPUI_INT_ADD );
  data.opInsertBefore( newop, op);
  return 1;
}

/// \class RuleXorCollapse
/// \brief Eliminate INT_XOR in comparisons: `(V ^ W) == 0  =>  V == W`
///
/// The comparison can be INT_EQUAL or INT_NOTEQUAL. This also supports the form:
///   - `(V ^ c) == d  => V == (c^d)`
void RuleXorCollapse::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_EQUAL);
  oplist.push_back(CPUI_INT_NOTEQUAL);
}

int4 RuleXorCollapse::applyOp(PcodeOp *op,Funcdata &data)

{
  uintb coeff1,coeff2;

  if (!op->getIn(1)->isConstant()) return 0;
  PcodeOp *xorop = op->getIn(0)->getDef();
  if (xorop == (PcodeOp *)0) return 0;
  if (xorop->code() != CPUI_INT_XOR) return 0;
  if (op->getIn(0)->loneDescend() == (PcodeOp *)0) return 0;
  coeff1 = op->getIn(1)->getOffset();
  Varnode *xorvn = xorop->getIn(1);
  if (xorop->getIn(0)->isFree()) return 0; // This will be propagated
  if (!xorvn->isConstant()) {
    if (coeff1 != 0) return 0;
    if (xorvn->isFree()) return 0;
    data.opSetInput(op,xorvn,1); // Move term to other side
    data.opSetInput(op,xorop->getIn(0),0);
    return 1;
  }
  coeff2 = xorvn->getOffset();
  if (coeff2 == 0) return 0;
  Varnode *constvn = data.newConstant(op->getIn(1)->getSize(),coeff1^coeff2);
  constvn->copySymbolIfValid(xorvn);
  data.opSetInput(op,constvn,1);
  data.opSetInput(op,xorop->getIn(0),0);
  return 1;
}

bool RuleAddMultCollapse::form1(PcodeOp *op,Funcdata &data)

{
  Varnode *c[2];           // Constant varnodes
  Varnode *sub1,*sub2,*newvn;
  PcodeOp *subop;

  if (op->code() != CPUI_INT_ADD) return false;
  // Constant is in c[0], other is in sub
  c[0] = op->getIn(1);
  if (!c[0]->isConstant()) return false; // Neither input is a constant
  sub1 = op->getIn(0);
  // Find other constant one level down
  if (!sub1->isWritten()) return false;
  subop = sub1->getDef();
  if (subop->code() != CPUI_INT_ADD) return false; // Must be same exact operation
  c[1] = subop->getIn(1);
  if (!c[1]->isConstant()) return false;
  sub2 = subop->getIn(0);
  if (sub2->isFree()) return false;

  intb val0 = sign_extend(c[0]->getOffset(),8*c[0]->getSize()-1);
  intb val1 = sign_extend(c[1]->getOffset(),8*c[1]->getSize()-1);
  intb val = val0 + val1;
  newvn = data.newConstant(c[0]->getSize(),val&calc_mask(c[0]->getSize()));
  if (c[0]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[0]);
  else if (c[1]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[1]);
  data.opSetInput(op,newvn,1); // Replace c[0] with c[0]+c[1]
  data.opSetInput(op,sub2,0); // Replace sub with sub2
  return true;
}

bool RuleAddMultCollapse::form2(PcodeOp *op,Funcdata &data)

{
  Varnode *c[2];           // Constant varnodes
  Varnode *sub,*newvn;
  PcodeOp *subop;

  if (op->code() != CPUI_INT_MULT) return false;
  // Constant is in c[0], other is in sub
  c[0] = op->getIn(1);
  if (!c[0]->isConstant()) return false; // Neither input is a constant
  // Find other constant one level down
  subop = op->getIn(0)->getDef();
  if (subop == (PcodeOp *)0) return false;
  if (subop->code() != CPUI_INT_MULT) return false; // Must be same exact operation
  c[1] = subop->getIn(1);
  if (!c[1]->isConstant()) return false;
  sub = subop->getIn(0);
  if (sub->isFree()) return false;

  intb val0 = sign_extend(c[0]->getOffset(),8*c[0]->getSize()-1);
  intb val1 = sign_extend(c[1]->getOffset(),8*c[1]->getSize()-1);
  intb val = val0 * val1;
  newvn = data.newConstant(c[0]->getSize(),val&calc_mask(c[0]->getSize()));
  if (c[0]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[0]);
  else if (c[1]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[1]);
  data.opSetInput(op,newvn,1); // Replace c[0] with c[0]*c[1]
  data.opSetInput(op,sub,0); // Replace sub with sub2
  return true;
}

bool RuleAddMultCollapse::form3(PcodeOp *op,Funcdata &data)

{
  Varnode *c[2];           // Constant varnodes
  Varnode *sub;
  Varnode *newvn;
  PcodeOp *subop;

  if (op->code() != CPUI_INT_ADD) return false;
  // Constant is in c[0], other is in sub
  c[0] = op->getIn(1);
  if (!c[0]->isConstant()) return false; // Neither input is a constant
  // Find other constant one level down
  subop = op->getIn(0)->getDef();
  if (subop == (PcodeOp *)0) return false;
  if (subop->code() != CPUI_INT_ADD) return false; // Must be same exact operation
  c[1] = subop->getIn(1);
  if (c[1]->isConstant()) return false;
  // a = ((stackbase + c[1]) + othervn) + c[0]  =>       (stackbase + c[0] + c[1]) + othervn
  // This lets two constant offsets get added together even in the case where there is:
  //    another term getting added in AND
  //    the result of the intermediate sum is used more than once  (otherwise collectterms should pick it up)
  Varnode *othervn,*basevn;
  PcodeOp *baseop;
  for(int4 i=0;i<2;++i) {
    othervn = subop->getIn(i);
    if (othervn->isConstant()) continue;
    if (othervn->isFree()) continue;
    sub = subop->getIn(1-i);
    if (!sub->isWritten()) continue;
    baseop = sub->getDef();
    if (baseop->code() != CPUI_INT_ADD) continue;
    c[1] = baseop->getIn(1);
    if (!c[1]->isConstant()) continue;
    basevn = baseop->getIn(0);
    if (!basevn->isSpacebase()) continue; // Only apply this particular case if we are adding to a base pointer
    if (!basevn->isInput()) continue;	// because this adds a new add operation

    intb val0 = sign_extend(c[0]->getOffset(),8*c[0]->getSize()-1);
    intb val1 = sign_extend(c[1]->getOffset(),8*c[1]->getSize()-1);
    intb val = val0 + val1;
    newvn = data.newConstant(c[0]->getSize(),val&calc_mask(c[0]->getSize()));
    if (c[0]->getSymbolEntry() != (SymbolEntry *)0)
      newvn->copySymbolIfValid(c[0]);
    else if (c[1]->getSymbolEntry() != (SymbolEntry *)0)
      newvn->copySymbolIfValid(c[1]);
    PcodeOp *newop = data.newOp(2,op->getAddr());
    data.opSetOpcode(newop,CPUI_INT_ADD);
    Varnode *newout = data.newUniqueOut(c[0]->getSize(),newop);
    data.opSetInput(newop,basevn,0);
    data.opSetInput(newop,newvn,1);
    data.opInsertBefore(newop,op);
    data.opSetInput(op,newout,0);
    data.opSetInput(op,othervn,1);
    return true;
  }
  return false;
}

/// \class RuleAddMultCollapse
/// \brief Collapse constants in an additive or multiplicative expression
///
/// Forms include:
///  - `(V + c) + d  =>  V + (c+d)`
///  - `(V * c) * d  =>  V * (c*d)`
///  - `(V + (W + c)) + d  =>  (W + (c+d)) + V`
void RuleAddMultCollapse::getOpList(vector<uint4> &oplist) const

{
  uint4 list[]= { CPUI_INT_ADD, CPUI_INT_MULT };
  oplist.insert(oplist.end(),list,list+2);
}

int4 RuleAddMultCollapse::applyOp(PcodeOp *op,Funcdata &data)

{
  if (form1(op,data)) return 1;
  if (form2(op,data)) return 1;
  if (form3(op,data)) return 1;
  return 0;
}

bool RuleSubtractionCollapse::form1(PcodeOp *op,Funcdata &data)

{
  Varnode *v[2];           // Variable varnodes
  Varnode *c[2];           // Constant varnodes
  intb val[2];             // Constant values
  intb value;              // Final constant value
  v[0] = (Varnode *)0;     // V
  v[1] = (Varnode *)0;     // W
  c[0] = (Varnode *)0;     // c
  c[1] = (Varnode *)0;     // d
  val[0] = 0;              // c
  val[1] = 0;              // d
  value = 0;               // c-d

  if (op->code() != CPUI_INT_ADD) return false;
  PcodeOp *addop1 = op->getIn(0)->getDef();
  c[0] = op->getIn(1);
  if (addop1 == (PcodeOp *)0) return false;
  if (addop1->code() != CPUI_INT_ADD) return false;
  v[0] = addop1->getIn(0);

  PcodeOp *multop = addop1->getIn(1)->getDef();
  if (multop == (PcodeOp *)0) return false;
  if (multop->code() != CPUI_INT_MULT) return false;
  Varnode *cvn = multop->getIn(1);
  if (!cvn->isConstant()) return false;
  if (cvn->getOffset() != calc_mask(cvn->getSize())) return false;

  PcodeOp *addop2 = multop->getIn(0)->getDef();
  if (addop2 == (PcodeOp *)0) return false;
  if (addop2->code() != CPUI_INT_ADD) return false;
  v[1] = addop2->getIn(0);
  c[1] = addop2->getIn(1);

  if (v[0]->isFree()) return false;
  if (v[1]->isFree()) return false;
  if (!c[0]->isConstant()) return false;
  if (!c[1]->isConstant()) return false;

  val[0] = sign_extend(c[0]->getOffset(),8*c[0]->getSize()-1);
  val[1] = sign_extend(c[1]->getOffset(),8*c[1]->getSize()-1);
  value = val[0] - val[1];

  Varnode *newvn = data.newConstant(c[0]->getSize(),value&cvn->getOffset());
  if (c[0]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[0]);
  else if (c[1]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[1]);

  PcodeOp *newmultop = data.newOpBefore(op, CPUI_INT_MULT,v[1],cvn);
  PcodeOp *newaddop = data.newOpBefore(op,CPUI_INT_ADD,v[0],newmultop->getOut());
  data.opSetInput(op,newaddop->getOut(),0);
  data.opSetInput(op,newvn,1);
  return true;
}

bool RuleSubtractionCollapse::form2(PcodeOp *op,Funcdata &data)

{
  Varnode *v;              // Variable varnode
  Varnode *c[2];           // Constant varnodes
  intb val[2];             // Constant values
  intb value;              // Final constant value
  v = (Varnode *)0;        // V
  c[0] = (Varnode *)0;     // c
  c[1] = (Varnode *)0;     // d
  val[0] = 0;              // c
  val[1] = 0;              // d
  value = 0;               // c-d

  if (op->code() != CPUI_INT_ADD) return false;
  c[0] = op->getIn(1);
  PcodeOp *multop = op->getIn(0)->getDef();
  if (multop == (PcodeOp *)0) return false;
  if (multop->code() != CPUI_INT_MULT) return false;
  Varnode *cvn = multop->getIn(1);
  if (!cvn->isConstant()) return false;
  if (cvn->getOffset() != calc_mask(cvn->getSize())) return false;

  PcodeOp *addop = multop->getIn(0)->getDef();
  if (addop == (PcodeOp *)0) return false;
  if (addop->code() != CPUI_INT_ADD) return false;
  v = addop->getIn(0);
  c[1] = addop->getIn(1);

  if (v->isFree()) return false;
  if (!c[0]->isConstant()) return false;
  if (!c[1]->isConstant()) return false;

  val[0] = sign_extend(c[0]->getOffset(),8*c[0]->getSize()-1);
  val[1] = sign_extend(c[1]->getOffset(),8*c[1]->getSize()-1);
  value = val[0] - val[1];

  Varnode *newvn = data.newConstant(c[0]->getSize(),value&cvn->getOffset());
  if (c[0]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[0]);
  else if (c[1]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[1]);

  PcodeOp *newmultop = data.newOpBefore(op, CPUI_INT_MULT,v,cvn);
  data.opSetInput(op,newmultop->getOut(),0);
  data.opSetInput(op,newvn,1);

  return true;
}

bool RuleSubtractionCollapse::form3(PcodeOp *op,Funcdata &data)

{
  Varnode *v;              // Variable varnode
  Varnode *c[2];           // Constant varnodes
  intb val[2];             // Constant values
  intb value;              // Final constant value
  v = (Varnode *)0;        // V
  c[0] = (Varnode *)0;     // c
  c[1] = (Varnode *)0;     // d
  val[0] = 0;              // c
  val[1] = 0;              // d
  value = 0;               // c-d

  if (op == (PcodeOp *)0) return false;
  if (op->code() != CPUI_INT_ADD) return false;
  c[1] = op->getIn(1);
  PcodeOp *multop = op->getIn(0)->getDef();
  if (multop == (PcodeOp *)0) return false;
  if (multop->code() != CPUI_INT_MULT) return false;

  Varnode *cvn = multop->getIn(1);
  if (!cvn->isConstant()) return false;
  if (cvn->getOffset() != calc_mask(cvn->getSize())) return false;
  PcodeOp *ptrsubop = multop->getIn(0)->getDef();
  if (ptrsubop == (PcodeOp *)0) return false;
  if (ptrsubop->code() != CPUI_PTRSUB) return false;
  v = ptrsubop->getIn(0);
  c[0] = ptrsubop->getIn(1);

  if (v->isFree()) return false;
  if (!c[0]->isConstant()) return false;
  if (!c[1]->isConstant()) return false;

  val[0] = sign_extend(c[0]->getOffset(),8*c[0]->getSize()-1);
  val[1] = sign_extend(c[1]->getOffset(),8*c[1]->getSize()-1);
  value = val[0] - val[1];

  Varnode *newvn = data.newConstant(c[0]->getSize(),value&cvn->getOffset());
  if (c[0]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[0]);
  else if (c[1]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[1]);

  PcodeOp *newptrsubop = data.newOpBefore(op,CPUI_PTRSUB,v,newvn);
  data.opSetInput(op,newptrsubop->getOut(),0);
  data.opSetInput(op,cvn,1);
  data.opSetOpcode(op,CPUI_INT_MULT);
  return true;
}

bool RuleSubtractionCollapse::form4(PcodeOp *op,Funcdata &data)

{
  Varnode *v;              // Variable varnode
  Varnode *c[3];           // Constant varnodes
  intb val[3];             // Constant values
  intb value;              // Final constant value
  v = (Varnode *)0;        // V
  c[0] = (Varnode *)0;     // c
  c[1] = (Varnode *)0;     // d
  c[2] = (Varnode *)0;     // e
  val[0] = 0;              // c
  val[1] = 0;              // d
  val[2] = 0;              // e
  value = 0;               // c-(d*e)

  if (op->code() != CPUI_INT_ADD) return false;
  c[0] = op->getIn(1);
  PcodeOp *multop = op->getIn(0)->getDef();
  if (multop == (PcodeOp *)0) return false;
  if (multop->code() != CPUI_INT_MULT) return false;
  Varnode *cvn = multop->getIn(1);
  if (!cvn->isConstant()) return false;
  if (cvn->getOffset() != calc_mask(cvn->getSize())) return false;

  PcodeOp *ptraddop = multop->getIn(0)->getDef();
  if (ptraddop == (PcodeOp *)0) return false;
  if (ptraddop->code() != CPUI_PTRADD) return false;
  v = ptraddop->getIn(0);
  c[1] = ptraddop->getIn(1);
  c[2] = ptraddop->getIn(2);

  if (v->isFree()) return false;
  if (!c[0]->isConstant()) return false;
  if (!c[1]->isConstant()) return false;
  if (!c[2]->isConstant()) return false;

  val[0] = sign_extend(c[0]->getOffset(),8*c[0]->getSize()-1);
  val[1] = sign_extend(c[1]->getOffset(),8*c[1]->getSize()-1);
  val[2] = sign_extend(c[2]->getOffset(),8*c[2]->getSize()-1);
  value = val[0] - (val[1] * val[2]);

  Varnode *newvn = data.newConstant(c[0]->getSize(),value&cvn->getOffset());
  if (c[0]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[0]);
  else if (c[1]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[1]);
  else if (c[2]->getSymbolEntry() != (SymbolEntry *)0)
    newvn->copySymbolIfValid(c[2]);

  PcodeOp *newmultop = data.newOpBefore(op, CPUI_INT_MULT,v,cvn);
  data.opSetInput(op,newmultop->getOut(),0);
  data.opSetInput(op,newvn,1);

  return true;
}

bool RuleSubtractionCollapse::form5(PcodeOp *op,Funcdata &data)

{
  Varnode *v[4];           // Variable varnode
  Varnode *c[3];           // Constant varnodes
  intb val[3];             // Constant values
  intb value[2];           // Final constant values
  v[0] = (Varnode *)0;     // V
  v[1] = (Varnode *)0;     // W
  v[2] = (Varnode *)0;     // X
  v[3] = (Varnode *)0;     // Y
  c[0] = (Varnode *)0;     // c
  c[1] = (Varnode *)0;     // d
  c[2] = (Varnode *)0;     // e
  val[0] = 0;              // c
  val[1] = 0;              // d
  val[2] = 0;              // e
  value[0] = 0;            // 1-e
  value[1] = 0;            // c-d*e

  if (op->code() != CPUI_PTRADD) return false;
  c[2] = op->getIn(2);

  PcodeOp *ptrsubop1 = op->getIn(0)->getDef();
  if (ptrsubop1 == (PcodeOp *)0) return false;
  if (ptrsubop1->code() != CPUI_PTRSUB) return false;
  v[0] = ptrsubop1->getIn(0);
  c[0] = ptrsubop1->getIn(1);

  PcodeOp *addop1 = op->getIn(1)->getDef();
  if (addop1 == (PcodeOp *)0) return false;
  if (addop1->code() != CPUI_INT_ADD) return false;
  v[3] = addop1->getIn(1);

  PcodeOp *addop2 = addop1->getIn(0)->getDef();
  if (addop2 == (PcodeOp *)0) return false;
  if (addop2->code() != CPUI_INT_ADD) return false;
  v[2] = addop2->getIn(1);

  PcodeOp *addop3 = addop2->getIn(0)->getDef();
  if (addop3 == (PcodeOp *)0) return false;
  if (addop3->code() != CPUI_INT_ADD) return false;
  v[1] = addop3->getIn(1);

  PcodeOp *multop = addop3->getIn(0)->getDef();
  if (multop == (PcodeOp *)0) return false;
  if (multop->code() != CPUI_INT_MULT) return false;
  Varnode *cvn = multop->getIn(1);
  if (!cvn->isConstant()) return false;
  if (cvn->getOffset() != calc_mask(cvn->getSize())) return false;

  PcodeOp *ptrsubop2 = multop->getIn(0)->getDef();
  if (ptrsubop2 == (PcodeOp *)0) return false;
  if (ptrsubop2->code() != CPUI_PTRSUB) return false;
  if (ptrsubop2->getIn(0) != v[0]) return false;
  c[1] = ptrsubop2->getIn(1);

  if (v[0]->isFree()) return false;
  if (v[1]->isFree() && !v[1]->isConstant()) return false;
  if (v[2]->isFree() && !v[2]->isConstant()) return false;
  if (v[3]->isFree() && !v[3]->isConstant()) return false;
  if (!c[0]->isConstant()) return false;
  if (!c[1]->isConstant()) return false;
  if (!c[2]->isConstant()) return false;

  val[0] = sign_extend(c[0]->getOffset(),8*c[0]->getSize()-1);
  val[1] = sign_extend(c[1]->getOffset(),8*c[1]->getSize()-1);
  val[2] = sign_extend(c[2]->getOffset(),8*c[2]->getSize()-1);
  value[0] = 1 - val[2];
  value[1] = val[0] - val[1] * val[2];

  Varnode *newvn1 = data.newConstant(c[0]->getSize(),value[0]&cvn->getOffset());
  Varnode *newvn2 = data.newConstant(c[0]->getSize(),value[1]&cvn->getOffset());
  if (c[0]->getSymbolEntry() != (SymbolEntry *)0) {
    newvn1->copySymbolIfValid(c[0]);
    newvn2->copySymbolIfValid(c[0]);
  }
  else if (c[1]->getSymbolEntry() != (SymbolEntry *)0) {
    newvn1->copySymbolIfValid(c[1]);
    newvn2->copySymbolIfValid(c[1]);
  }
  else if (c[2]->getSymbolEntry() != (SymbolEntry *)0) {
    newvn1->copySymbolIfValid(c[2]);
    newvn2->copySymbolIfValid(c[2]);
  }

  PcodeOp *newaddop1 = data.newOpBefore(op,CPUI_INT_ADD,v[1],v[2]);
  PcodeOp *newaddop2 = data.newOpBefore(op,CPUI_INT_ADD,newaddop1->getOut(),v[3]);
  PcodeOp *newmultop1 = data.newOpBefore(op,CPUI_INT_MULT,newaddop2->getOut(),c[2]);
  PcodeOp *newmultop2 = data.newOpBefore(op,CPUI_INT_MULT,v[0],newvn1);
  PcodeOp *newaddop3 = data.newOpBefore(op, CPUI_INT_ADD,newmultop1->getOut(),newmultop2->getOut());
  data.opRemoveInput(op,2);
  data.opSetInput(op,newaddop3->getOut(),0);
  data.opSetInput(op,newvn2,1);
  data.opSetOpcode(op,CPUI_INT_ADD);
  return true;
}

void RuleSubtractionCollapse::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ADD);
  oplist.push_back(CPUI_PTRADD);
}

/// \class RuleSubtractionCollapse
/// \brief Collapse constants in subtraction expression
///
/// INT_ADD forms:
///  - `(V + (W + d) * -1) + c  =>  (V + W * -1) + (c-d)`
///  - `(V + d) * -1 + c        =>  V * -1 + (c-d)`
/// PTRADD forms:
///  - `V + (d + PTRSUB(W,c) * -1)                                => V + PTRSUB(W,c-d) * -1`
///  - `PTRADD(V,d,e) * -1 + c                                    =>  V * -1 + (c-(d*e))`
///  - `PTRADD(PTRSUB(V,c),(((PTRSUB(V,d) * -1) + W) + X) + Y,e)  =>  ((((W + X) + Y) * e) + (V * 1-e)) + (c-d*e)`
int4 RuleSubtractionCollapse::applyOp(PcodeOp *op,Funcdata &data)

{
  // INT_ADD
  if (form1(op,data)) return 1;
  if (form2(op,data)) return 1;
  // PTRADD
  if (form3(op,data)) return 1;
  if (form4(op,data)) return 1;
  if (form5(op,data)) return 1;
  return 0;
}

/// \brief Return associated space if given Varnode is an \e active spacebase.
///
/// The Varnode should be a spacebase register input to the function or a
/// constant, and it should get loaded from the correct space.
/// \param glb is the address space manager
/// \param vn is the given Varnode
/// \param spc is the address space being loaded from
/// \return the associated space or NULL if the Varnode is not of the correct form
AddrSpace *RuleLoadVarnode::correctSpacebase(Architecture *glb,Varnode *vn,AddrSpace *spc)

{
  if (!vn->isSpacebase()) return (AddrSpace *)0;
  if (vn->isConstant())		// We have a global pseudo spacebase
    return spc;			// Associate with load/stored space
  if (!vn->isInput()) return (AddrSpace *)0;
  AddrSpace *assoc = glb->getSpaceBySpacebase(vn->getAddr(),vn->getSize());
  if (assoc->getContain() != spc) // Loading off right space?
    return (AddrSpace *)0;
  return assoc;
}

/// \brief Check if given Varnode is spacebase + a constant
///
/// If it is, pass back the constant and return the associated space
/// \param glb is the address space manager
/// \param vn is the given Varnode
/// \param val is the reference for passing back the constant
/// \param spc is the space being loaded from
/// \return the associated space or NULL
AddrSpace *RuleLoadVarnode::vnSpacebase(Architecture *glb,Varnode *vn,uintb &val,AddrSpace *spc)

{
  PcodeOp *op;
  Varnode *vn1,*vn2;
  AddrSpace *retspace;
  
  retspace = correctSpacebase(glb,vn,spc);
  if (retspace != (AddrSpace *)0) {
    val = 0;
    return retspace;
  }
  if (!vn->isWritten()) return (AddrSpace *)0;
  op = vn->getDef();
  if (op->code() != CPUI_INT_ADD) return (AddrSpace *)0;
  vn1 = op->getIn(0);
  vn2 = op->getIn(1);
  retspace = correctSpacebase(glb,vn1,spc);
  if (retspace != (AddrSpace *)0) {
    if (vn2->isConstant()) {
      val = vn2->getOffset();
      return retspace;
    }
    return (AddrSpace *)0;
  }
  retspace = correctSpacebase(glb,vn2,spc);
  if (retspace != (AddrSpace *)0) {
    if (vn1->isConstant()) {
      val = vn1->getOffset();
      return retspace;
    }
  }
  return (AddrSpace *)0;
}

/// \brief Check if STORE or LOAD is off of a spacebase + constant
///
/// If so return the associated space and pass back the offset
/// \param glb is the address space manager
/// \param op is the STORE or LOAD PcodeOp
/// \param offoff is a reference to where the offset should get passed back
/// \return the associated space or NULL
AddrSpace *RuleLoadVarnode::checkSpacebase(Architecture *glb,PcodeOp *op,uintb &offoff)

{
  Varnode *offvn;
  AddrSpace *loadspace;

  if (op->code() != CPUI_LOAD)
    if (op->code() != CPUI_STORE)
      return (AddrSpace *)0;
  offvn = op->getIn(1);		// Address offset
  loadspace = op->getIn(0)->getSpaceFromConst(); // Space being loaded/stored
  // Treat segmentop as part of load/store
  if (offvn->isWritten()&&(offvn->getDef()->code()==CPUI_SEGMENTOP)) {
    offvn = offvn->getDef()->getIn(2);
    // If we are looking for a spacebase (i.e. stackpointer)
    // Then currently we COMPLETELY IGNORE the base part of the
    // segment. We assume it is all correct.
    // If the segmentop inner is constant, we are NOT looking
    // for a spacebase, and we do not igore the base. If the
    // base is also constant, we let RuleSegmentOp reduce
    // the whole segmentop to a constant.  If the base
    // is not constant, we are not ready for a fixed address.
    if (offvn->isConstant())
      return (AddrSpace *)0;
  }
  else if (offvn->isConstant()) { // Check for constant
    offoff = offvn->getOffset();
    return loadspace;
  }
  return vnSpacebase(glb,offvn,offoff,loadspace);
}

/// \class RuleLoadVarnode
/// \brief Convert LOAD operations using a constant offset to COPY
///
/// The pointer can either be a constant offset into the LOAD's specified address space,
/// or it can be a \e spacebase register plus an offset, in which case it points into
/// the \e spacebase register's address space.
void RuleLoadVarnode::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_LOAD);
}

int4 RuleLoadVarnode::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 size;
  Varnode *newvn;
  AddrSpace *baseoff;
  uintb offoff;

  baseoff = checkSpacebase(data.getArch(),op,offoff);
  if (baseoff == (AddrSpace *)0) return 0;

  size = op->getOut()->getSize();
  offoff = AddrSpace::addressToByte(offoff,baseoff->getWordSize());
  // In normal address space (and not in the register one)
  if (baseoff->getType() == IPTR_PROCESSOR && baseoff->getName() != "register") {
    SymbolEntry *entry = op->getIn(1)->getGlobalPointerSymbol(op);
    // Must have symbol defined there
    if (entry == (SymbolEntry *)0) return 0;
  }

  newvn = data.newVarnode(size,baseoff,offoff);
  data.opSetInput(op,newvn,0);
  data.opRemoveInput(op,1);
  data.opSetOpcode(op, CPUI_COPY );
  Varnode *refvn = op->getOut();
  if (refvn->isSpacebasePlaceholder()) {
    refvn->clearSpacebasePlaceholder();	// Clear the trigger
    PcodeOp *placeOp = refvn->loneDescend();
    if (placeOp != (PcodeOp *)0) {
      FuncCallSpecs *fc = data.getCallSpecs(placeOp);
      if (fc != (FuncCallSpecs *)0)
	fc->resolveSpacebaseRelative(data,refvn);
    }
  }
  return 1;
}

//Get ops which use pointer to the same offset as given
void RuleStoreVarnode::gatherOffsetUsageOps(PcodeOp *op,Varnode *basevn,AddrSpace *space,uintb offset,Funcdata &data,vector<PcodeOp *> &ops,vector<int4> &slots)

{
  // Check aliasing int_add and ptrsub
  intb addroff = sign_extend(offset,8*space->getAddrSize()-1);
  list<PcodeOp *>::const_iterator oiter;
  for (oiter=basevn->beginDescend();oiter!=basevn->endDescend();++oiter) {
    PcodeOp *otherop = *oiter;
    if (otherop->code() == CPUI_INT_ADD) {
      if (otherop->getIn(0) != basevn) continue;
      intb otheroff = sign_extend(otherop->getIn(1)->getOffset(),8*otherop->getIn(1)->getSize()-1);
      if (otheroff != addroff) continue;
      Varnode *vn = otherop->getOut();
      PcodeOp *useop = vn->loneDescend();
      if (useop == (PcodeOp *)0) continue;
      if (useop == op) continue;
      ops.push_back(useop);
      int4 slot = useop->getSlot(vn);
      slots.push_back(slot);
    }
    else if (otherop->code() == CPUI_PTRSUB) {
      if (otherop->getIn(0) != basevn) continue;
      intb otheroff = sign_extend(otherop->getIn(1)->getOffset(),8*otherop->getIn(1)->getSize()-1);
      if (otheroff != addroff) continue;
      Varnode *vn = otherop->getOut();
      PcodeOp *useop = vn->loneDescend();
      if (useop == (PcodeOp *)0) continue;
      if (useop == op) continue;
      ops.push_back(useop);
      int4 slot = useop->getSlot(vn);
      slots.push_back(slot);
    }
  }

  // Also check location aliases
  uintb byteoff = AddrSpace::addressToByte(offset,space->getWordSize());
  Address addr(space,byteoff);
  VarnodeLocSet::const_iterator viter;
  for (viter=data.beginLoc(addr);viter!=data.endLoc(addr);++viter) {
    Varnode *vn = *viter;
    PcodeOp *useop = vn->loneDescend();
    if (useop == (PcodeOp *)0) continue;
    ops.push_back(useop);
    int4 slot = useop->getSlot(vn);
    slots.push_back(slot);
  }
}

void RuleStoreVarnode::gatherPointerUsageOps(PcodeOp *op,Funcdata &data,vector<PcodeOp *> &ops,vector<int4> &slots)

{
  uintb endoff;
  AddrSpace *spc = RuleLoadVarnode::checkSpacebase(data.getArch(),op,endoff);
  if (spc == (AddrSpace *)0) return;

  PcodeOp *addop = op->getIn(1)->getDef();
  if (addop == (PcodeOp *)0) return;
  if (addop->code() != CPUI_INT_ADD) return;
  Varnode *basevn = addop->getIn(0);

  gatherOffsetUsageOps(op,basevn,spc,endoff,data,ops,slots);

  TypePointer *ptype = (TypePointer *)basevn->getType();
  if (ptype->getMetatype() != TYPE_PTR) return;
  TypeSpacebase *sb = (TypeSpacebase *)ptype->getPtrTo();
  if (sb->getMetatype() != TYPE_SPACEBASE) return;
  Address addr = sb->getAddress(endoff,basevn->getSize(),op->getAddr());
  if (addr.isInvalid()) return;
  Scope *scope = sb->getMap();
  SymbolEntry *entry = scope->queryContainer(addr,1,Address());
  if (entry == (SymbolEntry *)0) return;

  uintb startoff = entry->getAddr().getOffset();
  for (uintb off = startoff;off<endoff;off++) {
    gatherOffsetUsageOps(op,basevn,spc,off,data,ops,slots);
  }
}

bool RuleStoreVarnode::testStore(PcodeOp *op,Funcdata &data)

{
  TypeFactory *types = data.getArch()->types;
  Datatype *dt = op->recoverVftableDatatype(types,true);
  if (dt != (Datatype *)0) return false;

  vector<PcodeOp *> useops;
  vector<int4> useslots;
  gatherPointerUsageOps(op,data,useops,useslots);

  vector<PcodeOp *>::const_iterator iter1;
  for (int4 i=0;i<useops.size();++i) {
    uintb off1,off2 = 0;
    AddrSpace *base1,*base2 = (AddrSpace *)0;
    PcodeOp *guardop = (PcodeOp *)0;

    PcodeOp *use = useops[i];
    int4 slot = useslots[i];
    switch (use->code()) {
      case CPUI_COPY:
	if (use->getOut()->hasNoDescend())
	  return false; // Partial deletion of copy which is still used
	break;
      case CPUI_LOAD:
	if (!use->getOut()->hasNoDescend())
	  return false;
	break;
      case CPUI_STORE:
	if (slot == 2) return false; // An address is taken
	base1 = RuleLoadVarnode::checkSpacebase(data.getArch(),op,off1);
	base2 = RuleLoadVarnode::checkSpacebase(data.getArch(),use,off2);

	if (base1 == (AddrSpace *)0) return false;
	if (base2 == (AddrSpace *)0) return false;
	if (off1 != off2) return false;

	// If addresses match, this doesn't count as usage
	break;
      case CPUI_CALL:
	if (slot > 0)
	  return false; // Call parameter always counts as usage
	break;
      case CPUI_INDIRECT:
	guardop = (PcodeOp *)use->getIn(1)->getOffset();
	if (guardop->code() == CPUI_STORE)
	  return false;
	break;
      default:
	break;
    }
  }
  return true;
}

/// \class RuleStoreVarnode
/// \brief Convert STORE operations using a constant offset to COPY
///
/// The pointer can either be a constant offset into the STORE's specified address space,
/// or it can be a \e spacebase register plus an offset, in which case it points into
/// the \e spacebase register's address space.
void RuleStoreVarnode::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_STORE);
}

int4 RuleStoreVarnode::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 size;
  AddrSpace *baseoff;
  uintb offoff;

  baseoff = RuleLoadVarnode::checkSpacebase(data.getArch(),op,offoff);
  if (baseoff == (AddrSpace *)0) return 0;
  // TODO investigate cases
  //if (!testStore(op,data)) return 0;

  size = op->getIn(2)->getSize();
  offoff = AddrSpace::addressToByte(offoff,baseoff->getWordSize());
  Address addr(baseoff,offoff);
  data.newVarnodeOut(size, addr,op);
  op->getOut()->setStackStore();	// Mark as originally coming from CPUI_STORE
  data.opRemoveInput(op,1);
  data.opRemoveInput(op,0);
  data.opSetOpcode(op, CPUI_COPY );
  if (op->isStoreUnmapped()) {
    data.getScopeLocal()->markNotMapped(baseoff, offoff, size, false);
  }
  return 1;
}

// This op is quadratic in the number of MULTIEQUALs in a block
// void RuleShadowVar::getOpList(vector<uint4> &oplist) const

// {
//   oplist.push_back(CPUI_MULTIEQUAL);
// }

// int4 RuleShadowVar::applyOp(PcodeOp *op,Funcdata &data)

// {				// Check for "shadowed" varnode
//   PcodeOp *op2;
//   int4 i;

//   for(op2=op->previousOp();op2!=(PcodeOp *)0;op2=op2->previousOp()) {
//     if (op2->code() != CPUI_MULTIEQUAL) continue;
//     for(i=0;i<op->numInput();++i) // Check for match in each branch
//       if (*op->Input(i) != *op2->Input(i)) break;
//     if (i != op->numInput()) continue; // All branches did not match
    
// 				// This op "shadows" op2, so replace with COPY
//     vector<Varnode *> plist;
//     plist.push_back(op2->Output());
//     data.op_setopcode(op,CPUI_COPY);
//     data.opSetAllInput(op,plist);
//     return 1;
//   }
//   return 0;
// }

// void RuleTruncShiftCancel::getOpList(vector<uint4> &oplist) const

// {
//   oplist.push_back(CPUI_SUBPIECE);
// }

// int4 RuleTruncShiftCancel::applyOp(PcodeOp *op,Funcdata &data) const

// { // SUBPIECE with truncation cancels out <<
//   // replace SUB( vn << #c , #d) with
//   // SUB( vn << #e, #f )    where either #e or #f is zero
// }

/// \class RuleSubExtComm
/// \brief Commute SUBPIECE and INT_ZEXT:  `sub(zext(V),c)  =>  zext(sub(V,c))`
///
/// This is in keeping with the philosophy to push SUBPIECE back earlier in the expression.
/// The original SUBPIECE is changed into the INT_ZEXT, but the original INT_ZEXT is
/// not changed, a new SUBPIECE is created.
/// There are corner cases, if the SUBPIECE doesn't hit extended bits or is ultimately unnecessary.
///    - `sub(zext(V),c)  =>  sub(V,C)`
///    - `sub(zext(V),0)  =>  zext(V)`
///
/// This rule also works with INT_SEXT.
void RuleSubExtComm::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleSubExtComm::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *base = op->getIn(0);
  if (!base->isWritten()) return 0;
  PcodeOp *extop = base->getDef();
  if ((extop->code()!=CPUI_INT_ZEXT)&&(extop->code()!=CPUI_INT_SEXT))
    return 0;
  Varnode *invn = extop->getIn(0);
  if (invn->isFree()) return 0;
  int4 subcut = (int4)op->getIn(1)->getOffset();
  if (op->getOut()->getSize() + subcut <= invn->getSize()) {
    // SUBPIECE doesn't hit the extended bits at all
    data.opSetInput(op,invn,0);
    if (invn->getSize() == op->getOut()->getSize()) {
      data.opRemoveInput(op, 1);
      data.opSetOpcode(op, CPUI_COPY);
    }
    return 1;
  }

  if (subcut >= invn->getSize()) return 0;

  Varnode *newvn;
  if (subcut != 0) {
    PcodeOp *newop = data.newOp(2,op->getAddr());
    data.opSetOpcode(newop,CPUI_SUBPIECE);
    newvn = data.newUniqueOut(invn->getSize()-subcut,newop);
    data.opSetInput(newop,data.newConstant(op->getIn(1)->getSize(),(uintb)subcut),1);
    data.opSetInput(newop,invn,0);
    data.opInsertBefore(newop,op);
  }
  else
    newvn = invn;

  data.opRemoveInput(op,1);
  data.opSetOpcode(op,extop->code());
  data.opSetInput(op,newvn,0);
  return 1;
}

/// \class RuleSubCommute
/// \brief Commute SUBPIECE operations with earlier operations where possible
///
/// A SUBPIECE conmmutes with long and short forms of many operations.
/// We try to push SUBPIECE earlier in the expression trees (preferring short versions
/// of ops over long) in the hopes that the SUBPIECE will run into a
/// constant, a INT_SEXT, or a INT_ZEXT, canceling out
void RuleSubCommute::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

/// \brief Shrink the output of an extension to the given size
///
/// The output of either a INT_ZEXT or INT_SEXT is replaced with a smaller/truncated Varnode.
/// \param extOp is the INT_ZEXT or INT_SEXT
/// \param maxSize is the given size to shrink the output to
/// \param data is the function owning the extension
/// \return the new smaller Varnode
Varnode *RuleSubCommute::shortenExtension(PcodeOp *extOp,int4 maxSize,Funcdata &data)

{
  Varnode *origOut = extOp->getOut();
  Address addr = origOut->getAddr();
  if (addr.isBigEndian())
    addr = addr + (origOut->getSize() - maxSize);
  data.opUnsetOutput(extOp);
  return data.newVarnodeOut(maxSize, addr, extOp);
}

/// \brief Eliminate input extensions on given binary PcodeOp
///
/// Make some basic checks.  Replace the input and output Varnodes with smaller sizes.
/// \param longform is the given binary PcodeOp to modify
/// \param subOp is the PcodeOp truncating the output of \b longform
/// \param ext0In is the first input Varnode before the extension
/// \param ext1In is the second input Varnode before the extension
/// \param data is the function being analyzed
/// \return true is the PcodeOp is successfully modified
bool RuleSubCommute::cancelExtensions(PcodeOp *longform,PcodeOp *subOp,Varnode *ext0In,Varnode *ext1In,Funcdata &data)

{
  int4 maxSize;
  Varnode *outvn = longform->getOut();
  if (outvn->loneDescend() != subOp) return false;	// Must be exactly one output to SUBPIECE
  if (ext0In->getSize() == ext1In->getSize()) {
    maxSize = ext0In->getSize();
    if (ext0In->isFree()) return false;		// Must be able to propagate inputs
    if (ext1In->isFree()) return false;
  }
  else if (ext0In->getSize() < ext1In->getSize()) {
    maxSize = ext1In->getSize();
    if (ext1In->isFree()) return false;
    if (longform->getIn(0)->loneDescend() != longform) return false;
    ext0In = shortenExtension(longform->getIn(0)->getDef(), maxSize, data);
  }
  else {
    maxSize = ext0In->getSize();
    if (ext0In->isFree()) return false;
    if (longform->getIn(1)->loneDescend() != longform) return false;
    ext1In = shortenExtension(longform->getIn(1)->getDef(), maxSize, data);
  }
  data.opUnsetOutput(longform);
  outvn = data.newUniqueOut(maxSize,longform);	// Create truncated form of longform output
  data.opSetInput(longform,ext0In,0);
  data.opSetInput(longform,ext1In,1);
  data.opSetInput(subOp,outvn,0);
  return true;
}

int4 RuleSubCommute::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *base,*vn,*newvn,*outvn;
  PcodeOp *longform,*newsub,*prevop;
  int4 i,j,offset,insize;

  base = op->getIn(0);
  if (!base->isWritten()) return 0;
  offset = op->getIn(1)->getOffset();
  outvn = op->getOut();
  if (outvn->isPrecisLo()||outvn->isPrecisHi()) return 0;
  insize = base->getSize();
  longform = base->getDef();
  j = -1;
  switch( longform->code() ) {	// Determine if this op commutes with SUBPIECE
    //  case CPUI_COPY:
  case CPUI_INT_LEFT:
    j = 1;			// Special processing for shift amount param
    if (offset != 0) return 0;
    if (!longform->getIn(0)->isWritten()) return 0;
    prevop = longform->getIn(0)->getDef();
    if (prevop->code()==CPUI_INT_ZEXT) {
    }
    else if (prevop->code()==CPUI_PIECE) {
    }
    else
      return 0;
    break;
  case CPUI_INT_REM:
  case CPUI_INT_DIV:
  {
				// Only commutes if inputs are zero extended
    if (offset != 0) return 0;
    if (!longform->getIn(0)->isWritten()) return 0;
    PcodeOp *zext0 = longform->getIn(0)->getDef();
    if (zext0->code() != CPUI_INT_ZEXT) return 0;
    Varnode *zext0In = zext0->getIn(0);
    if (longform->getIn(1)->isWritten()) {
      PcodeOp *zext1 = longform->getIn(1)->getDef();
      if (zext1->code() != CPUI_INT_ZEXT) return 0;
      Varnode *zext1In = zext1->getIn(0);
      if (zext1In->getSize() > outvn->getSize() || zext0In->getSize() > outvn->getSize()) {
	  // Special case where we need a PARTIAL commute of the SUBPIECE
	  // SUBPIECE cancels the ZEXTs, but there is still some SUBPIECE left
	if (cancelExtensions(longform,op,zext0In,zext1In,data))	// Cancel ZEXT operations
	  return 1;						// Leave SUBPIECE intact
	return 0;
      }
      // If ZEXT sizes are both not bigger, go ahead and commute SUBPIECE (fallthru)
    }
    else if (longform->getIn(1)->isConstant() && (zext0In->getSize() <= outvn->getSize())) {
      uintb val = longform->getIn(1)->getOffset();
      uintb smallval = val & calc_mask(outvn->getSize());
      if (val != smallval)
	return 0;
    }
    else
      return 0;
    break;
  }
  case CPUI_INT_SREM:
  case CPUI_INT_SDIV:
  {
				// Only commutes if inputs are sign extended
    if (offset != 0) return 0;
    if (!longform->getIn(0)->isWritten()) return 0;
    PcodeOp *sext0 = longform->getIn(0)->getDef();
    if (sext0->code() != CPUI_INT_SEXT) return 0;
    Varnode *sext0In = sext0->getIn(0);
    if (longform->getIn(1)->isWritten()) {
      PcodeOp *sext1 = longform->getIn(1)->getDef();
      if (sext1->code() != CPUI_INT_SEXT) return 0;
      Varnode *sext1In = sext1->getIn(0);
      if (sext1In->getSize() > outvn->getSize() || sext0In->getSize() > outvn->getSize()) {
	// Special case where we need a PARTIAL commute of the SUBPIECE
	// SUBPIECE cancels the SEXTs, but there is still some SUBPIECE left
	if (cancelExtensions(longform,op,sext0In,sext1In,data))	// Cancel SEXT operations
	  return 1;						// Leave SUBPIECE intact
	return 0;
      }
      // If SEXT sizes are both not bigger, go ahead and commute SUBPIECE (fallthru)
    }
    else if (longform->getIn(1)->isConstant() && (sext0In->getSize() <= outvn->getSize())) {
      uintb val = longform->getIn(1)->getOffset();
      uintb smallval = val & calc_mask(outvn->getSize());
      smallval = sign_extend(smallval,outvn->getSize(),insize);
      if (val != smallval)
	return 0;
    }
    else
      return 0;
    break;
  }
  case CPUI_INT_ADD:
    if (offset != 0) return 0;	// Only commutes with least significant SUBPIECE
    if (longform->getIn(0)->isSpacebase()) return 0;	// Deconflict with RulePtrArith
    break;
  case CPUI_INT_MULT:
    if (offset != 0) return 0;	// Only commutes with least significant SUBPIECE
    break;
				// Bitwise ops, type of subpiece doesnt matter
  case CPUI_INT_NEGATE:
  case CPUI_INT_XOR:
  case CPUI_INT_AND:
  case CPUI_INT_OR:
    break;
  default:			// Most ops don't commute
    return 0;
  }

				// Make sure no other piece of base is getting used
  if (base->loneDescend() != op) return 0;

  if (offset == 0) {		// Look for overlap with RuleSubZext
    PcodeOp *nextop = outvn->loneDescend();
    if ((nextop != (PcodeOp *)0)&&(nextop->code() == CPUI_INT_ZEXT)) {
      if (nextop->getOut()->getSize() == insize)
	return 0;
    }
  }

  for(i=0;i<longform->numInput();++i) {
    vn = longform->getIn(i);
    if (i!=j) {
      newsub = data.newOp(2,op->getAddr()); // Commuted SUBPIECE op
      data.opSetOpcode(newsub,CPUI_SUBPIECE);
      newvn = data.newUniqueOut(outvn->getSize(),newsub);  // New varnode is subpiece
      data.opSetInput(longform,newvn,i);
      data.opSetInput(newsub,vn,0); // of old varnode
      data.opSetInput(newsub,data.newConstant(4,offset),1);
      data.opInsertBefore(newsub,longform);
    }
  }
  data.opSetOutput(longform,outvn);
  data.opDestroy(op);		// Get rid of old SUBPIECE
  return 1;
}

/// \class RuleConcatCommute
/// \brief Commute PIECE with INT_AND, INT_OR, and INT_XOR
///
/// This supports forms:
///   - `concat( V & c, W)  =>  concat(V,W) & (c<<16 | 0xffff)`
///   - `concat( V, W | c)  =>  concat(V,W) | c`
void RuleConcatCommute::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PIECE);
}

int4 RuleConcatCommute::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn;
  Varnode *hi,*lo,*newvn;
  PcodeOp *logicop,*newconcat;
  OpCode opc;
  uintb val;

  int4 outsz = op->getOut()->getSize();
  if (outsz > sizeof(uintb))
    return 0;			// FIXME:  precision problem for constants
  for(int4 i=0;i<2;++i) {
    vn = op->getIn(i);
    if (!vn->isWritten()) continue;
    logicop = vn->getDef();
    opc = logicop->code();
    if ((opc == CPUI_INT_OR)||(opc == CPUI_INT_XOR)) {
      if (!logicop->getIn(1)->isConstant()) continue;
      val = logicop->getIn(1)->getOffset();
      if (i==0) {
	hi = logicop->getIn(0);
	lo = op->getIn(1);
	val <<= 8*lo->getSize();
      }
      else {
	hi = op->getIn(0);
	lo = logicop->getIn(0);
      }
    }
    else if (opc == CPUI_INT_AND) {
      if (!logicop->getIn(1)->isConstant()) continue;
      val = logicop->getIn(1)->getOffset();
      if (i==0) {
	hi = logicop->getIn(0);
	lo = op->getIn(1);
	val <<= 8*lo->getSize();
	val |= calc_mask(lo->getSize());
      }
      else {
	hi = op->getIn(0);
	lo = logicop->getIn(0);
	val |= (calc_mask(hi->getSize()) << 8*lo->getSize());
      }
    }
    else
      continue;
    if (hi->isFree()) continue;
    if (lo->isFree()) continue;
    newconcat = data.newOp(2,op->getAddr());
    data.opSetOpcode(newconcat,CPUI_PIECE);
    newvn = data.newUniqueOut(outsz,newconcat);
    data.opSetInput(newconcat,hi,0);
    data.opSetInput(newconcat,lo,1);
    data.opInsertBefore(newconcat,op);
    data.opSetOpcode(op,opc);
    data.opSetInput(op,newvn,0);
    data.opSetInput(op,data.newConstant(newvn->getSize(),val),1);
    return 1;
  }
  return 0;
}

// void RuleIndirectConcat::getOpList(vector<uint4> &oplist) const

// {
//   oplist.push_back(CPUI_INDIRECT);
// }

// int4 RuleIndirectConcat::applyOp(PcodeOp *op,Funcdata &data)

// {
//   Varnode *vn = op->getIn(0);
//   if (!vn->isWritten()) return 0;
//   PcodeOp *concatop = vn->getDef();
//   if (concatop->code() != CPUI_PIECE) return 0;
//   Varnode *vnhi = concatop->getIn(0);
//   Varnode *vnlo = concatop->getIn(1);
//   if (vnhi->isFree() || vnhi->isVolatile() || vnhi->isSpacebase()) return 0;
//   if (vnlo->isFree() || vnlo->isVolatile() || vnlo->isSpacebase()) return 0;
//   if (op->getIn(1)->getSpace()->getType() != IPTR_IOP) return 0;
//   PcodeOp *indop = PcodeOp::getOpFromConst(op->getIn(1)->getAddr());
//   Varnode *newvnhi,*newvnlo;
//   Varnode *outvn = op->getOut();
//   data.splitVarnode(outvn,vnlo->getSize(),newvnlo,newvnhi);
//   PcodeOp *newophi,*newoplo;

//   newophi = data.newOp(2,indop->getAddr());
//   newoplo = data.newOp(2,indop->getAddr());
//   data.opSetOpcode(newophi,CPUI_INDIRECT);
//   data.opSetOpcode(newoplo,CPUI_INDIRECT);
//   data.opSetOutput(newophi,newvnhi);
//   data.opSetOutput(newoplo,newvnlo);
//   data.opSetInput(newophi,vnhi,0);
//   data.opSetInput(newoplo,vnlo,0);
//   data.opSetInput(newophi,data.newVarnodeIop(indop),1);
//   data.opSetInput(newoplo,data.newVarnodeIop(indop),1);
//   data.opInsertBefore(newophi,indop);
//   data.opInsertBefore(newoplo,indop);

//   // The original INDIRECT is basically dead at this point, so we clear any addrforce so it can be
//   // removed as deadcode
//   outvn->clearAddrForce();
//   if (outvn->hasNoDescend()) {	// If nobody else uses the value
//     // Prepare op for deletion, and so that the same rule won't trigger again
//     data.opSetOpcode(op,CPUI_COPY);
//     data.opRemoveInput(op,1);
//   }
//   else { // If the original INDIRECT output was used by other ops
//     // We recycle the op as the commuted concatenation
//     data.opUninsert(op);	// Remove op from before (simultaneous) execution with indop
//     data.opSetOpcode(op,CPUI_PIECE);
//     data.opSetInput(op,newvnhi,0);
//     data.opSetInput(op,newvnlo,1);
//     data.opInsertAfter(op,indop); // Insert recycled PIECE after the indop
//   }
//   return 1;
// }

/// \class RuleConcatZext
/// \brief Commute PIECE with INT_ZEXT:  `concat(zext(V),W)  =>  zext(concat(V,W))`
void RuleConcatZext::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PIECE);
}

int4 RuleConcatZext::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *zextop;
  Varnode *hi,*lo;

  hi = op->getIn(0);
  if (!hi->isWritten()) return 0;
  zextop = hi->getDef();
  if (zextop->code() != CPUI_INT_ZEXT) return 0;
  hi = zextop->getIn(0);
  lo = op->getIn(1);
  if (hi->isFree()) return 0;
  if (lo->isFree()) return 0;

  // Create new (earlier) concat out of hi and lo
  PcodeOp *newconcat = data.newOp(2,op->getAddr());
  data.opSetOpcode(newconcat,CPUI_PIECE);
  Varnode *newvn = data.newUniqueOut(hi->getSize()+lo->getSize(),newconcat);
  data.opSetInput(newconcat,hi,0);
  data.opSetInput(newconcat,lo,1);
  data.opInsertBefore(newconcat,op);

  // Change original op into a ZEXT
  data.opRemoveInput(op,1);
  data.opSetInput(op,newvn,0);
  data.opSetOpcode(op,CPUI_INT_ZEXT);
  return 1;
}

/// \class RuleZextCommute
/// \brief Commute INT_ZEXT with INT_RIGHT: `zext(V) >> W  =>  zext(V >> W)`
void RuleZextCommute::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_RIGHT);
}

int4 RuleZextCommute::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *zextvn = op->getIn(0);
  if (!zextvn->isWritten()) return 0;
  PcodeOp *zextop = zextvn->getDef();
  if (zextop->code() != CPUI_INT_ZEXT) return 0;
  Varnode *zextin = zextop->getIn(0);
  if (zextin->isFree()) return 0;
  Varnode *savn = op->getIn(1);
  if ((!savn->isConstant())&&(savn->isFree()))
    return 0;

  PcodeOp *newop = data.newOp(2,op->getAddr());
  data.opSetOpcode(newop,CPUI_INT_RIGHT);
  Varnode *newout = data.newUniqueOut(zextin->getSize(),newop);
  data.opRemoveInput(op,1);
  data.opSetInput(op,newout,0);
  data.opSetOpcode(op,CPUI_INT_ZEXT);
  data.opSetInput(newop,zextin,0);
  data.opSetInput(newop,savn,1);
  data.opInsertBefore(newop,op);
  return 1;
}

/// \class RuleZextShiftZext
/// \brief Simplify multiple INT_ZEXT operations: `zext( zext(V) << c )  => zext(V) << c`
void RuleZextShiftZext::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ZEXT);
}

int4 RuleZextShiftZext::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *invn = op->getIn(0);
  if (!invn->isWritten()) return 0;
  PcodeOp *shiftop = invn->getDef();
  if (shiftop->code() == CPUI_INT_ZEXT) {	// Check for ZEXT( ZEXT( a ) )
    Varnode *vn = shiftop->getIn(0);
    if (vn->isFree()) return 0;
    if (invn->loneDescend() != op)		// Only propagate if -op- is only use of -invn-
      return 0;
    data.opSetInput(op,vn,0);
    return 1;
  }
  if (shiftop->code() != CPUI_INT_LEFT) return 0;
  if (!shiftop->getIn(1)->isConstant()) return 0;
  if (!shiftop->getIn(0)->isWritten()) return 0;
  PcodeOp *zext2op = shiftop->getIn(0)->getDef();
  if (zext2op->code() != CPUI_INT_ZEXT) return 0;
  Varnode *rootvn = zext2op->getIn(0);
  if (rootvn->isFree()) return 0;

  uintb sa = shiftop->getIn(1)->getOffset();
  if (sa > 8* (uintb)(zext2op->getOut()->getSize() - rootvn->getSize()))
    return 0; // Shift might lose bits off the top
  PcodeOp *newop = data.newOp(1,op->getAddr());
  data.opSetOpcode(newop,CPUI_INT_ZEXT);
  Varnode *outvn = data.newUniqueOut(op->getOut()->getSize(),newop);
  data.opSetInput(newop,rootvn,0);
  data.opSetOpcode(op,CPUI_INT_LEFT);
  data.opSetInput(op,outvn,0);
  data.opInsertInput(op,data.newConstant(4,sa),1);
  data.opInsertBefore(newop,op);
  return 1;
}

/// \class RuleShiftAnd
/// \brief Eliminate any INT_AND when the bits it zeroes out are discarded by a shift
///
/// This also allows for bits that aren't discarded but are already zero.
void RuleShiftAnd::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_RIGHT);
  oplist.push_back(CPUI_INT_LEFT);
  oplist.push_back(CPUI_INT_MULT);
}

int4 RuleShiftAnd::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *cvn = op->getIn(1);
  if (!cvn->isConstant()) return 0;
  Varnode *shiftin = op->getIn(0);
  if (!shiftin->isWritten()) return 0;
  PcodeOp *andop = shiftin->getDef();
  if (andop->code() != CPUI_INT_AND) return 0;
  if (shiftin->loneDescend() != op) return 0;
  Varnode *maskvn = andop->getIn(1);
  if (!maskvn->isConstant()) return 0;
  uintb mask = maskvn->getOffset();
  Varnode *invn = andop->getIn(0);
  if (invn->isFree()) return 0;

  OpCode opc = op->code();
  int4 sa;
  if ((opc == CPUI_INT_RIGHT)||(opc == CPUI_INT_LEFT))
    sa = (int4)cvn->getOffset();
  else {
    sa = leastsigbit_set(cvn->getOffset()); // Make sure the multiply is really a shift
    if (sa <= 0) return 0;
    uintb testval = 1;
    testval <<= sa;
    if (testval != cvn->getOffset()) return 0;
    opc = CPUI_INT_LEFT;	// Treat CPUI_INT_MULT as CPUI_INT_LEFT
  }
  uintb nzm = invn->getNZMask();
  uintb fullmask = calc_mask(invn->getSize());
  if (opc == CPUI_INT_RIGHT) {
    nzm >>= sa;
    mask >>= sa;
  }
  else {
    nzm <<= sa;
    mask <<= sa;
    nzm &= fullmask;
    mask &= fullmask;
  }
  if ((mask & nzm) != nzm) return 0;
  data.opSetOpcode(andop,CPUI_COPY); // AND effectively does nothing, so we change it to a copy
  data.opRemoveInput(andop,1);
  return 1;
}

/// \class RuleConcatZero
/// \brief Simplify concatenation with zero:  `concat(V,0)  =>  zext(V) << c`
void RuleConcatZero::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PIECE);
}

int4 RuleConcatZero::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(1)->isConstant()) return 0;
  if (op->getIn(1)->getOffset() != 0) return 0;
  if (op->getOut()->getSize() > sizeof(uintb)) return 0; // No array shifts are allowed
  Datatype *outDt = op->getOut()->getType();
  if (outDt != (Datatype *)0) {
    if (outDt->getMetatype() == TYPE_STRUCT) return 0; // Don't touch structures
  }


  int4 sa = 8*op->getIn(1)->getSize();
  Varnode *highvn = op->getIn(0);
  PcodeOp *newop = data.newOp(1,op->getAddr());
  Varnode *outvn = data.newUniqueOut(op->getOut()->getSize(),newop);
  data.opSetOpcode(newop,CPUI_INT_ZEXT);
  data.opSetOpcode(op,CPUI_INT_LEFT);
  data.opSetInput(op,outvn,0);
  data.opSetInput(op,data.newConstant(4,sa),1);
  data.opSetInput(newop,highvn,0);
  data.opInsertBefore(newop,op);
  return 1;
}

/// \class RuleConcatLeftShift
/// \brief Simplify concatenation of extended value: `concat(V, zext(W) << c)  =>  concat( concat(V,W), 0)`
void RuleConcatLeftShift::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PIECE);
}

int4 RuleConcatLeftShift::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn2 = op->getIn(1);
  if (!vn2->isWritten()) return 0;
  PcodeOp *shiftop = vn2->getDef();
  if (shiftop->code() != CPUI_INT_LEFT) return 0;
  if (!shiftop->getIn(1)->isConstant()) return 0; // Must be a constant shift
  int4 sa = shiftop->getIn(1)->getOffset();
  if ((sa&7)!=0) return 0;	// Not a multiple of 8
  Varnode *tmpvn = shiftop->getIn(0);
  if (!tmpvn->isWritten()) return 0;
  PcodeOp *zextop = tmpvn->getDef();
  if (zextop->code() != CPUI_INT_ZEXT) return 0;
  Varnode *b = zextop->getIn(0);
  if (b->isFree()) return 0;
  Varnode *vn1 = op->getIn(0);
  if (vn1->isFree()) return 0;
  sa /= 8;			// bits to bytes
  if (sa + b->getSize() != tmpvn->getSize()) return 0; // Must shift to most sig boundary

  PcodeOp *newop = data.newOp(2,op->getAddr());
  data.opSetOpcode(newop,CPUI_PIECE);
  Varnode *newout = data.newUniqueOut(vn1->getSize() + b->getSize(),newop);
  data.opSetInput(newop,vn1,0);
  data.opSetInput(newop,b,1);
  data.opInsertBefore(newop,op);
  data.opSetInput(op,newout,0);
  data.opSetInput(op,data.newConstant(op->getOut()->getSize()-newout->getSize() ,0),1);
  return 1;
}

/// \class RuleSubZext
/// \brief Simplify INT_ZEXT applied to SUBPIECE expressions
///
/// This performs:
///  - `zext( sub( V, 0) )        =>    V & mask`
///  - `zext( sub( V, c)          =>    (V >> c*8) & mask`
///  - `zext( sub( V, c) >> d )   =>    (V >> (c*8+d)) & mask`
void RuleSubZext::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ZEXT);
}

int4 RuleSubZext::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *subvn,*basevn,*constvn;
  PcodeOp *subop;
  uintb val;

  if (op->getOut()->getSize() > sizeof(uintb)) return 0; // No array masking is allowed
  subvn = op->getIn(0);
  if (!subvn->isWritten()) return 0;
  subop = subvn->getDef();
  if (subop->code() == CPUI_SUBPIECE) {
    basevn = subop->getIn(0);
    if (basevn->isFree()) return 0;
    if (basevn->getSize() != op->getOut()->getSize()) return 0;	// Truncating then extending to same size
    if (basevn->getSize() > sizeof(uintb))
      return 0;
    if (subop->getIn(1)->getOffset() != 0) { // If truncating from middle
      if (subvn->loneDescend() != op) return 0; // and there is no other use of the truncated value
      Varnode *newvn = data.newUnique(basevn->getSize(),(Datatype *)0);
      constvn = subop->getIn(1);
      uintb rightVal = constvn->getOffset() * 8;
      data.opSetInput(op,newvn,0);
      data.opSetOpcode(subop,CPUI_INT_RIGHT); // Convert the truncation to a shift
      data.opSetInput(subop,data.newConstant(constvn->getSize(),rightVal),1);
      data.opSetOutput(subop,newvn);
    }
    else
      data.opSetInput(op,basevn,0); // Otherwise, bypass the truncation entirely
    val = calc_mask(subvn->getSize());
    constvn = data.newConstant(basevn->getSize(),val);
    data.opSetOpcode(op,CPUI_INT_AND);
    data.opInsertInput(op,constvn,1);
    return 1;
  }
  else if (subop->code() == CPUI_INT_RIGHT) {
    PcodeOp *shiftop = subop;
    if (!shiftop->getIn(1)->isConstant()) return 0;
    Varnode *midvn = shiftop->getIn(0);
    if (!midvn->isWritten()) return 0;
    subop = midvn->getDef();
    if (subop->code() != CPUI_SUBPIECE) return 0;
    basevn = subop->getIn(0);
    if (basevn->isFree()) return 0;
    if (basevn->getSize() != op->getOut()->getSize()) return 0;	// Truncating then extending to same size
    if (midvn->loneDescend() != shiftop) return 0;
    if (subvn->loneDescend() != op) return 0;
    val = calc_mask(midvn->getSize()); // Mask based on truncated size
    uintb sa = shiftop->getIn(1)->getOffset(); // The shift shrinks the mask even further
    val >>= sa;
    sa += subop->getIn(1)->getOffset() * 8; // The total shift = truncation + small shift
    Varnode *newvn = data.newUnique(basevn->getSize(),(Datatype *)0);
    data.opSetInput(op,newvn,0);
    data.opSetInput(shiftop,basevn,0); // Shift the full value, instead of the truncated value
    data.opSetInput(shiftop,data.newConstant(shiftop->getIn(1)->getSize(),sa),1);	// by the combined amount
    data.opSetOutput(shiftop,newvn);
    constvn = data.newConstant(basevn->getSize(),val);
    data.opSetOpcode(op,CPUI_INT_AND); // Turn the ZEXT into an AND
    data.opInsertInput(op,constvn,1); // With the appropriate mask
    return 1;
  }
  return 0;
}

/// \class RuleSubCancel
/// \brief Simplify composition of SUBPIECE with INT_ZEXT, INT_SEXT, and INT_AND
///
/// The SUBPIECE may partially or wholly cancel out the extension or INT_AND:
///  - `sub(zext(V),0)  =>  zext(V)`
///  - `sub(zext(V),0)  =>  V`
///  - `sub(zext(V),0)  =>  sub(V)`
///  - `sub(V & 0xffff, 0)  =>  sub(V)`
///
/// This also supports the corner case:
///  - `sub(zext(V),c)  =>  0  when c is big enough`
void RuleSubCancel::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleSubCancel::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *base,*thruvn;
  int4 offset,outsize,insize,farinsize;
  PcodeOp *extop;
  OpCode opc;

  base = op->getIn(0);
  if (!base->isWritten()) return 0;
  extop = base->getDef();
  opc = extop->code();
  if (opc != CPUI_INT_ZEXT && opc != CPUI_INT_SEXT && opc != CPUI_INT_AND)
    return 0;
  offset = op->getIn(1)->getOffset();
  outsize = op->getOut()->getSize();
  TypeFactory *types = data.getArch()->types;

  if (opc == CPUI_INT_AND) {
    Varnode *cvn = extop->getIn(1);
    if (offset == 0 && cvn->isConstant() && cvn->getOffset() == calc_mask(outsize)) {
      thruvn = extop->getIn(0);
      if (!thruvn->isFree()) {
	data.opSetInput(op,thruvn,0);
	return 1;
      }
    }
    return 0;
  }
  insize = base->getSize();
  farinsize = extop->getIn(0)->getSize();
				
  if (offset == 0) {		// If SUBPIECE is of least sig part
    if (!types->isPresent(outsize)) return 0; // Do not introduce non-specified datatype
    thruvn = extop->getIn(0);	// Something still comes through
    if (thruvn->isFree()) {
      if (thruvn->isConstant() && (insize > sizeof(uintb)) && (outsize == farinsize)) {
	// If we have a constant that is too big to represent, and the elimination is total
	opc = CPUI_COPY;	// go ahead and do elimination
	thruvn = data.newConstant(thruvn->getSize(),thruvn->getOffset()); // with new constant varnode
      }
      else
	return 0; // If original is constant or undefined don't proceed
    }
    else if (outsize == farinsize)
      opc = CPUI_COPY;		// Total elimination of extension
    else if (outsize < farinsize)
      opc = CPUI_SUBPIECE;
  }
  else {
    if (opc==CPUI_INT_ZEXT) { // output contains nothing of original input
      Varnode *cvn = extop->getIn(0);
      if ((farinsize<=offset)||(cvn->isConstant()&&cvn->getOffset()==0)) {
	/*if (!types->isPresent(outsize)) {
	  uint4 insz = types->getPresentUntil(outsize);
	  if (insz<1)
	    insz = 1;	// Fallback to 1 byte type even if not supported
	  Varnode *cvn = data.newConstant(insz,0);
	  PcodeOp *zextop = data.newOp(1,extop->getAddr());
	  opc = CPUI_COPY;
	  thruvn = data.newUniqueOut(outsize,zextop);
	  data.opSetOpcode(zextop,CPUI_INT_ZEXT);
	  data.opSetOutput(zextop,thruvn);
	  data.opSetInput(zextop,cvn,0);
	  data.opInsertBefore(zextop,extop);
	}*/
	opc = CPUI_COPY;		// Nothing but zero coming through
	thruvn = data.newConstant(outsize,0);
      }
      else
	return 0;
    }
    else			// Missing one case here
      return 0;
  }

  data.opSetOpcode(op,opc);	// SUBPIECE <- EXT replaced with one op
  data.opSetInput(op,thruvn,0);

  if (opc != CPUI_SUBPIECE)
    data.opRemoveInput(op,1);	// ZEXT, SEXT, or COPY has only 1 input
  return 1;
}

/// \class RuleShiftSub
/// \brief Simplify SUBPIECE applied to INT_LEFT: `sub( V << 8*k, c)  =>  sub(V,c-k)`
void RuleShiftSub::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleShiftSub::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(0)->isWritten()) return 0;
  PcodeOp *shiftop = op->getIn(0)->getDef();
  if (shiftop->code() != CPUI_INT_LEFT) return 0;
  Varnode *sa = shiftop->getIn(1);
  if (!sa->isConstant()) return 0;
  int4 n = sa->getOffset();
  if ((n & 7) != 0) return 0;		// Must shift by a multiple of 8 bits
  int4 c = op->getIn(1)->getOffset();
  Varnode *vn = shiftop->getIn(0);
  if (vn->isFree()) return 0;
  int4 insize = vn->getSize();
  int4 outsize = op->getOut()->getSize();
  c -= n/8;
  if (c < 0 || c + outsize > insize)	// Check if this is a natural truncation
    return 0;
  data.opSetInput(op,vn,0);
  data.opSetInput(op,data.newConstant(op->getIn(1)->getSize(),c),1);
  return 1;
}

bool RuleHumptyDumpty::pieceForm(PcodeOp *op,Funcdata &data)

{
  uintb pos1,pos2;
  int4 size1,size2;
  Varnode *vn1,*vn2,*root;
  PcodeOp *sub1,*sub2;

  vn1 = op->getIn(0);
  vn2 = op->getIn(1)->getDef()->getIn(0);

  sub1 = vn1->getDef();
  sub2 = vn2->getDef();
  if (sub2 == (PcodeOp *)0) return false;
  if (sub2->code() != CPUI_SUBPIECE) return false;

  root = sub1->getIn(0);
  if (root != sub2->getIn(0)) return false; // pieces of the same whole

  pos1 = sub1->getIn(1)->getOffset();
  pos2 = sub2->getIn(1)->getOffset();
  size1 = vn1->getSize();
  size2 = vn2->getSize();

  if (pos1 != pos2 + size2) return false; // Pieces do not match up

  PcodeOp *pieceop = op->getIn(1)->getDef();
  if ((pos2==0)&&(size1+size2==root->getSize())) {	// Pieced together whole thing
    data.opSetInput(op,root,0);
    data.opSetInput(op,pieceop->getIn(1),1);
  }
  else {	// Pieced together a larger part of the whole
    PcodeOp *sub3 = data.newOp(2,op->getAddr());
    data.opSetOpcode(sub3,CPUI_SUBPIECE);
    data.opSetInput(sub3,root,0);
    data.opSetInput(sub3,data.newConstant(sub2->getIn(1)->getSize(),pos2),1);
    data.newUniqueOut(op->getOut()->getSize() - pieceop->getIn(1)->getSize(),sub3);
    data.opInsertBefore(sub3,op);
    data.opSetInput(op,sub3->getOut(),0);
    data.opSetInput(op,pieceop->getIn(1),1);
  }
  return true;
}

/// \class RuleHumptyDumpty
/// \brief Simplify break and rejoin:  `concat( sub(V,c), sub(V,0) )  =>  V`
///
/// There is also the variation:
///  - `concat( sub(V,c), sub(V,d) )  => sub(V,d)`
///
/// Also piece form:
///  - `concat( sub(V,c), concat( sub(V,0),W ) ) => concat( V,W )`
///  - `concat( sub(V,c), concat( sub(V,d),W ) ) => concat( sub(V,d),W )`
void RuleHumptyDumpty::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PIECE);
}

int4 RuleHumptyDumpty::applyOp(PcodeOp *op,Funcdata &data)

{
  uintb pos1,pos2;
  int4 size1,size2;
  Varnode *vn1,*vn2,*root;
  PcodeOp *sub1,*sub2;
  				// op is something "put together"
  vn1 = op->getIn(0);
  if (!vn1->isWritten()) return 0;
  sub1 = vn1->getDef();
  if (sub1->code() != CPUI_SUBPIECE) return 0; // from piece1
  vn2 = op->getIn(1);
  if (!vn2->isWritten()) return 0;
  sub2 = vn2->getDef();
  if (sub2->code() == CPUI_PIECE) return pieceForm(op, data);
  if (sub2->code() != CPUI_SUBPIECE) return 0; // from piece2

  root = sub1->getIn(0);
  if (root != sub2->getIn(0)) return 0; // pieces of the same whole

  pos1 = sub1->getIn(1)->getOffset();
  pos2 = sub2->getIn(1)->getOffset();
  size1 = vn1->getSize();
  size2 = vn2->getSize();

  if (pos1 != pos2 + size2) return 0; // Pieces do not match up

  if ((pos2==0)&&(size1+size2==root->getSize())) {	// Pieced together whole thing
    data.opRemoveInput(op,1);
    data.opSetInput(op,root,0);
    data.opSetOpcode(op,CPUI_COPY);
  }
  else {			// Pieced together a larger part of the whole
    data.opSetInput(op,root,0);
    data.opSetInput(op,data.newConstant(sub2->getIn(1)->getSize(),pos2),1);
    data.opSetOpcode(op,CPUI_SUBPIECE);
  }
  return 1;
}

/// \class RuleDumptyHump
/// \brief Simplify join and break apart: `sub( concat(V,W), c)  =>  sub(W,c)`
///
/// Depending on c, there are other variants:
///  - `sub( concat(V,W), 0)  =>  W`
///  - `sub( concat(V,W), c)  =>  V`
///  - `sub( concat(V,W), c)  =>  sub(V,c)`
void RuleDumptyHump::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleDumptyHump::applyOp(PcodeOp *op,Funcdata &data)

{				// If we append something to a varnode
				// And then take a subpiece that cuts off what
				// we just appended, treat whole thing as COPY
  Varnode *base,*vn,*vn1,*vn2;
  PcodeOp *pieceop;
  int4 offset,outsize;

  base = op->getIn(0);
  if (!base->isWritten()) return 0;
  pieceop = base->getDef();
  if (pieceop->code() != CPUI_PIECE) return 0;
  offset = op->getIn(1)->getOffset();
  outsize = op->getOut()->getSize();

  vn1 = pieceop->getIn(0);
  vn2 = pieceop->getIn(1);

  if (offset < vn2->getSize()) {	// Sub draws from vn2
    if (offset+outsize > vn2->getSize()) return 0;	// Also from vn1
    vn = vn2;
  }
  else {			// Sub draws from vn1
    vn = vn1;
    offset -= vn2->getSize();	// offset relative to vn1
  }

  if (vn->isFree() && (!vn->isConstant())) return 0;
  if ((offset==0)&&(outsize==vn->getSize())) {
    // Eliminate SUB and CONCAT altogether
    data.opSetOpcode(op,CPUI_COPY);
    data.opRemoveInput(op,1);
    data.opSetInput(op,vn,0);	// Skip over CONCAT
  }
  else {
    // Eliminate CONCAT and adjust SUB
    data.opSetInput(op,vn,0);	// Skip over CONCAT
    data.opSetInput(op,data.newConstant(4,offset),1);
  }
  return 1;
}

/// \class RuleHumptyOr
/// \brief Simplify masked pieces INT_ORed together:  `(V & ff00) | (V & 00ff)  =>  V`
///
/// This supports the more general form:
///  - `(V & W) | (V & X)  =>  V & (W|X)`
void RuleHumptyOr::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_OR);
}

int4 RuleHumptyOr::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn1,*vn2;
  Varnode *a, *b, *c, *d;
  PcodeOp *and1,*and2;

  vn1 = op->getIn(0);
  if (!vn1->isWritten()) return 0;
  vn2 = op->getIn(1);
  if (!vn2->isWritten()) return 0;
  and1 = vn1->getDef();
  if (and1->code() != CPUI_INT_AND) return 0;
  and2 = vn2->getDef();
  if (and2->code() != CPUI_INT_AND) return 0;
  a = and1->getIn(0);
  b = and1->getIn(1);
  c = and2->getIn(0);
  d = and2->getIn(1);
  if (a == c) {
    c = d;		// non-matching are b and d
  }
  else if (a == d) {	// non-matching are b and c
  }
  else if (b == c) {	// non-matching are a and d
    b = a;
    a = c;
    c = d;
  }
  else if (b == d) {	// non-matching are a and c
    b = a;
    a = d;
  }
  else
    return 0;
  // Reaching here a, matches across both ANDs, b and c are the respective other params
  // We know a is not free, because there are at least two references to it
  if (b->isConstant() && c->isConstant()) {
    uintb totalbits = b->getOffset() | c->getOffset();
    if (totalbits == calc_mask(a->getSize())) {
      // Between the two sides, we get all bits of a. Convert to COPY
      data.opSetOpcode(op,CPUI_COPY);
      data.opRemoveInput(op,1);
      data.opSetInput(op,a,0);
    }
    else {
      // We get some bits, but not all.  Convert to an AND
      data.opSetOpcode(op,CPUI_INT_AND);
      data.opSetInput(op,a,0);
      Varnode *newconst = data.newConstant(a->getSize(),totalbits);
      data.opSetInput(op,newconst,1);
    }
  }
  else {
    if (!b->isHeritageKnown()) return 0;
    if (!c->isHeritageKnown()) return 0;
    uintb aMask = a->getNZMask();
    if ((b->getNZMask() & aMask)==0) return 0; // RuleAndDistribute would reverse us
    if ((c->getNZMask() & aMask)==0) return 0; // RuleAndDistribute would reverse us
    PcodeOp *newOrOp = data.newOp(2,op->getAddr());
    data.opSetOpcode(newOrOp,CPUI_INT_OR);
    Varnode *orVn = data.newUniqueOut(a->getSize(),newOrOp);
    data.opSetInput(newOrOp,b,0);
    data.opSetInput(newOrOp,c,1);
    data.opInsertBefore(newOrOp,op);
    data.opSetInput(op,a,0);
    data.opSetInput(op,orVn,1);
    data.opSetOpcode(op,CPUI_INT_AND);
  }
  return 1;
}

/// \class RuleSwitchSingle
/// \brief Convert BRANCHIND with only one computed destination to a BRANCH
void RuleSwitchSingle::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_BRANCHIND);
}

int4 RuleSwitchSingle::applyOp(PcodeOp *op,Funcdata &data)

{
  BlockBasic *bb = op->getParent();
  if (bb->sizeOut() != 1) return 0;

  JumpTable *jt = data.findJumpTable(op);
  if (jt == (JumpTable *)0) return 0;
  if (jt->numEntries() == 0) return 0;
  if (!jt->isLabelled()) return 0; // Labels must be recovered (as this discovers multistage issues)
  Address addr = jt->getAddressByIndex(0);
  bool needwarning = false;
  bool allcasesmatch = false;
  if (jt->numEntries() != 1) {
    needwarning = true;
    allcasesmatch = true;
    for(int4 i=1;i<jt->numEntries();++i) {
      if (jt->getAddressByIndex(i) != addr) {
	allcasesmatch = false;
	break;
      }
    }
  }

  if (!op->getIn(0)->isConstant())
    needwarning = true;
  // If the switch variable is a constant this is final
  // confirmation that the switch has only one destination
  // otherwise this may indicate some other problem

  if (needwarning) {
    ostringstream s;
    s << "Switch with 1 destination removed at ";
    op->getAddr().printRaw(s);
    if (allcasesmatch) {
      s << " : " << dec << jt->numEntries() << " cases all go to same destination";
    }
    data.warningHeader(s.str());
  }
  
  // Convert the BRANCHIND to just a branch
  data.opSetOpcode(op,CPUI_BRANCH);
  // Stick in the coderef of the single jumptable entry
  data.opSetInput(op,data.newCodeRef(addr),0);
  data.removeJumpTable(jt);
  data.getStructure().clear();	// Get rid of any block switch structures
  return 1;
}

/// \class RuleCondNegate
/// \brief Flip conditions to match structuring cues
///
/// Structuring control-flow introduces a preferred meaning to individual
/// branch directions as \b true or \b false, but this may conflict with the
/// natural meaning of the boolean calculation feeding into a CBRANCH.
/// This Rule introduces a BOOL_NEGATE op as necessary to get the meanings to align.
void RuleCondNegate::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_CBRANCH);
}

int4 RuleCondNegate::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *newop;
  Varnode *vn,*outvn;

  if (!op->isBooleanFlip()) return 0;

  vn = op->getIn(1);
  newop = data.newOp(1,op->getAddr());
  data.opSetOpcode(newop,CPUI_BOOL_NEGATE);
  outvn = data.newUniqueOut(1,newop); // Flipped version of varnode
  data.opSetInput(newop,vn,0);
  data.opSetInput(op,outvn,1);
  data.opInsertBefore(newop,op);
  data.opFlipCondition(op);	// Flip meaning of condition
				// NOTE fallthru block is still same status
  return 1;
}

/// \class RuleBoolNegate
/// \brief Apply a set of identities involving BOOL_NEGATE
///
/// The identities include:
///  - `!!V  =>  V`
///  - `!(V == W)  =>  V != W`
///  - `!(V < W)   =>  W <= V`
///  - `!(V <= W)  =>  W < V`
///  - `!(V != W)  =>  V == W`
///
/// This supports signed and floating-point variants as well
void RuleBoolNegate::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_BOOL_NEGATE);
}

int4 RuleBoolNegate::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn;
  PcodeOp *flip_op;
  OpCode opc;
  bool flipyes;

  vn = op->getIn(0);
  if (!vn->isWritten()) return 0;
  flip_op = vn->getDef();

  list<PcodeOp *>::const_iterator iter;

				// ALL descendants must be negates
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter)
    if ((*iter)->code() != CPUI_BOOL_NEGATE) return 0;

  opc = get_booleanflip(flip_op->code(),flipyes);
  if (opc == CPUI_MAX) return 0;
  data.opSetOpcode(flip_op,opc); // Set the negated opcode
  if (flipyes)			// Do we need to reverse the two operands
    data.opSwapInput(flip_op,0,1);
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter)
    data.opSetOpcode(*iter,CPUI_COPY); // Remove all the negates
  return 1;
}

/// \class RuleLess2Zero
/// \brief Simplify INT_LESS applied to extremal constants
///
/// Forms include:
///  - `0 < V  =>  0 != V`
///  - `V < 0  =>  false`
///  - `ffff < V  =>  false`
///  - `V < ffff` =>  V != ffff`
void RuleLess2Zero::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_LESS);
}

int4 RuleLess2Zero::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *lvn,*rvn;
  lvn = op->getIn(0);
  rvn = op->getIn(1);

  if (lvn->isConstant()) {
    if (lvn->getOffset() == 0) {
      data.opSetOpcode(op,CPUI_INT_NOTEQUAL); // All values except 0 are true   ->  NOT_EQUAL
      return 1;
    }
    else if (lvn->getOffset() == calc_mask(lvn->getSize())) {
      data.opSetOpcode(op,CPUI_COPY); // Always false
      data.opRemoveInput(op,1);
      data.opSetInput(op,data.newConstant(1,0),0);
      return 1;
    }
  }
  else if (rvn->isConstant()) {
    if (rvn->getOffset() == 0) {
      data.opSetOpcode(op,CPUI_COPY); // Always false
      data.opRemoveInput(op,1);
      data.opSetInput(op,data.newConstant(1,0),0);
      return 1;
    }
    else if (rvn->getOffset() == calc_mask(rvn->getSize())) { // All values except -1 are true -> NOT_EQUAL
      data.opSetOpcode(op,CPUI_INT_NOTEQUAL);
      return 1;
    }
  }
  return 0;
}

/// \class RuleLessEqual2Zero
/// \brief Simplify INT_LESSEQUAL applied to extremal constants
///
/// Forms include:
///  - `0 <= V  =>  true`
///  - `V <= 0  =>  V == 0`
///  - `ffff <= V  =>  ffff == V`
///  - `V <= ffff` =>  true`
void RuleLessEqual2Zero::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_LESSEQUAL);
}

int4 RuleLessEqual2Zero::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *lvn,*rvn;
  lvn = op->getIn(0);
  rvn = op->getIn(1);

  if (lvn->isConstant()) {
    if (lvn->getOffset() == 0) {
      data.opSetOpcode(op,CPUI_COPY); // All values => true
      data.opRemoveInput(op,1);
      data.opSetInput(op,data.newConstant(1,1),0);
      return 1;
    }
    else if (lvn->getOffset() == calc_mask(lvn->getSize())) {
      data.opSetOpcode(op,CPUI_INT_EQUAL); // No value is true except -1
      return 1;
    }
  }
  else if (rvn->isConstant()) {
    if (rvn->getOffset() == 0) {
      data.opSetOpcode(op,CPUI_INT_EQUAL); // No value is true except 0
      return 1;
    }
    else if (rvn->getOffset() == calc_mask(rvn->getSize())) {
      data.opSetOpcode(op,CPUI_COPY); // All values => true
      data.opRemoveInput(op,1);
      data.opSetInput(op,data.newConstant(1,1),0);
      return 1;
    }
  }
  return 0;
}

/// \brief Get the piece containing the sign-bit
///
/// If the given PcodeOp pieces together 2 Varnodes only one of which is
/// determining the high bit, return that Varnode.
/// \param op is the given PcodeOp
/// \return the Varnode holding the high bit
Varnode *RuleSLess2Zero::getHiBit(PcodeOp *op)

{
  OpCode opc = op->code();
  if ((opc != CPUI_INT_ADD)&&(opc != CPUI_INT_OR)&&(opc != CPUI_INT_XOR))
    return (Varnode *)0;

  Varnode *vn1 = op->getIn(0);
  Varnode *vn2 = op->getIn(1);
  uintb mask = calc_mask(vn1->getSize());
  mask = (mask ^ (mask>>1));	// Only high-bit is set
  uintb nzmask1 = vn1->getNZMask();
  if ((nzmask1!=mask)&&((nzmask1 & mask)!=0)) // If high-bit is set AND some other bit
    return (Varnode *)0;
  uintb nzmask2 = vn2->getNZMask();
  if ((nzmask2!=mask)&&((nzmask2 & mask)!=0))
    return (Varnode *)0;

  if (nzmask1 == mask)
    return vn1;
  if (nzmask2 == mask)
    return vn2;
  return (Varnode *)0;
}

/// \class RuleSLess2Zero
/// \brief Simplify INT_SLESS applied to 0 or -1
///
/// Forms include:
///  - `0 s< V * -1  =>  V s< 0`
///  - `V * -1 s< 0  =>  0 s< V`
///  - `-1 s< SUB(V,hi) => -1 s< V`
///  - `SUB(V,hi) s< 0  => V s< 0`
///  - `-1 s< ~V     => V s< 0`
///  - `~V s< 0      => -1 s< V`
///  - `(V & 0xf000) s< 0   =>  V s< 0`
///  - `-1 s< (V & 0xf000)  =>  -1 s< V
///  - `CONCAT(V,W) s< 0    =>  V s< 0`
///  - `-1 s< CONCAT(V,W)   =>  -1 s> V`
///  - `-1 s< (bool << #8*sz-1)   => !bool`
///
/// There is a second set of forms where one side of the comparison is
/// built out of a high and low piece, where the high piece determines the
/// sign bit:
///  - `-1 s< (hi + lo)  =>  -1 s< hi`
///  - `(hi + lo) s< 0   =>  hi s< 0`
///
void RuleSLess2Zero::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SLESS);
}

int4 RuleSLess2Zero::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *lvn,*rvn,*coeff,*avn;
  PcodeOp *feedOp;
  OpCode feedOpCode;
  lvn = op->getIn(0);
  rvn = op->getIn(1);

  if (lvn->isConstant()) {
    if (!rvn->isWritten()) return 0;
    if (lvn->getOffset() == 0) {
      feedOp = rvn->getDef();
      feedOpCode = feedOp->code();
      if (feedOpCode == CPUI_INT_MULT) {
	coeff = feedOp->getIn(1);
	if (!coeff->isConstant()) return 0;
	if (coeff->getOffset() != calc_mask(coeff->getSize())) return 0;
	avn = feedOp->getIn(0);
	if (avn->isFree()) return 0;
	data.opSetInput(op,avn,0);
	data.opSetInput(op,lvn,1);
	return 1;
      }
    }
    else if (lvn->getOffset() == calc_mask(lvn->getSize())) {
      feedOp = rvn->getDef();
      feedOpCode = feedOp->code();
      Varnode *hibit = getHiBit(feedOp);
      if (hibit != (Varnode *) 0) { // Test for -1 s<  (hi ^ lo)
	if (hibit->isConstant())
	  data.opSetInput(op, data.newConstant(hibit->getSize(), hibit->getOffset()), 1);
	else
	  data.opSetInput(op, hibit, 1);
	data.opSetOpcode(op, CPUI_INT_EQUAL);
	data.opSetInput(op, data.newConstant(hibit->getSize(), 0), 0);
	return 1;
      }
      else if (feedOpCode == CPUI_SUBPIECE) {
	avn = feedOp->getIn(0);
	if (avn->isFree() || avn->getSize() > 8)	// Don't create comparison bigger than 8 bytes
	  return 0;
	if (rvn->getSize() + (int4) feedOp->getIn(1)->getOffset() == avn->getSize()) {
	  // We have -1 s< SUB( avn, #hi )
	  data.opSetInput(op, avn, 1);
	  data.opSetInput(op, data.newConstant(avn->getSize(), calc_mask(avn->getSize())), 0);
	  return 1;
	}
      }
      else if (feedOpCode == CPUI_INT_NEGATE) {
	// We have -1 s< ~avn
	avn = feedOp->getIn(0);
	if (avn->isFree())
	  return 0;
	data.opSetInput(op, avn, 0);
	data.opSetInput(op, data.newConstant(avn->getSize(), 0), 1);
	return 1;
      }
      else if (feedOpCode == CPUI_INT_AND) {
	avn = feedOp->getIn(0);
	if (avn->isFree() || rvn->loneDescend() == (PcodeOp *)0)
	  return 0;

	Varnode *maskVn = feedOp->getIn(1);
	if (maskVn->isConstant()) {
	  uintb mask = maskVn->getOffset();
	  mask >>= (8 * avn->getSize() - 1);	// Fetch sign-bit
	  if ((mask & 1) != 0) {
	    // We have -1 s< avn & 0x8...
	    data.opSetInput(op, avn, 1);
	    return 1;
	  }
	}
      }
      else if (feedOpCode == CPUI_PIECE) {
	// We have -1 s< CONCAT(V,W)
	avn = feedOp->getIn(0);		// Most significant piece
	if (avn->isFree())
	  return 0;
	data.opSetInput(op, avn, 1);
	data.opSetInput(op, data.newConstant(avn->getSize(),calc_mask(avn->getSize())), 0);
	return 1;
      }
      else if (feedOpCode == CPUI_INT_LEFT) {
	coeff = feedOp->getIn(1);
	if (!coeff->isConstant() || coeff->getOffset() != lvn->getSize() * 8 - 1)
	  return 0;
	avn = feedOp->getIn(0);
	if (!avn->isWritten() || !avn->getDef()->isBoolOutput())
	  return 0;
	// We have -1 s< (bool << #8*sz-1)
	data.opSetOpcode(op, CPUI_BOOL_NEGATE);
	data.opRemoveInput(op, 1);
	data.opSetInput(op, avn, 0);
	return 1;
      }
    }
  }
  else if (rvn->isConstant()) {
    if (!lvn->isWritten()) return 0;
    if (rvn->getOffset() == 0) {
      feedOp = lvn->getDef();
      feedOpCode = feedOp->code();
      if (feedOpCode == CPUI_INT_MULT) {
	coeff = feedOp->getIn(1);
	if (!coeff->isConstant()) return 0;
	if (coeff->getOffset() != calc_mask(coeff->getSize())) return 0;
	avn = feedOp->getIn(0);
	if (avn->isFree()) return 0;
	data.opSetInput(op,avn,1);
	data.opSetInput(op,rvn,0);
	return 1;
      }
      else {
	Varnode *hibit = getHiBit(feedOp);
	if (hibit != (Varnode *)0) { // Test for (hi ^ lo) s< 0
	  if (hibit->isConstant())
	    data.opSetInput(op,data.newConstant(hibit->getSize(),hibit->getOffset()),0);
	  else
	    data.opSetInput(op,hibit,0);
	  data.opSetOpcode(op,CPUI_INT_NOTEQUAL);
	  return 1;
	}
	else if (feedOpCode == CPUI_SUBPIECE) {
	  avn = feedOp->getIn(0);
	  if (avn->isFree() || avn->getSize() > 8)	// Don't create comparison greater than 8 bytes
	    return 0;
	  if (lvn->getSize() + (int4)feedOp->getIn(1)->getOffset() == avn->getSize()) {
	    // We have SUB( avn, #hi ) s< 0
	    data.opSetInput(op,avn,0);
	    data.opSetInput(op,data.newConstant(avn->getSize(),0),1);
	    return 1;
	  }
	}
	else if (feedOpCode == CPUI_INT_NEGATE) {
	  // We have ~avn s< 0
	  avn = feedOp->getIn(0);
	  if (avn->isFree()) return 0;
	  data.opSetInput(op,avn,1);
	  data.opSetInput(op,data.newConstant(avn->getSize(),calc_mask(avn->getSize())),0);
	  return 1;
	}
	else if (feedOpCode == CPUI_INT_AND) {
	  avn = feedOp->getIn(0);
	  if (avn->isFree() || lvn->loneDescend() == (PcodeOp *)0)
	    return 0;
	  Varnode *maskVn = feedOp->getIn(1);
	  if (maskVn->isConstant()) {
	    uintb mask = maskVn->getOffset();
	    mask >>= (8 * avn->getSize() - 1);	// Fetch sign-bit
	    if ((mask & 1) != 0) {
	      // We have avn & 0x8... s< 0
	      data.opSetInput(op, avn, 0);
	      return 1;
	    }
	  }
	}
	else if (feedOpCode == CPUI_PIECE) {
	  // We have CONCAT(V,W) s< 0
	  avn = feedOp->getIn(0);		// Most significant piece
	  if (avn->isFree())
	    return 0;
	  data.opSetInput(op, avn, 0);
	  data.opSetInput(op, data.newConstant(avn->getSize(), 0), 1);
	  return 1;
	}
      }
    }
  }
  return 0;
}

/// \class RuleEqual2Zero
/// \brief Simplify INT_EQUAL applied to 0: `0 == V + W * -1  =>  V == W  or  0 == V + c  =>  V == -c`
///
/// The Rule also applies to INT_NOTEQUAL comparisons.
void RuleEqual2Zero::getOpList(vector<uint4> &oplist) const

{
  uint4 list[] = { CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL };
  oplist.insert(oplist.end(),list,list+2);
}

int4 RuleEqual2Zero::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn,*vn2,*addvn;
  Varnode *posvn,*negvn,*unnegvn;
  PcodeOp *addop;
  
  vn = op->getIn(0);
  if ((vn->isConstant())&&(vn->getOffset() == 0))
    addvn = op->getIn(1);
  else {
    addvn = vn;
    vn = op->getIn(1);
    if ((!vn->isConstant())||(vn->getOffset() != 0))
      return 0;
  }
  for(list<PcodeOp *>::const_iterator iter=addvn->beginDescend();iter!=addvn->endDescend();++iter) {
    // make sure the sum is only used in comparisons
    PcodeOp *boolop = *iter;
    if (!boolop->isBoolOutput()) return 0;
  }
  //  if (addvn->lone_descendant() != op) return 0;
  addop = addvn->getDef();
  if (addop==(PcodeOp *)0) return 0;
  if (addop->code() != CPUI_INT_ADD) return 0;
  vn = addop->getIn(0);
  vn2 = addop->getIn(1);
  if (vn2->isConstant()) {
    Address val(vn2->getSpace(),uintb_negate(vn2->getOffset()-1,vn2->getSize()));
    unnegvn = data.newVarnode(vn2->getSize(),val);
    unnegvn->copySymbolIfValid(vn2);	// Propagate any markup
    posvn = vn;
  }
  else {
    if ((vn->isWritten())&&(vn->getDef()->code()==CPUI_INT_MULT)) {
      negvn = vn;
      posvn = vn2;
    }
    else if ((vn2->isWritten())&&(vn2->getDef()->code()==CPUI_INT_MULT)) {
      negvn = vn2;
      posvn = vn;
    }
    else
      return 0;
    uintb multiplier;
    if (!negvn->getDef()->getIn(1)->isConstant()) return 0;
    unnegvn = negvn->getDef()->getIn(0);
    multiplier = negvn->getDef()->getIn(1)->getOffset();
    if (multiplier != calc_mask(unnegvn->getSize())) return 0;
  }
  if (!posvn->isHeritageKnown()) return 0;
  if (!unnegvn->isHeritageKnown()) return 0;

  data.opSetInput(op,posvn,0);
  data.opSetInput(op,unnegvn,1);
  return 1;
}

/// \class RuleEqual2Constant
/// \brief Simplify INT_EQUAL applied to arithmetic expressions
///
/// Forms include:
///  - `V * -1 == c  =>  V == -c`
///  - `V + c == d  =>  V == (d-c)`
///  - `~V == c     =>  V == ~c`
void RuleEqual2Constant::getOpList(vector<uint4> &oplist) const

{
  uint4 list[] = { CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL };
  oplist.insert(oplist.end(),list,list+2);
}

int4 RuleEqual2Constant::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *cvn = op->getIn(1);
  if (!cvn->isConstant()) return 0;

  Varnode *lhs = op->getIn(0);
  if (!lhs->isWritten()) return 0;
  PcodeOp *leftop = lhs->getDef();
  Varnode *a;
  uintb newconst;
  OpCode opc = leftop->code();
  if (opc == CPUI_INT_ADD) {
    Varnode *otherconst = leftop->getIn(1);
    if (!otherconst->isConstant()) return 0;
    newconst = cvn->getOffset() - otherconst->getOffset();
    newconst &= calc_mask(cvn->getSize());
  }
  else if (opc == CPUI_INT_MULT) {
    Varnode *otherconst = leftop->getIn(1);
    if (!otherconst->isConstant()) return 0;
    // The only multiply we transform, is multiply by -1
    if (otherconst->getOffset() != calc_mask(otherconst->getSize())) return 0;
    newconst = cvn->getOffset();
    newconst = (-newconst) & calc_mask(otherconst->getSize());
  }
  else if (opc == CPUI_INT_NEGATE) {
    newconst = cvn->getOffset();
    newconst = (~newconst) & calc_mask(lhs->getSize());
  }
  else
    return 0;

  a = leftop->getIn(0);
  if (a->isFree()) return 0;

  // Make sure the transformed form of a is only used
  // in comparisons of similar form
  list<PcodeOp *>::const_iterator iter;
  for(iter=lhs->beginDescend();iter!=lhs->endDescend();++iter) {
    PcodeOp *dop = *iter;
    if (dop == op) continue;
    if ((dop->code()!=CPUI_INT_EQUAL)&&(dop->code()!=CPUI_INT_NOTEQUAL))
      return 0;
    if (!dop->getIn(1)->isConstant()) return 0;
  }

  data.opSetInput(op,a,0);
  data.opSetInput(op,data.newConstant(a->getSize(),newconst),1);
  return 1;
}

bool RuleUnlinkPtrAdd::unlinkAddOp(PcodeOp *op,Funcdata &data)

{
  if (op == (PcodeOp *)0) return false;
  if (op->code() != CPUI_INT_ADD) return false;

  // Check input ops recursively
  if (unlinkAddOp(op->getIn(0)->getDef(),data)) return true;
  if (unlinkAddOp(op->getIn(1)->getDef(),data)) return true;

  Varnode *outVn = op->getOut();
  if (outVn->hasNoDescend()) return false;
  if (outVn->loneDescend() != (PcodeOp *)0) return false;
  data.splitUses(outVn);
  return true;
}

void RuleUnlinkPtrAdd::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ADD);
}

int4 RuleUnlinkPtrAdd::applyOp(PcodeOp *op,Funcdata &data)

{
  if (RulePtrArith::canApply(op,data)) {
    if (unlinkAddOp(op,data)) return 1;
  }
  if (RuleCancelOutPtrAdd::canApply(op)) {
    if (unlinkAddOp(op,data)) return 1;
  }
  if (RuleInferPointerMult::canApply(op,data)) {
    if (unlinkAddOp(op,data)) return 1;
  }
  if (RuleInferPointerAdd::canApply(op,data)) {
    if (unlinkAddOp(op,data)) return 1;
  }
  return 0;
}

PcodeOp *RuleAllocaPushParams::getCorrespondingLoadOp(PcodeOp *storeop)

{
  PcodeOp *ptrop = storeop->getIn(1)->getDef();
  if (ptrop == (PcodeOp *)0) return (PcodeOp *)0;
  if (ptrop->code() != CPUI_INT_ADD) return (PcodeOp *)0;
  Varnode *basevn = ptrop->getIn(0);
  Varnode *offvn = ptrop->getIn(1);
  if (!offvn->isConstant()) return (PcodeOp *)0;
  BlockBasic *curblock = storeop->getParent();
  list<PcodeOp *>::iterator begiter = curblock->beginOp();
  list<PcodeOp *>::iterator enditer = curblock->endOp();
  // Shift right to given store op
  for(;;) {
    if (begiter == enditer) return (PcodeOp *)0;
    if (storeop == *begiter) break;
    begiter++;
  }
  list<PcodeOp *>::iterator iter = begiter;
  for(;;) {
    iter++;
    if (iter == enditer) break;
    PcodeOp *op = *iter;
    OpCode opc = op->code();
    switch (opc) {
      case CPUI_LOAD:
      {
	if (op->getIn(0)->getOffset() != storeop->getIn(0)->getOffset()) continue;
	PcodeOp *addop = op->getIn(1)->getDef();
	if (addop == (PcodeOp *)0) continue;
	if (addop->code() != CPUI_INT_ADD) continue;
	if (addop->getIn(0) != basevn) continue;
	if (!addop->getIn(1)->isConstant()) continue;
	if (addop->getIn(1)->getOffset() != offvn->getOffset()) continue;
	return op;
      }
      case CPUI_STORE:
      {
	if (op->getIn(0)->getOffset() != storeop->getIn(0)->getOffset()) continue;
	PcodeOp *addop = op->getIn(1)->getDef();
	if (addop == (PcodeOp *)0) continue;
	if (addop->code() != CPUI_INT_ADD) continue;
	if (addop->getIn(0) != basevn) continue;
	if (!addop->getIn(1)->isConstant()) continue;
	if (addop->getIn(1)->getOffset() != offvn->getOffset()) continue;
	break;
      }
      case CPUI_INT_ADD:
	continue;
      default:
	break;
    }
    break;
  }
  return (PcodeOp *)0;
}

void RuleAllocaPushParams::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_STORE);
}

int4 RuleAllocaPushParams::applyOp(PcodeOp *op,Funcdata &data)

{
  if (op->isReturnAddressConstant(data)) {
    PcodeOp *loadop = getCorrespondingLoadOp(op);
    if (loadop != (PcodeOp *)0) {
      Varnode *loadout = loadop->getOut();
      if (!loadout->hasNoDescend()) {
	PcodeOp *loneop = loadout->loneDescend();
	if (loneop == (PcodeOp *)0) return 0;
	OpCode loneopc = loneop->code();
	if (loneop->getAddr().getOffset() != op->getAddr().getOffset()) return 0;
	if (loneopc != CPUI_CALL && loneopc != CPUI_CALLIND) return 0;
      }
    }
    if (!op->getIn(1)->isStackPointerLocated(data)) return 0;
    data.opDestroy(op);
    return 1;
  }
  if (data.isStackGrowsNegative()) {
    Varnode *valvn = op->getIn(2);
    Varnode *ptrvn = op->getIn(1);
    if (!ptrvn->isStackPointerLocated(data)) return 0;
    PcodeOp *ptrop = ptrvn->getDef();
    if (ptrop == (PcodeOp *) 0) return 0;
    if (ptrop->code() != CPUI_INT_ADD) return 0;

    Varnode *offvn = ptrop->getIn(1);
    //Must be pushed to a negative constant
    if (!offvn->isConstant()) return 0;
    intb off = sign_extend(offvn->getOffset(),8*offvn->getSize()-1);
    if (off >= 0) return 0;

    Varnode *basevn = ptrop->getIn(0);
    if (!basevn->isStackPointerLocated(data)) return 0;
    PcodeOp *baseop = basevn->getDef();
    if (baseop == (PcodeOp *)0) return 0;
    if (baseop->code() == CPUI_MULTIEQUAL) {
      // There may be extra pop not fully identified
      // Ignore that and skip to the first definition
      basevn = baseop->getIn(0);
      if (!basevn->isStackPointerLocated(data)) return 0;
      baseop = basevn->getDef();
      if (baseop == (PcodeOp *)0) return 0;
      // TODO check that addition is negative
    }

    if (!baseop->isAllocaShift(data)) return 0;
    PcodeOp *loadop = getCorrespondingLoadOp(op);
    if (loadop == (PcodeOp *)0) return 0;
    Varnode *loadout = loadop->getOut();
    if (loadout->hasNoDescend()) return 0;

    list<PcodeOp *>::const_iterator iter = loadout->beginDescend();
    PcodeOp *callop = *iter;
    if (callop->code() != CPUI_CALL && callop->code() != CPUI_CALLIND) return 0;
    iter++;
    while (iter != loadout->endDescend()) {
      if (*iter != callop) return 0; //Make sure we are reusing for the same call op
      iter++;
    }

    // Simplify load
    data.opRemoveInput(loadop,1);
    data.opSetOpcode(loadop,CPUI_COPY);
    data.opSetInput(loadop,valvn,0);
    // Now get rid of stack store
    data.opDestroy(op);
    return 1;
  }
  return 0;
}

bool RuleCancelOutPtrAdd::checkPointerUsages(PcodeOp *op)

{
  if (op->getOut()->hasPointerUsages()) return true;

  Varnode *invn0 = (Varnode *)0;
  Varnode *invn1 = (Varnode *)0;
  Varnode *invn2 = (Varnode *)0;
  PcodeOp *inop0 = (PcodeOp *)0;
  PcodeOp *inop1 = (PcodeOp *)0;

  switch (op->code()) {
    case CPUI_INT_ADD:
      invn0 = op->getIn(0);
      invn1 = op->getIn(1);

      inop0 = invn0->getDef();
      inop1 = invn1->getDef();

      if (inop0 != (PcodeOp *)0) {
	if (checkPointerUsages(inop0)) return true;
      }
      if (inop1 != (PcodeOp *)0) {
	if (checkPointerUsages(inop1)) return true;
      }
      break;
    case CPUI_INT_MULT:
      invn0 = op->getIn(0);
      invn1 = op->getIn(1);

      inop0 = invn0->getDef();
      inop1 = invn1->getDef();

      if (invn1->isConstant()) {
	if (invn1->getOffset() == calc_mask(invn1->getSize())) {
	  if (inop0 != (PcodeOp *)0) {
	    if (checkPointerUsages(inop0)) return true;
	  }
	}
      }
      break;
  }
  return false;
}

void RuleCancelOutPtrAdd::gatherNegateOps(PcodeOp *op,vector<PcodeOp *> &negateops)

{
  if (op == (PcodeOp *)0) return;
  if (op->code() != CPUI_INT_ADD) return;

  // Search inside input ops recursively
  gatherNegateOps(op->getIn(0)->getDef(),negateops);
  gatherNegateOps(op->getIn(1)->getDef(),negateops);

  PcodeOp *negateOp;
  Varnode *vn;
  negateOp = op->getIn(0)->getDef();
  if (negateOp != (PcodeOp *)0 && negateOp->code() == CPUI_INT_MULT) {
    vn = negateOp->getIn(1);
    if (vn->isConstant()) {
      if (vn->getOffset() == calc_mask(vn->getSize())) {
        negateops.push_back(negateOp);
      }
    }
  }
  negateOp = op->getIn(1)->getDef();
  if (negateOp != (PcodeOp *)0 && negateOp->code() == CPUI_INT_MULT) {
    vn = negateOp->getIn(1);
    if (vn->isConstant()) {
      if (vn->getOffset() == calc_mask(vn->getSize())) {
        negateops.push_back(negateOp);
      }
    }
  }
}

void RuleCancelOutPtrAdd::gatherPossiblePairingOps(Varnode *vn,vector<PcodeOp *> &multis,vector<Varnode *> &others)

{
  PcodeOp *op = vn->getDef();
  if (op == (PcodeOp *)0) {
    others.push_back(vn);
    return;
  }
  OpCode opc = op->code();
  if (opc == CPUI_INT_ADD) {
    gatherPossiblePairingOps(op->getIn(0),multis,others);
    gatherPossiblePairingOps(op->getIn(1),multis,others);
    return;
  }
  if (opc == CPUI_MULTIEQUAL) {
    multis.push_back(op);
  }
  else {
    others.push_back(vn);
  }
}

PcodeOp *RuleCancelOutPtrAdd::getPosition(PcodeOp *op,Varnode *targetVn,bool checkDescendants)

{
  if (op == (PcodeOp *)0) return (PcodeOp *)0;
  if (op->code() != CPUI_INT_ADD) return (PcodeOp *)0;
  if (op->getOut()->hasNoDescend()) return (PcodeOp *)0;
  if (checkDescendants) {
    if (op->getOut()->loneDescend() == (PcodeOp *) 0) {
      return (PcodeOp *) 0;
    }
  }

  Varnode *inVn0 = op->getIn(0);
  Varnode *inVn1 = op->getIn(1);

  if (inVn0 == targetVn) return op;
  if (inVn1 == targetVn) return op;

  // Search in input ops recursively
  PcodeOp *pos0 = getPosition(inVn0->getDef(),targetVn,checkDescendants);
  if (pos0 != (PcodeOp *)0) return pos0;
  PcodeOp *pos1 = getPosition(inVn1->getDef(),targetVn,checkDescendants);
  if (pos1 != (PcodeOp *)0) return pos1;

  return (PcodeOp *)0;
}

bool RuleCancelOutPtrAdd::processOp(PcodeOp *op,PcodeOp *negateOp,PcodeOp *multi,Funcdata &data)

{
  if (negateOp == (PcodeOp *)0) return false;
  if (negateOp->code() != CPUI_INT_MULT) return false;
  Varnode *vn = negateOp->getIn(0);
  if (vn->isConstant() && vn->getOffset() == 0) return false;
  if (multi == (PcodeOp *)0) return false;
  if (multi->code() != CPUI_MULTIEQUAL) return false;

  Varnode *in0 = multi->getIn(0);
  Varnode *in1 = multi->getIn(1);
  PcodeOp *inOp0 = in0->getDef();
  PcodeOp *inOp1 = in1->getDef();
  if (inOp0 == (PcodeOp *)0) return false;
  if (inOp1 == (PcodeOp *)0) return false;
  if (inOp0->code() != CPUI_INT_ADD) return false;
  if (inOp1->code() != CPUI_INT_ADD) return false;
  if (inOp0->getIn(0) != vn) return false;
  if (inOp1->getIn(0)->getDef() != multi) return false;
  Varnode *diff0 = inOp0->getIn(1);
  Varnode *diff1 = inOp1->getIn(1);

  PcodeOp *negatePos = getPosition(op,negateOp->getOut(),true);
  PcodeOp *multiPos = getPosition(op,multi->getOut(),true);
  if (negatePos == (PcodeOp *)0) return false;
  if (multiPos == (PcodeOp *)0) return false;
  int4 negateSlot = negatePos->getSlot(negateOp->getOut());
  int4 multiSlot = multiPos->getSlot(multi->getOut());

  Varnode *zeroVn = data.newConstant(vn->getSize(), 0);
  PcodeOp *addOp0 = data.newOpBefore(inOp0,CPUI_INT_ADD,zeroVn,diff0);
  PcodeOp *addOp1 = data.newOpBefore(inOp1,CPUI_INT_ADD,zeroVn,diff1);
  PcodeOp *multiOp = data.newOpBefore(multi,CPUI_MULTIEQUAL,addOp0->getOut(),addOp1->getOut());
  data.opSetInput(addOp1,multiOp->getOut(),0);

  data.opSetInput(negatePos,zeroVn,negateSlot);
  data.opSetInput(multiPos,multiOp->getOut(),multiSlot);
  return true;
}

void RuleCancelOutPtrAdd::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ADD);
}

int4 RuleCancelOutPtrAdd::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!checkPointerUsages(op)) return 0;

  vector<PcodeOp *> negateops;
  gatherNegateOps(op,negateops);
  vector<Varnode *> others;
  vector<PcodeOp *> multis;
  gatherPossiblePairingOps(op->getOut(),multis,others);

  vector<PcodeOp *>::const_iterator iter;
  for (iter=negateops.begin();iter!=negateops.end();++iter) {
    PcodeOp *negateOp = *iter;
    vector<PcodeOp *>::const_iterator iter;
    for (iter=multis.begin();iter!=multis.end();++iter) {
      if (processOp(op,negateOp,*iter,data)) return 1;
    }
  }
  return 0;
}

bool RuleCancelOutPtrAdd::canProcessOp(PcodeOp *op,PcodeOp *negateOp,PcodeOp *multi)

{
  if (negateOp == (PcodeOp *)0) return false;
  if (negateOp->code() != CPUI_INT_MULT) return false;
  Varnode *vn = negateOp->getIn(0);
  if (vn->isConstant() && vn->getOffset() == 0) return false;
  if (multi == (PcodeOp *)0) return false;
  if (multi->code() != CPUI_MULTIEQUAL) return false;

  Varnode *in0 = multi->getIn(0);
  Varnode *in1 = multi->getIn(1);
  PcodeOp *inOp0 = in0->getDef();
  PcodeOp *inOp1 = in1->getDef();
  if (inOp0 == (PcodeOp *)0) return false;
  if (inOp1 == (PcodeOp *)0) return false;
  if (inOp0->code() != CPUI_INT_ADD) return false;
  if (inOp1->code() != CPUI_INT_ADD) return false;
  if (inOp0->getIn(0) != vn) return false;
  if (inOp1->getIn(0)->getDef() != multi) return false;
  Varnode *diff0 = inOp0->getIn(1);
  Varnode *diff1 = inOp1->getIn(1);

  PcodeOp *negatePos = getPosition(op,negateOp->getOut(),false);
  PcodeOp *multiPos = getPosition(op,multi->getOut(),false);
  if (negatePos == (PcodeOp *)0) return false;
  if (multiPos == (PcodeOp *)0) return false;

  return true;
}

bool RuleCancelOutPtrAdd::canApply(PcodeOp *op)

{
  if (!checkPointerUsages(op)) return false;

  vector<PcodeOp *> negateops;
  gatherNegateOps(op,negateops);
  vector<Varnode *> others;
  vector<PcodeOp *> multis;
  gatherPossiblePairingOps(op->getOut(),multis,others);

  vector<PcodeOp *>::const_iterator iter;
  for (iter=negateops.begin();iter!=negateops.end();++iter) {
    PcodeOp *negateOp = *iter;
    vector<PcodeOp *>::const_iterator iter;
    for (iter=multis.begin();iter!=multis.end();++iter) {
      if (canProcessOp(op,negateOp,*iter)) return true;
    }
  }
  return false;
}

void AddTreeState::clear(void)

{
  multsum = 0;
  nonmultsum = 0;
  biggestNonMultCoeff = 0;
  if (pRelType != (const TypePointerRel *)0) {
    nonmultsum = ((TypePointerRel *)ct)->getPointerOffset();
    nonmultsum &= ptrmask;
  }
  multiple.clear();
  coeff.clear();
  nonmult.clear();
  correct = 0;
  offset = 0;
  valid = true;
  isDistributeUsed = false;
  isSubtype = false;
  distributeOp = (PcodeOp *)0;
}

/// For some forms of pointer (TypePointerRel), the pointer can be interpreted as having two versions
/// of the data-type being pointed to.  This method initializes analysis for the second version, assuming
/// analysis of the first version has failed.
/// \return \b true if there is a second version that can still be analyzed
bool AddTreeState::initAlternateForm(void)

{
  if (pRelType == (const TypePointerRel *)0)
    return false;

  pRelType = (const TypePointerRel *)0;
  baseType = ct->getPtrTo();
  if (baseType->isVariableLength())
    size = 0;		// Open-ended size being pointed to, there will be no "multiples" component
  else
    size = AddrSpace::byteToAddressInt(baseType->getAlignSize(),ct->getWordSize());
  int4 unitsize = AddrSpace::addressToByteInt(1,ct->getWordSize());
  int4 alignSize = baseType->getAlignSize();
  isDegenerate = (alignSize <= unitsize && alignSize > 0);
  preventDistribution = false;
  clear();
  return true;
}

AddTreeState::AddTreeState(Funcdata &d,PcodeOp *op,int4 slot)
  : data(d)
{
  baseOp = op;
  baseSlot = slot;
  biggestNonMultCoeff = 0;
  ptr = op->getIn(slot);
  ct = (const TypePointer *)ptr->getTypeReadFacing(op);
  ptrsize = ptr->getSize();
  ptrmask = calc_mask(ptrsize);
  baseType = ct->getPtrTo();
  multsum = 0;		// Sums start out as zero
  nonmultsum = 0;
  pRelType = (const TypePointerRel *)0;
  if (ct->isFormalPointerRel()) {
    pRelType = (const TypePointerRel *)ct;
    baseType = pRelType->getParent();
    nonmultsum = pRelType->getPointerOffset();
    nonmultsum &= ptrmask;
  }
  if (baseType->isVariableLength())
    size = 0;		// Open-ended size being pointed to, there will be no "multiples" component
  else
    size = AddrSpace::byteToAddressInt(baseType->getAlignSize(),ct->getWordSize());
  correct = 0;
  offset = 0;
  valid = true;		// Valid until proven otherwise
  preventDistribution = false;
  isDistributeUsed = false;
  isSubtype = false;
  distributeOp = (PcodeOp *)0;
  int4 unitsize = AddrSpace::addressToByteInt(1,ct->getWordSize());
  int4 alignSize = baseType->getAlignSize();
  isDegenerate = (alignSize <= unitsize && alignSize > 0);
}

/// \brief Given an offset into the base data-type and array hints find sub-component being referenced
///
/// An explicit offset should target a specific sub data-type,
/// but array indexing may confuse things.  This method passes
/// back the offset of the best matching component, searching among components
/// that are \e nearby the given offset, preferring a matching array element size
/// and a component start that is nearer to the offset.
/// \param off is the given offset into the data-type
/// \param arrayHint if non-zero indicates array access, where the value is the element size
/// \param newoff is used to pass back the actual offset of the selected component
/// \return \b true if a good component match was found
bool AddTreeState::hasMatchingSubType(int8 off,uint4 arrayHint,int8 *newoff) const

{
  Datatype *typeBefore = (Datatype *)0;
  Datatype *typeAfter = (Datatype *)0;

  if (arrayHint == 0)
    return (baseType->getSubType(off,newoff) != (Datatype *)0);

  int8 elSizeBefore;
  int8 offBefore;
  typeBefore = baseType->nearestArrayedComponentBackward(off, &offBefore, &elSizeBefore);
  if (typeBefore != (Datatype *)0) {
    if (arrayHint == 1 || elSizeBefore == arrayHint) {
      int8 sizeAddr = AddrSpace::byteToAddressInt(typeBefore->getSize(),ct->getWordSize());
      if (offBefore >= 0 && offBefore < sizeAddr) {
	// If the offset is \e inside a component with a compatible array, return it.
	*newoff = offBefore;
	return true;
      }
    }
  }
  int8 elSizeAfter;
  int8 offAfter;
  //typeAfter = baseType->nearestArrayedComponentForward(off, &offAfter, &elSizeAfter);
  if (typeBefore == (Datatype *)0 && typeAfter == (Datatype *)0)
    return (baseType->getSubType(off,newoff) != (Datatype *)0);
  if (typeBefore == (Datatype *)0) {
    *newoff = offAfter;
    return true;
  }
  if (typeAfter == (Datatype *)0) {
    *newoff = offBefore;
    return true;
  }

  uint8 distBefore = (offBefore < 0) ? -offBefore : offBefore;
  uint8 distAfter = (offAfter < 0) ? -offAfter : offAfter;
  if (arrayHint != 1) {
    if (elSizeBefore != arrayHint)
      distBefore += 0x1000;
    if (elSizeAfter != arrayHint)
      distAfter += 0x1000;
  }
  *newoff = (distAfter < distBefore) ? offAfter : offBefore;
  return true;
}

/// Examine a CPUI_INT_MULT element in the middle of the add tree. Determine if we treat
/// the output simply as a leaf, or if the multiply needs to be distributed to an
/// additive subtree.  If the Varnode is a leaf of the tree, return \b true if
/// it is considered a multiple of the base data-type size. If the Varnode is the
/// root of another additive sub-tree, return \b true if no sub-node is a multiple.
/// \param vn is the output Varnode of the operation
/// \param op is the CPUI_INT_MULT operation
/// \param treeCoeff is constant multiple being applied to the node
/// \return \b true if there are no multiples of the base data-type size discovered
bool AddTreeState::checkMultTerm(Varnode *vn,PcodeOp *op,uint8 treeCoeff)

{
  Varnode *vnconst = op->getIn(1);
  Varnode *vnterm = op->getIn(0);
  uint8 val;

  if (vnterm->isFree()) {
    valid = false;
    return false;
  }
  if (vnconst->isConstant()) {
    val = (vnconst->getOffset() * treeCoeff) & ptrmask;
    intb sval = sign_extend(val, vn->getSize() * 8 - 1);
    intb rem = (size == 0) ? sval : sval % size;
    if (rem != 0) {
      if ((val >= size) && (size != 0)) {
	valid = false; // Size is too big: pointer type must be wrong
	return false;
      }
      if (!preventDistribution) {
	if (vnterm->isWritten() && vnterm->getDef()->code() == CPUI_INT_ADD) {
	  if (distributeOp == (PcodeOp *)0)
	    distributeOp = op;
	  return spanAddTree(vnterm->getDef(), val);
	}
      }
      uint4 vncoeff = (sval < 0) ? (uint4)-sval : (uint4)sval;
      if (vncoeff > biggestNonMultCoeff)
	biggestNonMultCoeff = vncoeff;
      return true;
    }
    else {
      if (treeCoeff != 1)
	isDistributeUsed = true;
      multiple.push_back(vnterm);
      coeff.push_back(sval);
      return false;
    }
  }
  if (treeCoeff > biggestNonMultCoeff)
    biggestNonMultCoeff = treeCoeff;
  return true;
}

/// If the given Varnode is a constant or multiplicative term, update
/// totals. If the Varnode is additive, traverse its sub-terms.
/// \param vn is the given Varnode term
/// \param treeCoeff is a constant multiple applied to the entire sub-tree
/// \return \b true if the sub-tree rooted at the given Varnode contains no multiples
bool AddTreeState::checkTerm(Varnode *vn,uint8 treeCoeff)

{
  uint8 val;
  PcodeOp *def;

  if (vn == ptr) return false;
  if (vn->isConstant()) {
    val = vn->getOffset() * treeCoeff;
    intb sval = sign_extend(val,vn->getSize()*8-1);
    intb rem = (size == 0) ? sval : (sval % size);
    if (rem!=0) {		// constant is not multiple of size
      if (treeCoeff != 1) {
	// An offset "into" the base data-type makes little sense unless is has subcomponents
	if (baseType->getMetatype() == TYPE_ARRAY || baseType->getMetatype() == TYPE_STRUCT)
	  isDistributeUsed = true;
      }
      nonmultsum += val;
      nonmultsum &= ptrmask;
      return true;
    }
    if (treeCoeff != 1)
      isDistributeUsed = true;
    multsum += val;		// Add multiples of size into multsum
    multsum &= ptrmask;
    return false;
  }
  if (vn->isWritten()) {
    def = vn->getDef();
    if (def->code() == CPUI_INT_ADD) // Recurse
      return spanAddTree(def, treeCoeff);
    if (def->code() == CPUI_COPY) { // Not finished reducing yet
      valid = false;
      return false;
    }
    if (def->code() == CPUI_INT_MULT)	// Check for constant coeff indicating size
      return checkMultTerm(vn, def, treeCoeff);
  }
  else if (vn->isFree()) {
    valid = false;
    return false;
  }
  if (treeCoeff > biggestNonMultCoeff)
    biggestNonMultCoeff = treeCoeff;
  return true;
}

/// Recursively walk the sub-tree from the given root.
/// Terms that are a \e multiple of the base data-type size are accumulated either in
/// the the sum of constant multiples or the container of non-constant multiples.
/// Terms that are a \e non-multiple are accumulated either in the sum of constant
/// non-multiples or the container of non-constant non-multiples. The constant
/// non-multiples are counted twice, once in the sum, and once in the container.
/// This routine returns \b true if no node of the sub-tree is considered a multiple
/// of the base data-type size (or \b false if any node is considered a multiple).
/// \param op is the root of the sub-expression to traverse
/// \param treeCoeff is a constant multiple applied to the entire additive tree
/// \return \b true if the given sub-tree contains no multiple nodes
bool AddTreeState::spanAddTree(PcodeOp *op,uint8 treeCoeff)

{
  bool one_is_non,two_is_non;

  one_is_non = checkTerm(op->getIn(0),treeCoeff);
  if (!valid) return false;
  two_is_non = checkTerm(op->getIn(1),treeCoeff);
  if (!valid) return false;

  if (pRelType != (const TypePointerRel *)0) {
    if (multsum != 0 || nonmultsum >= size || !multiple.empty()) {
      valid = false;
      return false;
    }
  }
  if (one_is_non&&two_is_non) return true;
  if (one_is_non)
    nonmult.push_back(op->getIn(0));
  if (two_is_non)
    nonmult.push_back(op->getIn(1));
  return false;		// At least one of the sides contains multiples
}

/// Make final calculations to determine if a pointer to a sub data-type of the base
/// data-type is being calculated, which will result in a CPUI_PTRSUB being generated.
void AddTreeState::calcSubtype(void)

{
  uint8 tmpoff = (multsum + nonmultsum) & ptrmask;
  if (size == 0 || tmpoff < size)
    offset = tmpoff;
  else {
    // For a sum that falls completely outside the data-type, there is presumably some
    // type of constant term added to an array index either at the current level or lower.
    // If we knew here whether an array of the baseType was possible we could make a slightly
    // better decision.
    intb stmpoff = sign_extend(tmpoff,ptrsize*8-1);
    stmpoff = stmpoff % size;
    if (stmpoff >= 0)
      // We assume the sum is big enough it represents an array index at this level
      offset = (uint8)stmpoff;
    else {
      // For a negative sum, if the baseType is a structure and there is array hints,
      // we assume the sum is an array index at a lower level
      if (baseType->getMetatype() == TYPE_STRUCT && biggestNonMultCoeff != 0 && multsum == 0)
	offset = tmpoff;
      else
	offset = (uint8)(stmpoff + size);
    }
  }
  correct = nonmultsum;				// Non-multiple constants are double counted, correct in final sum
  multsum = (tmpoff - offset) & ptrmask;	// Some extra multiples of size
  if (nonmult.empty()) {
    if ((multsum == 0) && multiple.empty()) {	// Is there anything at all
      valid = false;
      return;
    }
    isSubtype = false;		// There are no offsets INTO the pointer
  }
  else if (baseType->getMetatype() == TYPE_SPACEBASE) {
    int8 offsetbytes = AddrSpace::addressToByteInt(offset,ct->getWordSize()); // Convert to bytes
    int8 extra;
    // Get offset into mapped variable
    if (!hasMatchingSubType(offsetbytes, biggestNonMultCoeff, &extra)) {
      valid = false;		// Cannot find mapped variable but nonmult is non-empty
      return;
    }
    extra = AddrSpace::byteToAddress(extra, ct->getWordSize()); // Convert back to address units
    offset = (offset - extra) & ptrmask;
    correct = (correct - extra) & ptrmask;
    isSubtype = true;
  }
  else if (baseType->getMetatype() == TYPE_STRUCT) {
    intb soffset = sign_extend(offset,ptrsize*8-1);
    int8 offsetbytes = AddrSpace::addressToByteInt(soffset,ct->getWordSize()); // Convert to bytes
    int8 extra;
    // Get offset into field in structure
    if (!hasMatchingSubType(offsetbytes, biggestNonMultCoeff, &extra)) {
      if (offsetbytes < 0 || offsetbytes >= baseType->getSize()) {	// Compare as bytes! not address units
	valid = false; // Out of structure's bounds
	return;
      }
      extra = 0;	// No field, but pretend there is something there
    }
    extra = AddrSpace::byteToAddressInt(extra, ct->getWordSize()); // Convert back to address units
    offset = (offset - extra) & ptrmask;
    correct = (correct - extra) & ptrmask;
    if (pRelType != (TypePointerRel *)0 && offset == pRelType->getPointerOffset()) {
      // offset falls within basic ptrto
      if (!pRelType->evaluateThruParent(0)) {	// If we are not representing offset 0 through parent
	valid = false;				// Use basic (alternate) form
	return;
      }
    }
    isSubtype = true;
  }
  else if (baseType->getMetatype() == TYPE_ARRAY) {
    isSubtype = true;
    correct = (correct - offset) & ptrmask;
    offset = 0;
  }
  else {
    if ((multsum == 0) && multiple.empty()) { // Unless there is something
      // No struct or array, but nonmult is non-empty
      valid = false;                        // There is substructure we don't know about
      return;
    }
    isSubtype = false; // Otherwise there are no offsets INTO the pointer
  }
  if (pRelType != (const TypePointerRel *)0) {
    int4 ptrOff = ((TypePointerRel *)ct)->getPointerOffset();
    offset = (offset - ptrOff) & ptrmask;
    correct = (correct - ptrOff) & ptrmask;
  }
}

/// The data-type from the pointer input (of either a PTRSUB or PTRADD) is propagated to the
/// output of the PcodeOp.
/// \param op is the given PcodeOp
void AddTreeState::assignPropagatedType(PcodeOp *op)

{
  Varnode *vn = op->getIn(0);
  Datatype *inType = vn->getTypeReadFacing(op);
  Datatype *newType = op->getOpcode()->propagateType(inType, op, vn, op->getOut(), 0, -1);
  if (newType != (Datatype *)0)
    op->getOut()->updateType(newType, false, false);
}

/// Construct part of the tree that sums to a multiple of the base data-type size.
/// This value will be added to the base pointer as a CPUI_PTRADD. The final Varnode produced
/// by the sum is returned.  If there are no multiples, null is returned.
/// \return the output Varnode of the multiple tree or null
Varnode *AddTreeState::buildMultiples(void)

{
  Varnode *resNode;

  // Be sure to preserve sign in division below
  // Calc size-relative constant PTR addition
  intb smultsum = sign_extend(multsum,ptrsize*8-1);
  uintb constCoeff = (size==0) ? (uintb)0 : (smultsum / size) & ptrmask;
  if (constCoeff == 0)
    resNode = (Varnode *)0;
  else
    resNode= data.newConstant(ptrsize,constCoeff);
  for(int4 i=0;i<multiple.size();++i) {
    uintb finalCoeff = (size==0) ? (uintb)0 : (coeff[i] / size) & ptrmask;
    Varnode *vn = multiple[i];
    if (finalCoeff != 1) {
      PcodeOp *op = data.newOpBefore(baseOp,CPUI_INT_MULT,vn,data.newConstant(ptrsize,finalCoeff));
      vn = op->getOut();
    }
    if (resNode == (Varnode *)0)
      resNode = vn;
    else {
      PcodeOp *op = data.newOpBefore(baseOp,CPUI_INT_ADD, vn, resNode);
      resNode = op->getOut();
    }
  }
  return resNode;
}

/// Create a subtree summing all the elements that aren't multiples of the base data-type size.
/// Correct for any double counting of non-multiple constants.
/// Return the final Varnode holding the sum or null if there are no terms.
/// \return the final Varnode or null
Varnode *AddTreeState::buildExtra(void)

{
  Varnode *resNode = (Varnode *)0;
  for(int4 i=0;i<nonmult.size();++i) {
    Varnode *vn = nonmult[i];
    if (vn->isConstant()) {
      correct -= vn->getOffset();
      continue;
    }
    if (resNode == (Varnode *)0)
      resNode = vn;
    else {
      PcodeOp *op = data.newOpBefore(baseOp,CPUI_INT_ADD,vn,resNode);
      resNode = op->getOut();
    }
  }
  correct &= ptrmask;
  if (correct != 0) {
    Varnode *vn = data.newConstant(ptrsize,uintb_negate(correct-1,ptrsize));
    if (resNode == (Varnode *)0)
      resNode = vn;
    else {
      PcodeOp *op = data.newOpBefore(baseOp,CPUI_INT_ADD,vn,resNode);
      resNode = op->getOut();
    }
  }
  return resNode;
}

/// The base data-type being pointed to is unit sized (or smaller).  Everything is a multiple, so an ADD
/// is always converted into a PTRADD.
/// \return \b true if the degenerate transform was applied
bool AddTreeState::buildDegenerate(void)

{
  if (baseType->getAlignSize() < ct->getWordSize())
    // If the size is really less than scale, there is
    // probably some sort of padding going on
    return false;	// Don't transform at all
  if (baseOp->getOut()->getTypeDefFacing()->getMetatype() != TYPE_PTR)	// Make sure pointer propagates thru INT_ADD
    return false;
  if (RulePtraddUndo::canProcessOp(baseOp,1,baseSlot,data))
    // If it will be erased later on
    return false;	// Don't transform at all
  vector<Varnode *> newparams;
  int4 slot = baseOp->getSlot(ptr);
  newparams.push_back( ptr );
  newparams.push_back( baseOp->getIn(1-slot) );
  newparams.push_back( data.newConstant(ct->getSize(),1));
  data.opSetAllInput(baseOp,newparams);
  data.opSetOpcode(baseOp,CPUI_PTRADD);
  return true;
}

/// \return \b true if a transform was applied
bool AddTreeState::apply(void)

{
  if (isDegenerate)
    return buildDegenerate();
  spanAddTree(baseOp,1);
  if (!valid) return false;		// Were there any show stoppers
  if (distributeOp != (PcodeOp *)0 && !isDistributeUsed) {
    clear();
    preventDistribution = true;
    spanAddTree(baseOp,1);
  }
  calcSubtype();
  if (!valid) return false;
  while(valid && distributeOp != (PcodeOp *)0) {
    if (!data.distributeIntMultAdd(distributeOp)) {
      valid = false;
      break;
    }
    // Collapse any z = (x * #c) * #d  expressions produced by the distribute
    data.collapseIntMultMult(distributeOp->getIn(0));
    data.collapseIntMultMult(distributeOp->getIn(1));
    clear();
    spanAddTree(baseOp,1);
    if (distributeOp != (PcodeOp *)0 && !isDistributeUsed) {
      clear();
      preventDistribution = true;
      spanAddTree(baseOp,1);
    }
    calcSubtype();
  }
  if (!valid) {
    // Distribution transforms were made
    ostringstream s;
    s << "Problems distributing in pointer arithmetic at ";
    baseOp->getAddr().printRaw(s);
    data.warningHeader(s.str());
    return true;
  }
  buildTree();
  return true;
}

/// \return \b true if a transform can be applied
bool AddTreeState::canApply(void)

{
  if (isDegenerate) {
    if (baseType->getAlignSize() < ct->getWordSize()) {
      // If the size is really less than scale, there is
      // probably some sort of padding going on
      return false;        // Don't transform at all
    }
    if (baseOp->getOut()->getTypeDefFacing()->getMetatype() != TYPE_PTR) {
      // Make sure pointer propagates thru INT_ADD
      return false;
    }
    return true;
  }
  spanAddTree(baseOp,1);
  if (!valid) return false;		// Were there any show stoppers
  if (distributeOp != (PcodeOp *)0 && !isDistributeUsed) {
    clear();
    preventDistribution = true;
    spanAddTree(baseOp,1);
  }
  calcSubtype();
  if (!valid) return false;
  return true;
}

/// The original ADD tree has been successfully split into \e multiple and
/// \e non-multiple pieces.  Rewrite the tree as a pointer expression, putting
/// any \e multiple pieces into a PTRADD operation, creating a PTRSUB if a sub
/// data-type offset has been calculated, and preserving and remaining terms.
void AddTreeState::buildTree(void)

{
  Varnode *multNode = buildMultiples();
  Varnode *extraNode = buildExtra();
  PcodeOp *newop = (PcodeOp *)0;

  // Create PTRADD portion of operation
  if (multNode != (Varnode *)0) {
    newop = data.newOpBefore(baseOp,CPUI_PTRADD,ptr,multNode,data.newConstant(ptrsize,size));
    if (ptr->getType()->needsResolution())
      data.inheritResolution(ptr->getType(),newop, 0, baseOp, baseSlot);
    if (data.isTypeRecoveryExceeded())
      assignPropagatedType(newop);
    multNode = newop->getOut();
  }
  else
    multNode = ptr;		// Zero multiple terms

  // Create PTRSUB portion of operation
  if (isSubtype) {
    newop = data.newOpBefore(baseOp,CPUI_PTRSUB,multNode,data.newConstant(ptrsize,offset));
    // Need to add a check to not inherit any pointer types for multiplier node
    //if (multNode->getType()->needsResolution())
      //data.inheritResolution(multNode->getType(),newop, 0, baseOp, baseSlot);
    if (data.isTypeRecoveryExceeded())
      assignPropagatedType(newop);
    if (size != 0)
      newop->setStopTypePropagation();
    multNode = newop->getOut();
  }

  // Add back in any remaining terms
  if (extraNode != (Varnode *)0)
    newop = data.newOpBefore(baseOp,CPUI_INT_ADD,multNode,extraNode);

  if (newop == (PcodeOp *)0) {
    // This should never happen
    data.warning("ptrarith problems",baseOp->getAddr());
    return;
  }
  data.opSetOutput(newop,baseOp->getOut());
  data.opDestroy(baseOp);
}

/// \brief Test for other pointers in the ADD tree above the given op that might be a preferred base
///
/// This tests the condition of RulePushPtr on the node immediately above the given putative base pointer
/// \param op is the given op
/// \param slot is the input slot of the putative base pointer
/// \return \b true if the indicated slot holds the preferred pointer
bool RulePtrArith::verifyPreferredPointer(PcodeOp *op,int4 slot)

{
  Varnode *vn = op->getIn(slot);
  if (!vn->isWritten()) return true;
  PcodeOp *preOp = vn->getDef();
  if (preOp->code() != CPUI_INT_ADD) return true;
  int preslot = 0;
  if (preOp->getIn(preslot)->getTypeReadFacing(preOp)->getMetatype() != TYPE_PTR) {
    preslot = 1;
    if (preOp->getIn(preslot)->getTypeReadFacing(preOp)->getMetatype() != TYPE_PTR)
      return true;
  }
  return (1 != evaluatePointerExpression(preOp, preslot));	// Does earlier varnode look like the base pointer
}

/// \brief Determine if pointer op is valid by doing several sanity checks
/// All invalid cases are written from new line for the sake of readability
///
/// \param op is the root INT_ADD op
/// \param ptrBase input of op under preffered slot
/// \param ptrOther another input of op
/// \return true if all checks passed
bool RulePtrArith::isPointerOpValid(PcodeOp *op,Varnode *ptrBase,Varnode *ptrOther)

{
  // Datatypes to inspect
  Datatype *assumedDatatypePtr = (Datatype *)0;
  Datatype *containingDatatypePtr = (Datatype *)0;
  Datatype *intermediateDatatype = (Datatype *)0;
  Datatype *assumedDatatype = (Datatype *)0;
  Datatype *containingDatatype = (Datatype *)0;
  Datatype *derivedDatatype = (Datatype *)0;

  Varnode *in0,*in1;
  uintb in1const;
  type_metatype meta = TYPE_UNKNOWN;
  sub_metatype submeta = SUB_UNKNOWN;

  PcodeOp *ptrBaseOp = ptrBase->getDef();
  if (ptrBaseOp == (PcodeOp *)0) return true;

  if (ptrBaseOp->code() == CPUI_PTRSUB) {
    in0 = ptrBaseOp->getIn(0);
    in1 = ptrBaseOp->getIn(1);
    if (!in1->isConstant())
      return false;
    in1const = in1->getOffset();
    assumedDatatypePtr = ptrBase->getTypeReadFacing(op);
    intermediateDatatype = in0->getTypeReadFacing(ptrBaseOp);

    if (assumedDatatypePtr == intermediateDatatype) {
      if (!ptrOther->isConstant())
	return false;
    }
    else {
      PcodeOp *inop = in0->getDef();
      if (inop == (PcodeOp *)0) return true;
      if (inop->code() == CPUI_PTRADD) {
	meta = assumedDatatypePtr->getMetatype();
	submeta = assumedDatatypePtr->getSubMeta();
	if (assumedDatatypePtr->getMetatype() != TYPE_PTR) return true;
	if (submeta != SUB_PTR && submeta != SUB_PTR_STRUCT) return true;
	assumedDatatype = ((TypePointer *)assumedDatatypePtr)->getPtrTo();
	if (!assumedDatatype->isStructuredType()) return true;

	containingDatatypePtr = inop->getIn(0)->getTypeReadFacing(inop);
	submeta = containingDatatypePtr->getSubMeta();
	if (containingDatatypePtr->getMetatype() != TYPE_PTR) return true;
	if (submeta != SUB_PTR && submeta != SUB_PTR_STRUCT) return true;
	containingDatatype = ((TypePointer *)containingDatatypePtr)->getPtrTo();

	meta = containingDatatype->getMetatype();
	int8 newoff;
	Datatype *derivedDatatype = containingDatatype->getSubType(in1const, &newoff);
	if (derivedDatatype == (Datatype *)0)
	  // Datatype is unknown, so it's concidered not safe to put ptrsub there
	  return false;
	if (!derivedDatatype->isStructuredType())
	  // Datatype is unstructured whereas assumed is, will lead to ptrsub errors
	  return false;
      }
    }
  }

  if (ptrOther->isConstant()) {
    intb offset = sign_extend(ptrOther->getOffset(),8*ptrOther->getSize()-1);
    if (offset < 0) {
      assumedDatatypePtr = ptrBase->getTypeReadFacing(op);
      if (assumedDatatypePtr->getSubMeta() != SUB_PTRREL) return true;
      if (assumedDatatypePtr->isFormalPointerRel()) return true;
      assumedDatatype = ((TypePointer *)assumedDatatypePtr)->getPtrTo();
      int4 size = assumedDatatype->getSize();
      if (size != 0) {
	if ((-offset) % size != 0) {
	  // This prevents transformation which will break propagation in case of ephemeral relative pointers
	  return false;
	}
      }
    }
  }
  return true;
}

/// \brief Determine if the expression rooted at the given INT_ADD operation is ready for conversion
///
/// Converting an expression of INT_ADDs into PTRSUBs and PTRADDs requires that the base pointer
/// be at the root of the expression tree.  This method evaluates whether given root has the base
/// pointer at the bottom.  If not, a \e push transform needs to be performed before RulePtrArith can apply.
/// This method returns a command code:
///    -  0 if no action should be taken, the expression is not fully linked or should not be converted
///    -  1 if a \e push action should be taken, prior to conversion
///    -  2 if the pointer arithmetic conversion can proceed
/// \param op is the given INT_ADD
/// \param slot is the index of the pointer
/// \return the command code
int4 RulePtrArith::evaluatePointerExpression(PcodeOp *op,int4 slot)

{
  int4 res = 1;		// Assume we are going to push
  int4 count = 0;	// Count descendants
  Varnode *ptrOther = op->getIn(1 - slot);
  Varnode *ptrBase = op->getIn(slot);
  if (ptrBase->isFree() && !ptrBase->isConstant())
    return 0;
  if (!isPointerOpValid(op,ptrBase,ptrOther))
    return 0;
  if (ptrOther->getTypeReadFacing(op)->getMetatype() == TYPE_PTR)
    res = 2;
  Varnode *outVn = op->getOut();
  list<PcodeOp *>::const_iterator iter;
  for(iter=outVn->beginDescend();iter!=outVn->endDescend();++iter) {
    PcodeOp *decOp = *iter;
    count += 1;
    OpCode opc = decOp->code();
    if (opc == CPUI_INT_ADD) {
      Varnode *otherVn = decOp->getIn(1 - decOp->getSlot(outVn));
      if (otherVn->isFree() && !otherVn->isConstant())
	return 0;	// No action if the data-flow isn't fully linked
      if (otherVn->getTypeReadFacing(decOp)->getMetatype() == TYPE_PTR)
	res = 2;	// Do not push in the presence of other pointers
    }
    else if ((opc == CPUI_LOAD || opc == CPUI_STORE) && decOp->getIn(1) == outVn) {	// If use is as pointer for LOAD or STORE
      if (ptrBase->isSpacebase() && (ptrBase->isInput()||(ptrBase->isConstant())) &&
          (ptrOther->isConstant()))
	return 0;
      res = 2;
    }
    else {	// Any other op besides ADD, do not push
      res = 2;
    }
  }
  if (count == 0)
    return 0;
  if (count > 1) {
    if (outVn->isSpacebase())
      return 0;		// For the RESULT to be a spacebase pointer it must have only 1 descendant
//    res = 2;		// Uncommenting this line will not let pointers get pushed to multiple descendants
  }
  return res;
}

// Simplify constants multiplication via 2 CPUI_INT_MULT
bool RulePtrArith::replaceMultiplier(PcodeOp *op,Funcdata &data)

{
  if (op == (PcodeOp *)0) return false;
  if (op->code() != CPUI_INT_MULT) return false;
  Varnode *vn0 = op->getIn(0);
  Varnode *vn1 = op->getIn(1);
  if (!vn1->isConstant()) return false;
  PcodeOp *otherop = vn0->getDef();
  if (otherop == (PcodeOp *)0) return false;
  if (otherop->code() == CPUI_INT_ZEXT) {
    otherop = otherop->getIn(0)->getDef();
  }
  if (otherop == (PcodeOp *)0) return false;
  if (otherop->code() != CPUI_INT_MULT) return false;
  if (!otherop->getIn(1)->isConstant()) return false;
  Varnode *input = otherop->getIn(0);
  data.opSetInput(op,input,0);
  uintb off = vn1->getOffset()*otherop->getIn(1)->getOffset();
  input = data.newConstant(vn1->getSize(),off);
  data.opSetInput(op,input,1);
  return true;
}

bool RulePtrArith::preprocess(PcodeOp *op,Funcdata &data)

{
  if (op == (PcodeOp *)0) return false;
  if (op->code() != CPUI_INT_ADD) return false;

  // Check input ops recursively
  if (preprocess(op->getIn(0)->getDef(),data)) return true;
  if (preprocess(op->getIn(1)->getDef(),data)) return true;

  // Ensure that all constant multipliers are propagated here
  if (replaceMultiplier(op->getIn(0)->getDef(),data)) return true;
  if (replaceMultiplier(op->getIn(1)->getDef(),data)) return true;

  return false;
}

/// \class RulePtrArith
/// \brief Transform pointer arithmetic
///
/// Rule for converting integer arithmetic to pointer arithmetic.
/// A string of INT_ADDs is converted into PTRADDs and PTRSUBs.
///
/// Basic algorithm:
/// Starting with a varnode of known pointer type (with known size):
///  - Generate list of terms added to pointer
///  - Find all terms that are multiples of pointer size
///  - Find all terms that are smaller than pointer size
///  - Find sum of constants smaller than pointer size
///  - Multiples get converted to PTRADD
///  - Constant gets converted to nearest subfield offset
///  - Everything else is just added back on
///
/// We need to be wary of most things being in the units of the
/// space being pointed at. Type calculations are always in bytes
/// so we need to convert between space units and bytes.
void RulePtrArith::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ADD);
}

int4 RulePtrArith::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 slot;
  const Datatype *ct = (const Datatype *)0; // Unnecessary initialization

  if (!data.hasTypeRecoveryStarted()) return 0;

  for(slot=0;slot<op->numInput();++slot) { // Search for pointer type
    ct = op->getIn(slot)->getTypeReadFacing(op);
    if (ct->getMetatype() == TYPE_PTR) break;
  }
  if (slot == op->numInput()) return 0;
  if (evaluatePointerExpression(op, slot) != 2) return 0;
  if (!verifyPreferredPointer(op, slot)) return 0;

  // Skip until RuleUnlinkPtrAdd splits uses
  if (op->getOut()->loneDescend() == (PcodeOp *)0) return 0;

  AddTreeState state(data,op,slot);
  if (state.apply()) return 1;
  if (state.initAlternateForm()) {
    if (state.apply()) return 1;
  }
  return 0;
}

bool RulePtrArith::canApply(PcodeOp *op,Funcdata &data)

{
  int4 slot;
  const Datatype *ct = (const Datatype *)0; // Unnecessary initialization

  if (!data.hasTypeRecoveryStarted()) return false;

  for(slot=0;slot<op->numInput();++slot) { // Search for pointer type
    ct = op->getIn(slot)->getTypeReadFacing(op);
    if (ct->getMetatype() == TYPE_PTR) break;
  }
  if (slot == op->numInput()) return false;
  if (evaluatePointerExpression(op, slot) != 2) return false;
  if (!verifyPreferredPointer(op, slot)) return false;

  AddTreeState state(data,op,slot);
  if (state.canApply()) return true;
  if (state.initAlternateForm()) {
    if (state.canApply()) return true;
  }
  return false;
}

/// \brief Prevents infinite loop in cases when struct contains pointers to the same type as itself
///
/// \param op is main op
/// \param baseType is type retrieved from main op by input 1
/// \param subType is type at zeroth offset of baseType fetched from database
/// \return true if repeats to itself or similar
bool RuleStructOffset0::isRepeated(PcodeOp *op,Datatype *baseType,Datatype *subType)

{
  // Checks that this is another PTRSUB
  PcodeOp *def = op->getIn(1)->getDef();
  if (def == (PcodeOp *)0) return false;
  OpCode opc = def->code();
  if (opc != CPUI_PTRSUB) return false;
  // Checks that this is a zero-offset PTRSUB
  Varnode *in1Vn = def->getIn(1);
  if (!in1Vn->isConstant()) return false;
  if (in1Vn->getOffset() != 0) return false;
  Varnode *in0Vn = def->getIn(0);
  Varnode *outVn = def->getOut();
  Datatype *in0Type = in0Vn->getTypeReadFacing(def);
  Datatype *outType = outVn->getTypeDefFacing();
  // Already has one PTRSUB, why need more if datatype is the same?
  if (in0Type == outType) {
    return true;
  }
  if (subType == (Datatype *)0) return false;
  type_metatype subMeta = subType->getMetatype();
  if (subMeta == TYPE_PTR) {
    Datatype *subBase = ((TypePointer *) subType)->getPtrTo();
    if (subBase == baseType)
      return true;
  }
  if (subMeta == TYPE_STRUCT) {
    return false;
  }
  return false;
}

/// \class RuleStructOffset0
/// \brief Convert a LOAD or STORE to the first element of a structure to a PTRSUB.
///
/// Data-type propagation may indicate we have a pointer to a structure, but
/// we really need a pointer to the first element of the structure. We can tell
/// this is happening if we load or store too little data from the pointer, interpreting
/// it as a pointer to the structure.  This Rule then applies a PTRSUB(,0) to the pointer
/// to drill down to the first component.
void RuleStructOffset0::getOpList(vector<uint4> &oplist) const

{
  uint4 list[]={ CPUI_LOAD, CPUI_STORE };
  oplist.insert(oplist.end(),list,list+2);
}
  
int4 RuleStructOffset0::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 movesize;			// Number of bytes being moved by load or store
  Datatype *baseType = (Datatype *)0;
  int8 offset = 0;

  if (!data.hasTypeRecoveryStarted()) return 0;
  if (op->code()==CPUI_LOAD) {
    movesize = op->getOut()->getSize();
  }
  else if (op->code()==CPUI_STORE) {
    movesize = op->getIn(2)->getSize();
  }
  else
    return 0;

  Varnode *ptrVn = op->getIn(1);
  Datatype *ct = ptrVn->getTypeReadFacing(op);
  if (ct->getMetatype() != TYPE_PTR) return 0;

  if (op->isEventualFormalPointerRel()) {
    TypePointerRel *ptRel = (TypePointerRel *)ct;
    baseType = ptRel->getParent();
    if (baseType->getMetatype() != TYPE_STRUCT) return 0;
    int8 iOff = ptRel->getPointerOffset();
    iOff = AddrSpace::addressToByteInt(iOff, ptRel->getWordSize());
    if (iOff >= baseType->getSize()) return 0;
    offset = iOff;
  }
  else {
    baseType = ((TypePointer *)ct)->getPtrTo();
  }

  if (baseType->getMetatype() == TYPE_STRUCT) {
    if (baseType->getSize() < movesize) return 0;		// Moving something bigger than entire structure
    if (offset == 0) {						// Only check if offset is 0.
								// Otherwise there will be always an extra ptrsub
      Datatype *subType = baseType->getSubType(offset,&offset); // Get field at pointer's offset
      if (subType==(Datatype *)0) return 0;
      if (subType->getSize() < movesize) return 0;		// Subtype is too small to handle LOAD/STORE
      if (isRepeated(op,baseType,subType)) return 0;		// Does not contain anything within
      								// In fact this will lead to repeated datatypes
								// between both input0 and output of newly created PTRSUB
    }
    else {
      if (isRepeated(op,baseType,(Datatype *)0)) return 0;
    }
  }
  else if (baseType->getMetatype() == TYPE_ARRAY) {
    if (baseType->getSize() < movesize)
      return 0;				// Moving something bigger than entire array
    if (baseType->getSize() == movesize) {	// Moving something the size of entire array
      if (((TypeArray *)baseType)->numElements() != 1)
	return 0;
      // If we reach here, moving something size of single element. Assume this is normal access.
    }
  }
  else
    return 0;

  PcodeOp *newop = data.newOpBefore(op,CPUI_PTRSUB,ptrVn,data.newConstant(ptrVn->getSize(),0));
  if (ptrVn->getType()->needsResolution())
    data.inheritResolution(ptrVn->getType(),newop, 0, op, 1);
  newop->setStopTypePropagation();
  data.opSetInput(op,newop->getOut(),1);
  return 1;
}

/// \brief Build a duplicate of the given Varnode as an output of a PcodeOp, preserving the storage address if possible
///
/// If the Varnode is already a \e unique or is \e addrtied
/// \param vn is the given Varnode
/// \param op is the PcodeOp to which the duplicate should be an output
/// \param data is the function to add the duplicate to
/// \return the duplicate Varnode
Varnode *RulePushPtr::buildVarnodeOut(Varnode *vn,PcodeOp *op,Funcdata &data)

{
  if (vn->isAddrTied() || vn->getSpace()->getType() == IPTR_INTERNAL)
    return data.newUniqueOut(vn->getSize(), op);
  return data.newVarnodeOut(vn->getSize(), vn->getAddr(), op);
}

/// \brief Generate list of PcodeOps that need to be duplicated as part of pushing the pointer
///
/// If the pointer INT_ADD is duplicated as part of the push, some of the operations building
/// the offset to the pointer may also need to be duplicated.  Identify these and add them
/// to the result list.
/// \param reslist is the result list to be populated
/// \param vn is the offset Varnode being added to the pointer
void RulePushPtr::collectDuplicateNeeds(vector<PcodeOp *> &reslist,Varnode *vn)

{
  for(;;) {
    if (!vn->isWritten()) return;
    if (vn->isAutoLive()) return;
    if (vn->loneDescend() == (PcodeOp *)0) return;	// Already has multiple descendants
    PcodeOp *op = vn->getDef();
    OpCode opc = op->code();
    if (opc == CPUI_INT_ZEXT || opc == CPUI_INT_SEXT || opc == CPUI_INT_2COMP)
      reslist.push_back(op);
    else if (opc == CPUI_INT_MULT) {
      if (op->getIn(1)->isConstant())
	reslist.push_back(op);
    }
    else
      return;
    vn = op->getIn(0);
  }
}

/// \brief Duplicate the given PcodeOp so that the outputs have only 1 descendant
///
/// Run through the descendants of the PcodeOp output and create a duplicate
/// of the PcodeOp right before the descendant.  We assume the PcodeOp either has
/// a single input, or has 2 inputs where the second is a constant.
/// The (original) PcodeOp is destroyed.
/// \param op is the given PcodeOp to duplicate
/// \param data is function to build duplicates in
void RulePushPtr::duplicateNeed(PcodeOp *op,Funcdata &data)

{
  Varnode *outVn = op->getOut();
  Varnode *inVn = op->getIn(0);
  int num = op->numInput();
  OpCode opc = op->code();
  list<PcodeOp *>::const_iterator iter = outVn->beginDescend();
  do {
    PcodeOp *decOp = *iter;
    int4 slot = decOp->getSlot(outVn);
    PcodeOp *newOp = data.newOp(num, op->getAddr());	// Duplicate op associated with original address
    Varnode *newOut = buildVarnodeOut(outVn, newOp, data);	// Result contained in original storage
    newOut->updateType(outVn->getType(),false,false);
    data.opSetOpcode(newOp, opc);
    data.opSetInput(newOp, inVn, 0);
    if (num > 1)
      data.opSetInput(newOp, op->getIn(1), 1);
    data.opSetInput(decOp, newOut, slot);
    data.opInsertBefore(newOp, decOp);
    iter = outVn->beginDescend();
  } while(iter != outVn->endDescend());
  data.opDestroy(op);
}

/// \class RulePushPtr
/// \brief Push a Varnode with known pointer data-type to the bottom of its additive expression
///
/// This is part of the normalizing process for pointer expressions. The pointer should be added last
/// onto the expression calculating the offset into its data-type.
void RulePushPtr::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ADD);
}

int4 RulePushPtr::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 slot;
  Varnode *vni = (Varnode *)0;

  if (!data.hasTypeRecoveryStarted()) return 0;
  for(slot=0;slot<op->numInput();++slot) { // Search for pointer type
    vni = op->getIn(slot);
    if (vni->getTypeReadFacing(op)->getMetatype() == TYPE_PTR) break;
  }
  if (slot == op->numInput()) return 0;

  if (RulePtrArith::evaluatePointerExpression(op, slot) != 1) return 0;
  Varnode *vn = op->getOut();
  list<PcodeOp *>::const_iterator iter = vn->beginDescend();
  while (iter != vn->endDescend()) {
    PcodeOp *decop = *iter;
    if (decop->isAllocaShift(data)) return 0;
    iter++;
  }
  Varnode *vnadd2 = op->getIn(1-slot);
  vector<PcodeOp *> duplicateList;
  if (vn->loneDescend() == (PcodeOp *)0)
    collectDuplicateNeeds(duplicateList, vnadd2);

  for(;;) {
    iter = vn->beginDescend();
    if (iter == vn->endDescend()) break;
    PcodeOp *decop = *iter;
    int4 j = decop->getSlot(vn);

    Varnode *vnadd1 = decop->getIn(1-j);
    Varnode *newout;

    // Create new INT_ADD for the intermediate result that didn't exist in original code.
    // We don't associate it with the address of the original INT_ADD
    // We don't preserve the Varnode address of the original INT_ADD
    PcodeOp *newop = data.newOp(2,decop->getAddr());		// Use the later address
    data.opSetOpcode(newop,CPUI_INT_ADD);
    newout = data.newUniqueOut(vnadd1->getSize(),newop);	// Use a temporary storage address

    data.opSetInput(decop,vni,0);
    data.opSetInput(decop,newout,1);

    data.opSetInput(newop,vnadd1,0);
    data.opSetInput(newop,vnadd2,1);

    data.opInsertBefore(newop,decop);
  }
  if (!vn->isAutoLive())
    data.opDestroy(op);
  for(int4 i=0;i<duplicateList.size();++i)
    duplicateNeed(duplicateList[i], data);

  return 1;
}

/// \class RulePtraddUndo
/// \brief Remove PTRADD operations with mismatched data-type information
///
/// It is possible for Varnodes to be assigned incorrect types in the
/// middle of simplification. This leads to incorrect PTRADD conversions.
/// Once the correct type is found, the PTRADD must be converted back to an INT_ADD.
void RulePtraddUndo::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PTRADD);
}

int4 RulePtraddUndo::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *basevn;
  TypePointer *tp;

  int4 size = (int4)op->getIn(2)->getOffset(); // Size the PTRADD thinks we are pointing
  if (!canProcessOp(op,size,0,data)) return 0;
  data.opUndoPtradd(op,false);
  return 1;
}

/// \brief Check if there are problems with ptradd
///
/// \param op is add or ptradd op
/// \param size is size of the pointed-to datatype
/// \param slot is slot of the pointer
/// \param data is the function being analyzed
/// \return true if given ptradd is invalid
bool RulePtraddUndo::canProcessOp(PcodeOp *op,int4 size,int4 slot,Funcdata &data)

{
  if (!data.hasTypeRecoveryStarted()) return false;

  Varnode *basevn;
  TypePointer *tp;

  OpCode opc = op->code();
  if (opc != CPUI_INT_ADD && opc != CPUI_PTRADD) return false;
  basevn = op->getIn(slot);
  tp = (TypePointer *)basevn->getTypeReadFacing(op);
  // Make sure we are still a pointer
  if (tp->getMetatype() != TYPE_PTR) return true;
  Datatype *pt = tp->getPtrTo();
  if (tp->isFormalPointerRel()) {
    // Must use parent datatype
    pt = ((TypePointerRel *)tp)->getParent();
  }
  // of the correct size
  if (pt->getAlignSize()!=AddrSpace::addressToByteInt(size,tp->getWordSize())) return true;
  Varnode *indVn = op->getIn(1-slot);
  // and that index isn't zero
  if (indVn->isConstant() && indVn->getOffset() == 0) return true;
  return false;
}

const int4 RulePtrsubUndo::DEPTH_LIMIT = 8;

/// \class RulePtrsubUndo
/// \brief Remove PTRSUB operations with mismatched data-type information
///
/// Incorrect data-types may be assigned to Varnodes in the middle of simplification. This causes
/// incorrect PTRSUBs, which are discovered later. This rule converts the PTRSUB back to an INT_ADD
/// when the mistake is discovered.
void RulePtrsubUndo::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PTRSUB);
}

/// \brief Recursively search for additive constants and multiplicative constants
///
/// Walking backward from the given Varnode, search for constants being added in and return
/// the sum of all the constants. Additionally pass back the biggest constant coefficient, for any term
/// formed with INT_MULT.
/// \param vn is the given root Varnode of the additive tree
/// \param multiplier will hold the biggest constant multiplier or 0, if no multiplier is present
/// \param maxLevel is the maximum depth to search in the tree
/// \return the sum of all constants in the additive expression
int8 RulePtrsubUndo::getConstOffsetBack(Varnode *vn,int8 &multiplier,int4 maxLevel)

{
  multiplier = 0;
  int8 submultiplier;
  if (vn->isConstant())
    return vn->getOffset();
  if (!vn->isWritten())
    return 0;
  maxLevel -= 1;
  if (maxLevel < 0)
    return 0;
  PcodeOp *op = vn->getDef();
  OpCode opc = op->code();
  int8 retval = 0;
  if (opc == CPUI_INT_ADD) {
    retval += getConstOffsetBack(op->getIn(0),submultiplier,maxLevel);
    if (submultiplier > multiplier)
      multiplier = submultiplier;
    retval += getConstOffsetBack(op->getIn(1), submultiplier, maxLevel);
    if (submultiplier > multiplier)
      multiplier = submultiplier;
  }
  else if (opc == CPUI_INT_MULT) {
    Varnode *cvn = op->getIn(1);
    if (!cvn->isConstant()) return 0;
    multiplier = cvn->getOffset();
    getConstOffsetBack(op->getIn(0), submultiplier, maxLevel);
    if (submultiplier > 0)
      multiplier *= submultiplier;		// Only contribute to the multiplier
  }
  return retval;
}

/// \brief Collect constants and the biggest multiplier in the given PTRSUB expression.
///
/// Walking the additive expression (INT_ADD, PTRADD, and other PTRSUBs) and calculate any additional
/// constant value being added to the PTRSUB.  Additionally pass back the biggest constant coefficient of any
/// multiplicative term in the expression.
/// \param op is the given PTRSUB
/// \param multiplier will hold the biggest multiplicative coefficient or 0, if no INT_MULT or PTRADD is present.
int8 RulePtrsubUndo::getExtraOffset(PcodeOp *op,int8 &multiplier)

{
  int8 extra = 0;
  multiplier = 0;
  int8 submultiplier;
  Varnode *outvn = op->getOut();
  op = outvn->loneDescend();
  while(op != (PcodeOp *)0) {
    OpCode opc = op->code();
    if (opc == CPUI_INT_ADD) {
      int4 slot = op->getSlot(outvn);
      extra += getConstOffsetBack(op->getIn(1-slot),submultiplier,DEPTH_LIMIT);	// Get any constants from other input
      if (submultiplier > multiplier)
	multiplier = submultiplier;
    }
    else if (opc == CPUI_PTRSUB) {
      extra += op->getIn(1)->getOffset();
    }
    else if (opc == CPUI_PTRADD) {
      if (op->getIn(0) != outvn) break;
      int8 ptraddmult = op->getIn(2)->getOffset();
      Varnode *invn = op->getIn(1);
      if (invn->isConstant())					// Only contribute to the extra
	extra += ptraddmult * (int8)invn->getOffset();		// if the index is constant
      getConstOffsetBack(invn,submultiplier,DEPTH_LIMIT);	// otherwise just contribute to multiplier
      if (submultiplier != 0)
	ptraddmult *= submultiplier;
      if (ptraddmult > multiplier)
	multiplier = ptraddmult;
    }
    else {
      break;
    }
    outvn = op->getOut();
    op = outvn->loneDescend();
  }
  extra = sign_extend(extra, 8*outvn->getSize()-1);
  extra &= calc_mask(outvn->getSize());
  return extra;
}

/// \brief Remove any constants in the additive expression rooted at the given PcodeOp
///
/// Walking recursively through the expression, any INT_ADD with a constant input is converted to
/// a COPY.  The INT_ADD must only contribute to the root expression.
/// \param op is the given root PcodeOp
/// \param slot is the input slot to walk back from
/// \param maxLevel is the maximum depth to recurse
/// \param data is the function containing the expression
/// \return the sum of all constants that are removed
int8 RulePtrsubUndo::removeLocalAddRecurse(PcodeOp *op,int4 slot,int4 maxLevel,Funcdata &data)

{
  Varnode *vn = op->getIn(slot);
  if (!vn->isWritten())
    return 0;
  if (vn->loneDescend() != op)
    return 0;				// Varnode must not be used anywhere else
  maxLevel -= 1;
  if (maxLevel < 0)
    return 0;
  op = vn->getDef();
  int8 retval = 0;
  if (op->code() == CPUI_INT_ADD) {
    if (op->getIn(1)->isConstant()) {
      retval += (int8)op->getIn(1)->getOffset();
      data.opRemoveInput(op, 1);
      data.opSetOpcode(op, CPUI_COPY);
    }
    else {
      retval += removeLocalAddRecurse(op, 0, maxLevel, data);
      retval += removeLocalAddRecurse(op, 1, maxLevel, data);
    }
  }
  return retval;
}

/// \brief Remove constants in the additive expression involving the given Varnode
///
/// Any additional PTRADD, PTRSUB, or INT_ADD that uses the Varnode and adds a constant is converted
/// to a COPY.  Additionally any other INT_ADD involved in the expression that adds a constant is
/// also converted to COPY.
/// \param vn is the given Varnode
/// \param data is the function containing the expression
/// \return the sum of all constants that are removed
int8 RulePtrsubUndo::removeLocalAdds(Varnode *vn,Funcdata &data)

{
  int8 extra = 0;
  PcodeOp *op = vn->loneDescend();
  while(op != (PcodeOp *)0) {
    OpCode opc = op->code();
    if (opc == CPUI_INT_ADD) {
      int4 slot = op->getSlot(vn);
      if (slot == 0 && op->getIn(1)->isConstant()) {
	extra += (int8)op->getIn(1)->getOffset();
	data.opRemoveInput(op, 1);
	data.opSetOpcode(op, CPUI_COPY);
      }
      else {
	extra += removeLocalAddRecurse(op,1-slot,DEPTH_LIMIT, data);	// Get any constants from other input
      }
    }
    else if (opc == CPUI_PTRSUB) {
      extra += op->getIn(1)->getOffset();
      op->clearStopTypePropagation();
      data.opRemoveInput(op, 1);
      data.opSetOpcode(op, CPUI_COPY);
    }
    else if (opc == CPUI_PTRADD) {
      if (op->getIn(0) != vn) break;
      int8 ptraddmult = op->getIn(2)->getOffset();
      Varnode *invn = op->getIn(1);
      if (invn->isConstant()) {
	extra += ptraddmult * (int8)invn->getOffset();
	data.opRemoveInput(op,2);
	data.opRemoveInput(op,1);
	data.opSetOpcode(op, CPUI_COPY);
      }
    }
    else {
      break;
    }
    vn = op->getOut();
    op = vn->loneDescend();
  }
  return extra;
}

int4 RulePtrsubUndo::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!canProcessOp(op,data)) return 0;

  Varnode *cvn = op->getIn(1);
  int8 val = cvn->getOffset();
  int8 multiplier;
  int8 extra = getExtraOffset(op,multiplier);

  data.opSetOpcode(op,CPUI_INT_ADD);
  op->clearStopTypePropagation();
  extra = removeLocalAdds(op->getOut(),data);
  if (extra != 0) {
    val = val + extra;		// Lump extra into additive offset
    data.opSetInput(op,data.newConstant(cvn->getSize(), val & calc_mask(cvn->getSize())),1);
  }
  return 1;
}

/// \brief Check if there are problems with ptrsub
///
/// \param op is add or ptrsub op
/// \param slot is slot of the pointer
/// \param data is the function being analyzed
/// \return true if given ptrsub is invalid
bool RulePtrsubUndo::canProcessOp(PcodeOp *op,Funcdata &data)

{
  if (!data.hasTypeRecoveryStarted()) return false;

  Varnode *basevn = op->getIn(0);
  Varnode *cvn = op->getIn(1);
  int8 val = cvn->getOffset();
  int8 multiplier;
  int8 extra = getExtraOffset(op,multiplier);
  Datatype *basetype = basevn->getTypeReadFacing(op);
  if (basetype->isPtrsubMatching(val,extra,multiplier))
    return false;
  PcodeOp *ptrOp = basevn->getDef();
  if (ptrOp != (PcodeOp *)0 && ptrOp->code() == CPUI_PTRSUB)
    return false;

  return true;
}

// Clean up rules

/// \class RuleMultNegOne
/// \brief Cleanup: Convert INT_2COMP from INT_MULT:  `V * -1  =>  -V`
void RuleMultNegOne::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_MULT);
}

int4 RuleMultNegOne::applyOp(PcodeOp *op,Funcdata &data)

{				// a * -1 -> -a
  Varnode *constvn = op->getIn(1);
 
  if (!constvn->isConstant()) return 0;
  if (constvn->getOffset() != calc_mask(constvn->getSize())) return 0;

  data.opSetOpcode(op,CPUI_INT_2COMP);
  data.opRemoveInput(op,1);
  return 1;
}

/// \class RuleAddUnsigned
/// \brief Cleanup:  Convert INT_ADD of constants to INT_SUB:  `V + 0xff...  =>  V - 0x00...`
void RuleAddUnsigned::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ADD);
}

int4 RuleAddUnsigned::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *constvn = op->getIn(1);

  if (!constvn->isConstant()) return 0;
  Datatype *dt = constvn->getTypeReadFacing(op);
  if (dt->getMetatype() != TYPE_UINT) return 0;
  if (dt->isCharPrint()) return 0;	// Only change integer forms
  if (dt->isEnumType()) return 0;
  uintb val = constvn->getOffset();
  uintb mask = calc_mask(constvn->getSize());
  int4 sa = constvn->getSize() * 6;	// 1/4 less than full bitsize
  uintb quarter = (mask>>sa) << sa;
  if ((val & quarter) != quarter) return 0;	// The first quarter of bits must all be 1's
  if (constvn->getSymbolEntry() != (SymbolEntry *)0) {
    EquateSymbol *sym = dynamic_cast<EquateSymbol *>(constvn->getSymbolEntry()->getSymbol());
    if (sym != (EquateSymbol *)0) {
      if (sym->isNameLocked())
	return 0;		// Dont transform a named equate
    }
  }
  data.opSetOpcode(op,CPUI_INT_SUB);
  Varnode *cvn = data.newConstant(constvn->getSize(), (-val) & mask);
  cvn->copySymbol(constvn);
  data.opSetInput(op,cvn,1);
  return 1;
}

/// \class Rule2Comp2Sub
/// \brief Cleanup: Convert INT_ADD back to INT_SUB: `V + -W  ==> V - W`
void Rule2Comp2Sub::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_2COMP);
}

int4 Rule2Comp2Sub::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *addop = op->getOut()->loneDescend();
  if (addop == (PcodeOp *)0) return 0;
  if (addop->code() != CPUI_INT_ADD) return 0;
  if (addop->getIn(0) == op->getOut())
    data.opSetInput(addop,addop->getIn(1),0);
  data.opSetInput(addop,op->getIn(0),1);
  data.opSetOpcode(addop,CPUI_INT_SUB);
  data.opDestroy(op);		// Completely remove 2COMP
  return 1;
}

/// \class RuleSubRight
/// \brief Cleanup: Convert truncation to cast: `sub(V,c)  =>  sub(V>>c*8,0)`
///
/// Before attempting the transform, check if the SUBPIECE is really extracting a field
/// from a structure. If so, mark the op as requiring special printing and return.
/// If the lone descendant of the SUBPIECE is a INT_RIGHT or INT_SRIGHT,
/// we lump that into the shift as well.
void RuleSubRight::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleSubRight::applyOp(PcodeOp *op,Funcdata &data)

{
  if (op->doesSpecialPrinting())
    return 0;
  if (op->getIn(0)->getTypeReadFacing(op)->isPieceStructured()) {
    data.opMarkSpecialPrint(op);	// Print this as a field extraction
    return 0;
  }

  if (op->getIn(0)->getSize() > sizeof(uintb)) return 0; // No array shifts are allowed

  int4 c = op->getIn(1)->getOffset();
  if (c==0) return 0;		// SUBPIECE is not least sig
  Varnode *a = op->getIn(0);
  Varnode *outvn = op->getOut();
  if (outvn->isAddrTied() && a->isAddrTied()) {
    if (outvn->overlap(*a) == c) // This SUBPIECE should get converted to a marker by ActionCopyMarker
      return 0;			// So don't convert it
  }
  OpCode opc = CPUI_INT_RIGHT; // Default shift type
  int4 d = c*8;			// Convert to bit shift
  // Search for lone right shift descendant
  PcodeOp *lone = outvn->loneDescend();
  if (lone!=(PcodeOp *)0) {
    OpCode opc2 = lone->code();
    if ((opc2==CPUI_INT_RIGHT)||(opc2==CPUI_INT_SRIGHT)) {
      if (lone->getIn(1)->isConstant()) { // Shift by constant
	if (outvn->getSize() + c == a->getSize()) {
	  // If SUB is "hi" lump the SUB and shift together
	  d += lone->getIn(1)->getOffset();
	  if (d >= a->getSize() * 8) {
	    if (opc2 == CPUI_INT_RIGHT)
	      return 0;		// Result should have been 0
	    d = a->getSize() * 8 - 1;	// sign extraction
	  }
	  data.opUnlink(op);
	  op = lone;
	  data.opSetOpcode(op,CPUI_SUBPIECE);
	  opc = opc2;
	}
      }
    }
  }
  // Create shift BEFORE the SUBPIECE happens
  Datatype *ct;
  if (opc == CPUI_INT_RIGHT)
    ct = data.getArch()->types->getBase(a->getSize(),TYPE_UINT);
  else
    ct = data.getArch()->types->getBase(a->getSize(),TYPE_INT);
  PcodeOp *shiftop = data.newOp(2,op->getAddr());
  data.opSetOpcode(shiftop,opc);
  Varnode *newout = data.newUnique(a->getSize(),ct);
  data.opSetOutput(shiftop,newout);
  data.opSetInput(shiftop,a,0);
  data.opSetInput(shiftop,data.newConstant(4,d),1);
  data.opInsertBefore(shiftop,op);
   
  // Change SUBPIECE into a least sig SUBPIECE
  data.opSetInput(op,newout,0);
  data.opSetInput(op,data.newConstant(4,0),1);
  return 1;
}

/// \brief Try to push constant pointer further
///
/// Given a PTRSUB has been collapsed to a constant COPY of a string address,
/// try to collapse descendant any PTRADD.
/// \param data is the function being analyzed
/// \param outtype is the data-type associated with the constant
/// \param op is the putative descendant PTRADD
/// \param slot is the input slot receiving the collapsed PTRSUB
/// \param val is the constant pointer value
/// \return \b true if the descendant was collapsed
bool RulePtrsubCharConstant::pushConstFurther(Funcdata &data,TypePointer *outtype,PcodeOp *op,int4 slot,uintb val)

{
  if (op->code() != CPUI_PTRADD) return false;		// Must be a PTRADD
  if (slot != 0) return false;
  Varnode *vn = op->getIn(1);
  if (!vn->isConstant()) return false;			// that is adding a constant
  uintb addval = vn->getOffset();
  addval *= op->getIn(2)->getOffset();
  val += addval;
  Varnode *newconst = data.newConstant(vn->getSize(),val);
  newconst->updateType(outtype,false,false);		// Put the pointer datatype on new constant
  data.opRemoveInput(op,2);
  data.opRemoveInput(op,1);
  data.opSetOpcode(op,CPUI_COPY);
  data.opSetInput(op,newconst,0);
  return true;
}

/// \class RulePtrsubCharConstant
/// \brief Cleanup: Set-up to print string constants
///
/// If a SUBPIECE refers to a global symbol, the output of the SUBPIECE is a (char *),
/// and the address is read-only, then get rid of the SUBPIECE in favor
/// of printing a constant string.
void RulePtrsubCharConstant::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PTRSUB);
}

int4 RulePtrsubCharConstant::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *sb = op->getIn(0);
  Datatype *sbType = sb->getTypeReadFacing(op);
  if (sbType->getMetatype() != TYPE_PTR) return 0;
  TypeSpacebase *sbtype = (TypeSpacebase *)((TypePointer *)sbType)->getPtrTo();
  if (sbtype->getMetatype() != TYPE_SPACEBASE) return 0;
  Varnode *vn1 = op->getIn(1);
  if (!vn1->isConstant()) return 0;
  Varnode *outvn = op->getOut();
  TypePointer *outtype = (TypePointer *)outvn->getTypeDefFacing();
  if (outtype->getMetatype() != TYPE_PTR) return 0;
  Datatype *basetype = outtype->getPtrTo();
  if (!basetype->isCharPrint()) return 0;
  Address symaddr = sbtype->getAddress(vn1->getOffset(),vn1->getSize(),op->getAddr());
  Scope *scope = sbtype->getMap();
  if (!scope->isReadOnly(symaddr,1,op->getAddr()))
    return 0;
  // Check if data at the address looks like a string
  if (!data.getArch()->stringManager->isString(symaddr, basetype))
    return 0;

  // If we reach here, the PTRSUB should be converted to a (COPY of a) pointer constant.
  bool removeCopy = false;
  if (!outvn->isAddrForce()) {
    removeCopy = true;		// Assume we can remove, unless we can't propagate to all descendants
    list<PcodeOp *>::const_iterator iter,enditer;
    iter = outvn->beginDescend();
    enditer = outvn->endDescend();
    while(iter != enditer) {
      PcodeOp *subop = *iter;	// Give each descendant of op a chance to further propagate the constant
      ++iter;
      if (!pushConstFurther(data,outtype,subop,subop->getSlot(outvn),vn1->getOffset()))
	removeCopy = false;	// If the descendant does NOT propagate const, do NOT remove op
    }
  }
  if (removeCopy) {
    data.opDestroy(op);
  }
  else {	// Convert the original PTRSUB to a COPY of the constant
    Varnode *newvn = data.newConstant(outvn->getSize(),vn1->getOffset());
    newvn->updateType(outtype,false,false);
    data.opRemoveInput(op,1);
    data.opSetInput(op,newvn,0);
    data.opSetOpcode(op,CPUI_COPY);
  }
  return 1;
}

/// \class RuleExtensionPush
/// \brief Duplicate CPUI_INT_ZEXT and CPUI_INT_SEXT operations if the result is used in multiple pointer calculations
///
/// By making the extension operation part of each pointer calculation (where it is usually an implied cast),
/// we can frequently eliminate an explicit variable that would just hold the extension.
void RuleExtensionPush::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ZEXT);
  oplist.push_back(CPUI_INT_SEXT);
}

int4 RuleExtensionPush::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *inVn = op->getIn(0);
  if (inVn->isConstant()) return 0;
  if (inVn->isAddrForce()) return 0;
  if (inVn->isAddrTied()) return 0;
  Varnode *outVn = op->getOut();
  if (outVn->isTypeLock() || outVn->isNameLock()) return 0;
  if (outVn->isAddrForce() || outVn->isAddrTied()) return 0;
  list<PcodeOp *>::const_iterator iter;
  int4 addcount = 0;		// Number of INT_ADD descendants
  int4 ptrcount = 0;		// Number of PTRADD descendants
  for(iter=outVn->beginDescend();iter!=outVn->endDescend();++iter) {
    PcodeOp *decOp = *iter;
    OpCode opc = decOp->code();
    if (opc == CPUI_PTRADD) {
      // This extension will likely be hidden
      ptrcount += 1;
    }
    else if (opc == CPUI_INT_ADD) {
      PcodeOp *subOp = decOp->getOut()->loneDescend();
      if (subOp == (PcodeOp *)0 || subOp->code() != CPUI_PTRADD)
	return 0;
      addcount += 1;
    }
    else {
      return 0;
    }
  }
  if ((addcount + ptrcount) <= 1) return 0;
  if (addcount > 0) {
    if (op->getIn(0)->loneDescend() != (PcodeOp *)0) return 0;
  }
  RulePushPtr::duplicateNeed(op, data);		// Duplicate the extension to all result descendants
  return 1;
}

/// \brief Find the base structure or array data-type that the given Varnode is part of
///
/// If the Varnode's data-type is already a structure or array, return that data-type.
/// If the Varnode is part of a known symbol, use that data-type.
/// The starting byte offset of the given Varnode within the structure or array is passed back.
/// \param vn is the given Varnode
/// \param baseOffset is used to pass back the starting offset
/// \return the structure or array data-type, or null otherwise
Datatype *RulePieceStructure::determineDatatype(Varnode *vn,int4 &baseOffset)

{
  Datatype *ct = vn->getStructuredType();
  if (ct == (Datatype *)0)
    return ct;

  if (ct->getSize() != vn->getSize()) {			// vn is a partial
    SymbolEntry *entry = vn->getSymbolEntry();
    baseOffset = vn->getAddr().overlap(0,entry->getAddr(),ct->getSize());
    if (baseOffset < 0)
      return (Datatype*)0;
    baseOffset += entry->getOffset();
    // Find concrete sub-type that matches the size of the Varnode
    Datatype *subType = ct;
    int8 subOffset = baseOffset;
    while(subType != (Datatype *)0 && subType->getSize() > vn->getSize()) {
      subType = subType->getSubType(subOffset, &subOffset);
    }
    if (subType != (Datatype *)0 && subType->getSize() == vn->getSize() && subOffset == 0) {
      // If there is a concrete sub-type
      if (!subType->isPieceStructured())	// and the concrete sub-type is not a structured type itself
	return (Datatype *)0;	// don't split out CONCAT forming the sub-type
    }
  }
  else {
    baseOffset = 0;
  }
  return ct;
}

/// \brief For a structured data-type, determine if the given range spans multiple elements
///
/// Return true unless the range falls within a single non-structured element.
/// \param ct is the structured data-type
/// \param offset is the start of the given range
/// \param size is the number of bytes in the range
/// \return \b true if the range spans multiple elements
bool RulePieceStructure::spanningRange(Datatype *ct,int4 offset,int4 size)

{
  if (offset + size > ct->getSize()) return false;
  int8 newOff = offset;
  for(;;) {
    ct = ct->getSubType(newOff, &newOff);
    if (ct == (Datatype *)0) return true;	// Don't know what it spans, assume multiple
    if (newOff + size > ct->getSize()) return true;	// Spans more than 1
    if (!ct->isPieceStructured()) break;
  }
  return false;
}

/// \brief Convert an INT_ZEXT operation to a PIECE with a zero constant as the first parameter
///
/// The caller provides a parent data-type and an offset into it corresponding to the \e output of the INT_ZEXT.
/// The op is converted to a PIECE with a 0 Varnode, which will be assigned a data-type based on
/// the parent data-type and a computed offset.
/// \param zext is the INT_ZEXT operation
/// \param ct is the parent data-type
/// \param offset is the byte offset of the \e output within the parent data-type
/// \param data is the function containing the operation
/// \return true if the INT_ZEXT was successfully converted
bool RulePieceStructure::convertZextToPiece(PcodeOp *zext,Datatype *ct,int4 offset,Funcdata &data)

{
  Varnode *outvn = zext->getOut();
  Varnode *invn = zext->getIn(0);
  if (invn->isConstant()) return false;
  int4 sz = outvn->getSize() - invn->getSize();
  TypeFactory *types = data.getArch()->types;
  offset += outvn->getSpace()->isBigEndian() ? 0 : invn->getSize();
  int8 newOff = offset;
  while(ct != (Datatype *)0 && ct->getSize() > sz) {
    ct = ct->getSubType(newOff, &newOff);
  }
  Varnode *zerovn = (Varnode *)0;
  if ((types->isPresent(sz))&&(sz<=sizeof(uintb)))
    zerovn = data.newConstant(sz,0);
  else {
    int4 insz = types->getPresentUntil(sz-1);	// Use the greatest possible type
    if (insz<1)
      insz = 1;		// Fallback to 1 byte type even if not supported
    Varnode *cvn = data.newConstant(insz,0);
    PcodeOp *zextop = data.newOp(1,zext->getAddr());
    zerovn = data.newUniqueOut(sz, zextop);
    data.opSetOpcode(zextop,CPUI_INT_ZEXT);
    data.opSetOutput(zextop,zerovn);
    data.opSetInput(zextop,cvn,0);
    data.opInsertBefore(zextop,zext);
  }
  if (ct != (Datatype *)0 && ct->getSize() == sz)
    zerovn->updateType(ct, false, false);
  data.opSetOpcode(zext, CPUI_PIECE);
  data.opInsertInput(zext, zerovn, 0);
  if (invn->getType()->needsResolution())
    data.inheritResolution(invn->getType(), zext, 1, zext, 0);	// Transfer invn's resolution to slot 1
  return true;
}

/// \brief Search for leaves in the CONCAT tree defined by an INT_ZEXT operation and convert them to PIECE
///
/// The CONCAT tree can be extended through an INT_ZEXT, if the extensions output crosses multiple fields of
/// the parent data-type.  We check this and replace the INT_ZEXT with PIECE if appropriate.
/// \param stack is the node container for the CONCAT tree
/// \param structuredType is the parent data-type for the tree
/// \param data is the function containing the tree
/// \return \b true if any INT_ZEXT replacement was performed
bool RulePieceStructure::findReplaceZext(vector<PieceNode> &stack,Datatype *structuredType,Funcdata &data)

{
  bool change = false;
  for(int4 i=0;i<stack.size();++i) {
    PieceNode &node(stack[i]);
    if (!node.isLeaf()) continue;
    Varnode *vn = node.getVarnode();
    if (!vn->isWritten()) continue;
    PcodeOp *op = vn->getDef();
    if (op->code() != CPUI_INT_ZEXT) continue;
    if (!spanningRange(structuredType,node.getTypeOffset(),vn->getSize())) continue;
    if (convertZextToPiece(op,structuredType,node.getTypeOffset(),data))
      change = true;
  }
  return change;
}

/// \brief Return \b true if the two given \b root and \b leaf should be part of different symbols
///
/// A leaf in a CONCAT tree can be in a separate from the root if it is a parameter or a separate root.
/// \param root is the root of the CONCAT tree
/// \param leaf is the given leaf Varnode
/// \return \b true if the two Varnodes should be in different symbols
bool RulePieceStructure::separateSymbol(Varnode *root,Varnode *leaf)

{
  if (root->getSymbolEntry() != leaf->getSymbolEntry()) return true;	// Forced to be different symbols
  if (root->isAddrTied()) return false;
  if (!leaf->isWritten()) return true;	// Assume to be different symbols
  if (leaf->isProtoPartial()) return true;	// Already in another tree
  PcodeOp *op = leaf->getDef();
  if (op->isMarker()) return true;	// Leaf is not defined locally
  if (op->code() != CPUI_PIECE) return false;
  if (leaf->getType()->isPieceStructured()) return true;	// Would be a separate root

  return false;
}

/// \class RulePieceStructure
/// \brief Concatenating structure pieces gets printed as explicit write statements
///
/// Set properties so that a CONCAT expression like `v = CONCAT(CONCAT(v1,v2),CONCAT(v3,v4))` gets
/// rendered as a sequence of separate write statements. `v.field1 = v1; v.field2 = v2; v.field3 = v3; v.field4 = v4;`
void RulePieceStructure::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PIECE);
  oplist.push_back(CPUI_INT_ZEXT);
}

int4 RulePieceStructure::applyOp(PcodeOp *op,Funcdata &data)

{
  if (op->isPartialRoot()) return 0;		// Check if CONCAT tree already been visited
  Varnode *outvn = op->getOut();
  int4 baseOffset;
  Datatype *ct = determineDatatype(outvn, baseOffset);
  if (ct == (Datatype *)0) return 0;

  if (op->code() == CPUI_INT_ZEXT) {
    if (convertZextToPiece(op,outvn->getType(),0,data))
      return 1;
    return 0;
  }
  // Check if outvn is really the root of the tree
  PcodeOp *zext = outvn->loneDescend();
  if (zext != (PcodeOp*)0) {
    if (zext->code() == CPUI_PIECE)
      return 0;		// More PIECEs below us, not a root
    if (zext->code() == CPUI_INT_ZEXT) {
      // Extension of a structured data-type,  convert extension to PIECE first
      if (convertZextToPiece(zext,zext->getOut()->getType(),0,data))
	return 1;
      return 0;
    }
  }

  vector<PieceNode> stack;
  for(;;) {
    PieceNode::gatherPieces(stack, outvn, op, baseOffset, baseOffset);
    if (!findReplaceZext(stack, ct, data))	// Check for INT_ZEXT leaves that need to be converted to PIECEs
      break;
    stack.clear();	// If we found some, regenerate the tree
  }

  op->setPartialRoot();
  bool anyAddrTied = outvn->isAddrTied();
  Address baseAddr = outvn->getAddr() - baseOffset;
  for(int4 i=0;i<stack.size();++i) {
    PieceNode &node(stack[i]);
    Varnode *vn = node.getVarnode();
    Address addr = baseAddr + node.getTypeOffset();
    addr.renormalize(vn->getSize());		// Allow for possible join address
    if (vn->getAddr() == addr) {
      if (!node.isLeaf() || !separateSymbol(outvn, vn)) {
	// Varnode already has correct address and will be part of the same symbol as root
	// so we don't need to change the storage or insert a COPY
	if (!vn->isAddrTied() && !vn->isProtoPartial()) {
	  vn->setProtoPartial();
	}
	anyAddrTied = anyAddrTied || vn->isAddrTied();
	continue;
      }
    }
    if (node.isLeaf()) {
      PcodeOp *copyOp = data.newOp(1,node.getOp()->getAddr());
      Varnode *newVn = data.newVarnodeOut(vn->getSize(), addr, copyOp);
      anyAddrTied = anyAddrTied || newVn->isAddrTied();	// Its possible newVn is addrtied, even if vn isn't
      Datatype *newType = data.getArch()->types->getExactPiece(ct, node.getTypeOffset(), vn->getSize());
      if (newType == (Datatype *)0)
	newType = vn->getType();
      newVn->updateType(newType, false, false);
      data.opSetOpcode(copyOp, CPUI_COPY);
      data.opSetInput(copyOp, vn, 0);
      data.opSetInput(node.getOp(),newVn,node.getSlot());
      data.opInsertBefore(copyOp, node.getOp());
      if (vn->getType()->needsResolution()) {
	// Inherit PIECE's read resolution for COPY's read
	data.inheritResolution(vn->getType(), copyOp, 0, node.getOp(), node.getSlot());
      }
      if (newType->needsResolution()) {
	newType->resolveInFlow(copyOp, -1);	// If the piece represents part of a union, resolve it
      }
      if (!newVn->isAddrTied())
	newVn->setProtoPartial();
    }
    else {
      // Reaching here we know vn is NOT addrtied and has a lone descendant
      // We completely replace the Varnode with one having the correct storage
      PcodeOp *defOp = vn->getDef();
      PcodeOp *loneOp = vn->loneDescend();
      int4 slot = loneOp->getSlot(vn);
      Varnode *newVn = data.newVarnode(vn->getSize(), addr, vn->getType());
      data.opSetOutput(defOp, newVn);
      data.opSetInput(loneOp, newVn, slot);
      data.deleteVarnode(vn);
      if (!newVn->isAddrTied())
	newVn->setProtoPartial();
    }
  }
  if (!anyAddrTied)
    data.getMerge().registerProtoPartialRoot(outvn);
  return 1;
}

Datatype *RuleSplitCopy::findCharArrayContainingDatatype(Datatype *ct,int8 offset,int4 size,TypeFactory *types)

{
  if (ct->isCharPrint()) {
    if (offset != 0)
      return (Datatype *)0;
    if (size <= ct->getSize())
      return (Datatype *)0;
    return ct;
  }
  type_metatype meta = ct->getMetatype();
  if (meta == TYPE_ARRAY) {
    int8 newoff;
    Datatype *dt1 = ct->getSubType(offset,&newoff);
    if (dt1 == (Datatype *)0)
      return (Datatype *)0;
    Datatype *dt2 = findCharArrayContainingDatatype(dt1,newoff,size,types);
    if (dt2 == (Datatype *)0)
      return (Datatype *)0;
    if (dt2->isCharPrint())
      return types->getExactPiece(ct,offset,size);
    return dt2;
  }
  else if (meta == TYPE_STRUCT) {
    int8 newoff;
    Datatype *dt = ct->getSubType(offset,&newoff);
    if (dt == (Datatype *)0)
      return (Datatype *)0;
    return findCharArrayContainingDatatype(dt,newoff,size,types);
  }
  else
  if (meta == TYPE_UNION) {
    TypeUnion *tu = (TypeUnion *)ct;
    int4 numFields = tu->numDepend();
    for (int4 i=0;i<numFields;++i) {
      Datatype *dt1 = tu->getField(i)->type;
      Datatype *dt2 = findCharArrayContainingDatatype(dt1,offset,size,types);
      if (dt2 == (Datatype *)0) continue;
      return dt2;
    }
    return (Datatype *)0;
  }
  else if (meta == TYPE_PARTIALSTRUCT) {
    TypePartialStruct *tps = (TypePartialStruct *)ct;
    Datatype *ts = tps->getParent();
    int4 off = tps->getOffset() + offset;
    return findCharArrayContainingDatatype(ts,off,size,types);
  }
  else if (meta == TYPE_PARTIALUNION) {
    TypePartialUnion *tpu = (TypePartialUnion *)ct;
    TypeUnion *tu = tpu->getParentUnion();
    int4 off = tpu->getOffset() + offset;
    return findCharArrayContainingDatatype(tu,off,size,types);
  }
  return (Datatype *)0;
}

/// \class RuleSplitCopy
/// \brief Split COPY ops based on TypePartialStruct
///
/// If more than one logical component of a structure or array is copied at once,
/// rewrite the COPY operator as multiple COPYs.
void RuleSplitCopy::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_COPY);
}

int4 RuleSplitCopy::applyOp(PcodeOp *op,Funcdata &data)

{
  TypeFactory *typegrp = data.getArch()->types;
  Varnode *invn = op->getIn(0);
  Varnode *outvn = op->getOut();
  Datatype *ct = outvn->getType();
  Datatype *outType = (Datatype *)0;
  if (invn->isConstant()) {
    outType = findCharArrayContainingDatatype(ct,0,outvn->getSize(),typegrp);
  }
  if (outType == (Datatype *)0)
    outType = outvn->getTypeDefFacing();
  Datatype *inType = invn->getTypeReadFacing(op);
  type_metatype metain = inType->getMetatype();
  type_metatype metaout = outType->getMetatype();
  if (metain != TYPE_PARTIALSTRUCT && metaout != TYPE_PARTIALSTRUCT &&
      metain != TYPE_ARRAY && metaout != TYPE_ARRAY &&
      metain != TYPE_STRUCT && metaout != TYPE_STRUCT)
    return 0;
  SplitDatatype splitter(data);
  if (splitter.splitCopy(op, inType, outType))
    return 1;
  return 0;
}

/// \class RuleSplitLoad
/// \brief Split LOAD ops based on TypePartialStruct
///
/// If more than one logical component of a structure or array is loaded at once,
/// rewrite the LOAD operator as multiple LOADs.
void RuleSplitLoad::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_LOAD);
}

int4 RuleSplitLoad::applyOp(PcodeOp *op,Funcdata &data)

{
  Datatype *inType = SplitDatatype::getValueDatatype(op, op->getOut()->getSize(), data.getArch()->types);
  if (inType == (Datatype *)0)
    return 0;
  type_metatype metain = inType->getMetatype();
  if (metain != TYPE_STRUCT && metain != TYPE_ARRAY && metain != TYPE_PARTIALSTRUCT)
    return 0;
  SplitDatatype splitter(data);
  if (splitter.splitLoad(op, inType))
    return 1;
  return 0;
}

/// \class RuleSplitStore
/// \brief Split STORE ops based on TypePartialStruct
///
/// If more than one logical component of a structure or array is stored at once,
/// rewrite the STORE operator as multiple STOREs.
void RuleSplitStore::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_STORE);
}

int4 RuleSplitStore::applyOp(PcodeOp *op,Funcdata &data)

{
  Datatype *outType = SplitDatatype::getValueDatatype(op, op->getIn(2)->getSize(), data.getArch()->types);
  if (outType == (Datatype *)0)
    return 0;
  type_metatype metain = outType->getMetatype();
  if (metain != TYPE_STRUCT && metain != TYPE_ARRAY && metain != TYPE_PARTIALSTRUCT)
    return 0;
  SplitDatatype splitter(data);
  if (splitter.splitStore(op, outType))
    return 1;
  return 0;
}

/// \class RuleSubNormal
/// \brief Pull-back SUBPIECE through INT_RIGHT and INT_SRIGHT
///
/// The form looks like:
///  - `sub( V>>n ,c )  =>  sub( V, c+k/8 ) >> (n-k)  where k = (n/8)*8`  or
///  - `sub( V>>n, c )  =>  ext( sub( V, c+k/8 ) )  if n is big`
void RuleSubNormal::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleSubNormal::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *shiftout = op->getIn(0);
  if (!shiftout->isWritten()) return 0;
  PcodeOp *shiftop = shiftout->getDef();
  OpCode opc = shiftop->code();
  if ((opc!=CPUI_INT_RIGHT)&&(opc!=CPUI_INT_SRIGHT))
    return 0;
  if (!shiftop->getIn(1)->isConstant()) return 0;
  Varnode *a = shiftop->getIn(0);
  if (a->isFree()) return 0;
  Varnode *outvn = op->getOut();
  if (outvn->isPrecisHi() || outvn->isPrecisLo()) return 0;
  int4 n = shiftop->getIn(1)->getOffset();
  int4 c = op->getIn(1)->getOffset();
  int4 k = (n/8);
  int4 insize = a->getSize();
  int4 outsize = outvn->getSize();

  // Total shift + outsize must be greater equal to size of input
  if ((n+8*c+8*outsize < 8*insize)&&(n != k*8)) return 0;
  
  // If totalcut + remain > original input
  if (k+c+outsize > insize) {
    int4 truncSize = insize - c - k;
    if (n == k*8 && truncSize > 0 && popcount(truncSize)==1) {
      // We need an additional extension
      c += k;
      PcodeOp *newop = data.newOp(2,op->getAddr());
      opc = (opc == CPUI_INT_SRIGHT) ? CPUI_INT_SEXT : CPUI_INT_ZEXT;
      data.opSetOpcode(newop,CPUI_SUBPIECE);
      data.newUniqueOut(truncSize,newop);
      data.opSetInput(newop,a,0);
      data.opSetInput(newop,data.newConstant(4,c),1);
      data.opInsertBefore(newop,op);
      
      data.opSetInput(op,newop->getOut(),0);
      data.opRemoveInput(op,1);
      data.opSetOpcode(op,opc);
      return 1;
    }
    else
      k = insize-c-outsize; // Or we can shrink the cut
  }

  // if n == k*8, then a shift is unnecessary
  c += k;
  n -= k*8;
  if (n==0) {			// Extra shift is unnecessary
    data.opSetInput(op,a,0);
    data.opSetInput(op,data.newConstant(4,c),1);
    return 1;
  }
  else if (n >= outsize * 8) {
    n = outsize * 8;		// Can only shift so far
    if (opc == CPUI_INT_SRIGHT)
      n -= 1;
  }

  PcodeOp *newop = data.newOp(2,op->getAddr());
  data.opSetOpcode(newop,CPUI_SUBPIECE);
  data.newUniqueOut(outsize,newop);
  data.opSetInput(newop,a,0);
  data.opSetInput(newop,data.newConstant(4,c),1);
  data.opInsertBefore(newop,op);

  data.opSetInput(op,newop->getOut(),0);
  data.opSetInput(op,data.newConstant(4,n),1);
  data.opSetOpcode(op,opc);
  return 1;
}

/// \class RulePositiveDiv
/// \brief Signed division of positive values is unsigned division
///
/// If the sign bit of both the numerator and denominator of a signed division (or remainder)
/// are zero, then convert to the unsigned form of the operation.
void RulePositiveDiv::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SDIV);
  oplist.push_back(CPUI_INT_SREM);
}

int4 RulePositiveDiv::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 sa = op->getOut()->getSize();
  if (sa > sizeof(uintb)) return 0;
  sa = sa * 8 - 1;
  if (((op->getIn(0)->getNZMask() >> sa) & 1) != 0)
    return 0;		// Input 0 may be negative
  if (((op->getIn(1)->getNZMask() >> sa) & 1) != 0)
    return 0;		// Input 1 may be negative
  OpCode opc = (op->code() == CPUI_INT_SDIV) ? CPUI_INT_DIV : CPUI_INT_REM;
  data.opSetOpcode(op, opc);
  return 1;
}

/// \class RuleDivTermAdd
/// \brief Simplify expressions associated with optimized division expressions
///
/// The form looks like:
///   - `sub(ext(V)*c,b)>>d + V  ->  sub( (ext(V)*(c+2^n))>>n,0)`
///
/// where n = d + b*8, and the left-shift signedness (if it exists)
/// matches the extension signedness.
void RuleDivTermAdd::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
  oplist.push_back(CPUI_INT_RIGHT); // added
  oplist.push_back(CPUI_INT_SRIGHT); // added
}

int4 RuleDivTermAdd::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 n;
  OpCode shiftopc;
  PcodeOp *subop = findSubshift(op,n,shiftopc);
  if (subop == (PcodeOp *)0) return 0;
  if (n > 127) return 0;	// Up to 128-bits
  
  Varnode *multvn = subop->getIn(0);
  if (!multvn->isWritten()) return 0;
  PcodeOp *multop = multvn->getDef();
  if (multop->code() != CPUI_INT_MULT) return 0;
  uint8 multConst[2];
  if (!multop->getIn(1)->isConstantExtended(multConst))
    return 0;
  
  Varnode *extvn = multop->getIn(0);
  if (!extvn->isWritten()) return 0;
  PcodeOp *extop = extvn->getDef();
  OpCode opc = extop->code();
  if (opc == CPUI_INT_ZEXT) {
    if (op->code()==CPUI_INT_SRIGHT) return 0;
  }
  else if (opc == CPUI_INT_SEXT) {
    if (op->code()==CPUI_INT_RIGHT) return 0;
  }

  uint8 power[2];
  set_u128(power, 1);
  leftshift128(power,power,n);		// power = 2^n
  add128(multConst,power,multConst);	// multConst += 2^n
  Varnode *x = extop->getIn(0);

  list<PcodeOp *>::const_iterator iter;
  for(iter=op->getOut()->beginDescend();iter!=op->getOut()->endDescend();++iter) {
    PcodeOp *addop = *iter;
    if (addop->code() != CPUI_INT_ADD) continue;
    if ((addop->getIn(0)!=x)&&(addop->getIn(1)!=x))
      continue;

    // Construct the new constant
    Varnode *newConstVn = data.newExtendedConstant(extvn->getSize(), multConst, op);

    // Construct the new multiply
    PcodeOp *newmultop = data.newOp(2,op->getAddr());
    data.opSetOpcode(newmultop,CPUI_INT_MULT);
    Varnode *newmultvn = data.newUniqueOut(extvn->getSize(),newmultop);
    data.opSetInput(newmultop,extvn,0);
    data.opSetInput(newmultop,newConstVn,1);
    data.opInsertBefore(newmultop,op);

    PcodeOp *newshiftop = data.newOp(2,op->getAddr());
    if (shiftopc == CPUI_MAX)
      shiftopc = CPUI_INT_RIGHT;
    data.opSetOpcode(newshiftop,shiftopc);
    Varnode *newshiftvn = data.newUniqueOut(extvn->getSize(),newshiftop);
    data.opSetInput(newshiftop,newmultvn,0);
    data.opSetInput(newshiftop,data.newConstant(4,n),1);
    data.opInsertBefore(newshiftop,op);

    data.opSetOpcode(addop,CPUI_SUBPIECE);
    data.opSetInput(addop,newshiftvn,0);
    data.opSetInput(addop,data.newConstant(4,0),1);
    return 1;
  }
  return 0;
}

/// \brief Check for shift form of expression
///
/// Look for the two forms:
///  - `sub(V,c)`   or
///  - `sub(V,c) >> n`
///
/// Pass back whether a shift was involved and the total truncation in bits:  `n+c*8`
/// \param op is the root of the expression
/// \param n is the reference that will hold the total truncation
/// \param shiftopc will hold the shift OpCode if used, CPUI_MAX otherwise
/// \return the SUBPIECE op if present or NULL otherwise
PcodeOp *RuleDivTermAdd::findSubshift(PcodeOp *op,int4 &n,OpCode &shiftopc)

{ // SUB( .,#c) or SUB(.,#c)>>n  return baseop and n+c*8
  // make SUB is high
  PcodeOp *subop;
  shiftopc = op->code();
  if (shiftopc != CPUI_SUBPIECE) { // Must be right shift
    Varnode *vn = op->getIn(0);
    if (!vn->isWritten()) return (PcodeOp *)0;
    subop = vn->getDef();
    if (subop->code() != CPUI_SUBPIECE) return (PcodeOp *)0;
    if (!op->getIn(1)->isConstant()) return (PcodeOp *)0;
    n = op->getIn(1)->getOffset();
  }
  else {
    shiftopc = CPUI_MAX;	// Indicate there was no shift
    subop = op;
    n = 0;
  }
  int4 c = subop->getIn(1)->getOffset();
  if (subop->getOut()->getSize() + c != subop->getIn(0)->getSize())
    return (PcodeOp *)0;	// SUB is not high
  n += 8*c;

  return subop;
}

/// \class RuleDivTermAdd2
/// \brief Simplify another expression associated with optimized division
///
/// With `W = sub( zext(V)*c, d)` the rule is:
///   - `W+((V-W)>>1)   =>   `sub( (zext(V)*(c+2^n))>>(n+1), 0)`
///
/// where n = d*8. All extensions and right-shifts must be unsigned
/// n must be equal to the size of SUBPIECE's truncation.
void RuleDivTermAdd2::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_RIGHT);
}

int4 RuleDivTermAdd2::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(1)->isConstant()) return 0;
  if (op->getIn(1)->getOffset() != 1) return 0;
  if (!op->getIn(0)->isWritten()) return 0;
  PcodeOp *subop = op->getIn(0)->getDef();
  if (subop->code() != CPUI_INT_ADD) return 0;
  Varnode *x = (Varnode *)0;
  Varnode *compvn;
  PcodeOp *compop;
  int4 i;
  for(i=0;i<2;++i) {
    compvn = subop->getIn(i);
    if (compvn->isWritten()) {
      compop = compvn->getDef();
      if (compop->code() == CPUI_INT_MULT) {
	Varnode *invn = compop->getIn(1);
	if (invn->isConstant()) {
	  if (invn->getOffset() == calc_mask(invn->getSize())) {
	    x = subop->getIn(1-i);
	    break;
	  }
	}
      }
    }
  }
  if (i==2) return 0;
  Varnode *z = compvn->getDef()->getIn(0);
  if (!z->isWritten()) return 0;
  PcodeOp *subpieceop = z->getDef();
  if (subpieceop->code() != CPUI_SUBPIECE) return 0;
  int4 n = subpieceop->getIn(1)->getOffset() *8;
  if (n!= 8*(subpieceop->getIn(0)->getSize() - z->getSize())) return 0;
  Varnode *multvn = subpieceop->getIn(0);
  if (!multvn->isWritten()) return 0;
  PcodeOp *multop = multvn->getDef();
  if (multop->code() != CPUI_INT_MULT) return 0;
  uint8 multConst[2];
  if (!multop->getIn(1)->isConstantExtended(multConst)) return 0;
  Varnode *zextvn = multop->getIn(0);
  if (!zextvn->isWritten()) return 0;
  PcodeOp *zextop = zextvn->getDef();
  if (zextop->code() != CPUI_INT_ZEXT) return 0;
  if (zextop->getIn(0) != x) return 0;

  list<PcodeOp *>::const_iterator iter;
  for(iter=op->getOut()->beginDescend();iter!=op->getOut()->endDescend();++iter) {
    PcodeOp *addop = *iter;
    if (addop->code() != CPUI_INT_ADD) continue;
    if ((addop->getIn(0)!=z)&&(addop->getIn(1)!=z)) continue;

    uint8 pow[2];
    set_u128(pow, 1);
    leftshift128(pow,pow,n);		// Calculate 2^n
    add128(multConst, pow, multConst);	// multConst = multConst + 2^n
    PcodeOp *newmultop = data.newOp(2,op->getAddr());
    data.opSetOpcode(newmultop,CPUI_INT_MULT);
    Varnode *newmultvn = data.newUniqueOut(zextvn->getSize(),newmultop);
    data.opSetInput(newmultop,zextvn,0);
    Varnode *newConstVn = data.newExtendedConstant(zextvn->getSize(), multConst, op);
    data.opSetInput(newmultop,newConstVn,1);
    data.opInsertBefore(newmultop,op);

    PcodeOp *newshiftop = data.newOp(2,op->getAddr());
    data.opSetOpcode(newshiftop,CPUI_INT_RIGHT);
    Varnode *newshiftvn = data.newUniqueOut(zextvn->getSize(),newshiftop);
    data.opSetInput(newshiftop,newmultvn,0);
    data.opSetInput(newshiftop,data.newConstant(4,n+1),1);
    data.opInsertBefore(newshiftop,op);

    data.opSetOpcode(addop,CPUI_SUBPIECE);
    data.opSetInput(addop,newshiftvn,0);
    data.opSetInput(addop,data.newConstant(4,0),1);
    return 1;
  }
  return 0;
}

/// \brief Check for INT_(S)RIGHT and/or SUBPIECE followed by INT_MULT
///
/// Look for the forms:
///  - `sub(ext(X) * y,c)`       or
///  - `sub(ext(X) * y,c) >> n`  or
///  - `(ext(X) * y) >> n`
///
/// Looks for truncation/multiplication consistent with an optimized division. The
/// truncation can come as either a SUBPIECE operation and/or right shifts.
/// The numerand and the amount it has been extended is discovered. The extension
/// can be, but doesn't have to be, an explicit INT_ZEXT or INT_SEXT. If the form
/// doesn't match NULL is returned. If the Varnode holding the extended numerand
/// matches the final operand size, it is returned, otherwise the unextended numerand
/// is returned. The total truncation, the multiplicative constant, the numerand
/// size, and the extension type are all passed back.
/// \param op is the root of the expression
/// \param n is the reference that will hold the total number of bits of truncation
/// \param y will hold the multiplicative constant
/// \param xsize will hold the number of (non-zero) bits in the numerand
/// \param extopc holds whether the extension is INT_ZEXT or INT_SEXT
/// \return the extended numerand if possible, or the unextended numerand, or NULL
Varnode *RuleDivOpt::findForm(PcodeOp *op,int4 &n,uint8 *y,int4 &xsize,OpCode &extopc)

{
  PcodeOp *curOp = op;
  OpCode shiftopc = curOp->code();
  if (shiftopc == CPUI_INT_RIGHT || shiftopc == CPUI_INT_SRIGHT) {
    Varnode *vn = curOp->getIn(0);
    if (!vn->isWritten()) return (Varnode *)0;
    Varnode *cvn = curOp->getIn(1);
    if (!cvn->isConstant()) return (Varnode *)0;
    n = cvn->getOffset();
    curOp = vn->getDef();
  }
  else {
    n = 0;	// No initial shift
    if (shiftopc != CPUI_SUBPIECE) return (Varnode *)0;	// In this case SUBPIECE is not optional
    shiftopc = CPUI_MAX;
  }
  if (curOp->code() == CPUI_SUBPIECE) {		// Optional SUBPIECE
    int4 c = curOp->getIn(1)->getOffset();
    Varnode *inVn = curOp->getIn(0);
    if (!inVn->isWritten()) return (Varnode *)0;
    if (curOp->getOut()->getSize() + c != inVn->getSize())
      return (Varnode *)0;			// Must keep high bits
    n += 8*c;
    curOp = inVn->getDef();
  }
  if (curOp->code() != CPUI_INT_MULT) return (Varnode *)0;	// There MUST be an INT_MULT
  Varnode *inVn = curOp->getIn(0);
  if (!inVn->isWritten()) return (Varnode *)0;
  if (inVn->isConstantExtended(y)) {
    inVn = curOp->getIn(1);
    if (!inVn->isWritten()) return (Varnode *)0;
  }
  else if (!curOp->getIn(1)->isConstantExtended(y))
    return (Varnode *)0;	// There MUST be a constant

  Varnode *resVn;
  PcodeOp *extOp = inVn->getDef();
  extopc = extOp->code();
  if (extopc != CPUI_INT_SEXT) {
    uintb nzMask;
    if (extopc == CPUI_INT_ZEXT)
      nzMask = extOp->getIn(0)->getNZMask();
    else
      nzMask = inVn->getNZMask();
    xsize = 8*sizeof(uintb) - count_leading_zeros(nzMask);
    if (xsize == 0) return (Varnode *)0;
    if (xsize > 4*inVn->getSize()) return (Varnode *)0;
  }
  else
    xsize = extOp->getIn(0)->getSize() * 8;

  if (extopc == CPUI_INT_ZEXT || extopc == CPUI_INT_SEXT) {
    Varnode *extVn = extOp->getIn(0);
    if (extVn->isFree()) return (Varnode *)0;
    if (inVn->getSize() == op->getOut()->getSize())
      resVn = inVn;
    else
      resVn = extVn;
  }
  else {
    extopc = CPUI_INT_ZEXT;	// Treat as unsigned extension
    resVn = inVn;
  }
  // Check for signed mismatch
  if (((extopc == CPUI_INT_ZEXT)&&(shiftopc==CPUI_INT_SRIGHT))||
      ((extopc == CPUI_INT_SEXT)&&(shiftopc==CPUI_INT_RIGHT))) {
    if (8*op->getOut()->getSize() - n != xsize)
      return (Varnode *)0;
    // op's signedness does not matter because all the extension
    // bits are truncated
  }
  return resVn;
}

/// Given the multiplicative encoding \b y and the \b n, the power of 2,
/// Compute:
/// \code
///       divisor = 2^n / (y-1)
/// \endcode
///
/// Do some additional checks on the parameters as an optimized encoding
/// of a divisor.
/// \param n is the power of 2
/// \param y is the (up to 128-bit) multiplicative coefficient
/// \param xsize is the maximum power of 2
/// \return the divisor or 0 if the checks fail
uintb RuleDivOpt::calcDivisor(uintb n,uint8 *y,int4 xsize)

{
  if (n > 127 || xsize > 64) return 0;		// Not enough precision
  uint8 power[2];
  uint8 q[2];
  uint8 r[2];
  set_u128(power, 1);
  if (ulessequal128(y, power))		// Boundary cases, y <= 1, are wrong form
    return 0;

  subtract128(y, power, y);			// y = y - 1
  leftshift128(power, power, n);		// power = 2^n

  udiv128(power, y, q, r);
  if (0 != q[1])
    return 0;			// Result is bigger than 64-bits
  if (uless128(y,q)) return 0;	// if y < q
  uint8 diff = 0;
  if (!uless128(r,q)) {		// if r >= q
    // Its possible y is 1 too big giving us a q that is smaller by 1 than the correct value
    q[0] += 1;			// Adjust to bigger q
    subtract128(r,y,r);		// and remainder for the smaller y
    add128(r, q, r);
    if (!uless128(r,q)) return 0;
    diff = q[0];		// Using y that is off by one adds extra error, affecting allowable maxx
  }
  // The optimization of division to multiplication
  // by the reciprocal holds true, if the maximum value
  // of x times q-r is less than 2^n
  uint8 maxx = (xsize == 64) ? 0 : ((uint8)1) << xsize;
  maxx -= 1;			// Maximum possible x value
  uint8 tmp[2];
  uint8 denom[2];
  diff += q[0] - r[0];
  set_u128(denom,diff);
  udiv128(power,denom, tmp, r);
  if (0 != tmp[1])
    return (uintb)q[0];		// tmp is bigger than 2^64 > maxx
  if (tmp[0]<=maxx) return 0;
  return (uintb)q[0];
}

/// \brief Replace sign-bit extractions from the first given Varnode with the second Varnode
///
/// Look for either:
///  - `V >> 0x1f`
///  - `V s>> 0x1f`
///
/// Allow for the value to be COPYed around.
/// \param firstVn is the first given Varnode
/// \param replaceVn is the Varnode to replace it with in each extraction
/// \param data is the function holding the Varnodes
void RuleDivOpt::moveSignBitExtraction(Varnode *firstVn,Varnode *replaceVn,Funcdata &data)

{
  vector<Varnode *> testList;
  testList.push_back(firstVn);
  if (firstVn->isWritten()) {
    PcodeOp *op = firstVn->getDef();
    if (op->code() == CPUI_INT_SRIGHT) {
      // Same sign bit could be extracted from previous shifted version
      testList.push_back(op->getIn(0));
    }
  }
  for(int4 i=0;i<testList.size();++i) {
    Varnode *vn = testList[i];
    list<PcodeOp *>::const_iterator iter = vn->beginDescend();
    while(iter!=vn->endDescend()) {
      PcodeOp *op = *iter;
      ++iter;		// Increment before modifying the op
      OpCode opc = op->code();
      if (opc == CPUI_INT_RIGHT || opc == CPUI_INT_SRIGHT) {
	Varnode *constVn = op->getIn(1);
	if (constVn->isWritten()) {
	  PcodeOp *constOp = constVn->getDef();
	  if (constOp->code() == CPUI_COPY)
	    constVn = constOp->getIn(0);
	  else if (constOp->code() == CPUI_INT_AND) {
	    constVn = constOp->getIn(0);
	    Varnode *otherVn = constOp->getIn(1);
	    if (!otherVn->isConstant()) continue;
	    if (constVn->getOffset() != (constVn->getOffset() & otherVn->getOffset())) continue;
	  }
	}
	if (constVn->isConstant()) {
	  int4 sa = firstVn->getSize() * 8 - 1;
	  if (sa == (int4)constVn->getOffset()) {
	    data.opSetInput(op,replaceVn,0);
	  }
	}
      }
      else if (opc == CPUI_COPY) {
	testList.push_back(op->getOut());
      }
    }
  }
}

/// A form ending in a SUBPIECE, may be contained in a working form ending at
/// the SUBPIECE followed by INT_SRIGHT.  The containing form would supersede.
/// \param op is the root of the form to check
/// \return \b true if it is (possibly) contained in a superseding form
bool RuleDivOpt::checkFormOverlap(PcodeOp *op)

{
  if (op->code() != CPUI_SUBPIECE) return false;
  Varnode *vn = op->getOut();
  list<PcodeOp *>::const_iterator iter;
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *superOp = *iter;
    OpCode opc = superOp->code();
    if (opc != CPUI_INT_RIGHT && opc != CPUI_INT_SRIGHT) continue;
    Varnode *cvn = superOp->getIn(1);
    if (!cvn->isConstant()) return true;	// Might be a form where constant has propagated yet
    int4 n,xsize;
    uint8 y[2];
    OpCode extopc;
    Varnode *inVn = findForm(superOp, n, y, xsize, extopc);
    if (inVn != (Varnode *)0) return true;
  }
  return false;
}

/// \class RuleDivOpt
/// \brief Convert INT_MULT and shift forms into INT_DIV or INT_SDIV
///
/// The unsigned and signed variants are:
///   - `sub( (zext(V)*c), d) >> e   =>  V / (2^n/(c-1)) where n = d*8 + e`
///   - `sub( (sext(V)*c), d) s>> e =>  V s/ (2^n/(c-1)) where n = d*8 + e`
void RuleDivOpt::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
  oplist.push_back(CPUI_INT_RIGHT);
  oplist.push_back(CPUI_INT_SRIGHT);
}

int4 RuleDivOpt::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 n,xsize;
  uint8 y[2];
  OpCode extOpc;
  Varnode *inVn = findForm(op,n,y,xsize,extOpc);
  if (inVn == (Varnode *)0) return 0;
  if (checkFormOverlap(op)) return 0;
  if (extOpc == CPUI_INT_SEXT)
    xsize -= 1;		// one less bit for signed, because of signbit
  uintb divisor = calcDivisor(n,y,xsize);
  if (divisor == 0) return 0;
  int4 outSize = op->getOut()->getSize();

  if (inVn->getSize() < outSize) {	// Do we need an extension to get to final size
    PcodeOp *inExt = data.newOp(1,op->getAddr());
    data.opSetOpcode(inExt,extOpc);
    Varnode *extOut = data.newUniqueOut(outSize,inExt);
    data.opSetInput(inExt,inVn,0);
    inVn = extOut;
    data.opInsertBefore(inExt,op);
  }
  else if (inVn->getSize() > outSize) {	// Do we need a truncation to get to final size
    PcodeOp *newop = data.newOp(2,op->getAddr());	// Create new op to hold the INT_DIV or INT_SDIV:INT_ADD
    data.opSetOpcode(newop, CPUI_INT_ADD);		// This gets changed immediately, but need it for opInsert
    Varnode *resVn = data.newUniqueOut(inVn->getSize(), newop);
    data.opInsertBefore(newop, op);
    data.opSetOpcode(op, CPUI_SUBPIECE);	// Original op becomes a truncation
    data.opSetInput(op,resVn,0);
    data.opSetInput(op,data.newConstant(4, 0),1);
    op = newop;					// Main transform now changes newop
    outSize = inVn->getSize();
  }
  if (extOpc == CPUI_INT_ZEXT) { // Unsigned division
    data.opSetInput(op,inVn,0);
    data.opSetInput(op,data.newConstant(outSize,divisor),1);
    data.opSetOpcode(op,CPUI_INT_DIV);
  }
  else {			// Sign division
    moveSignBitExtraction(op->getOut(), inVn, data);
    PcodeOp *divop = data.newOp(2,op->getAddr());
    data.opSetOpcode(divop,CPUI_INT_SDIV);
    Varnode *newout = data.newUniqueOut(outSize,divop);
    data.opSetInput(divop,inVn,0);
    data.opSetInput(divop,data.newConstant(outSize,divisor),1);
    data.opInsertBefore(divop,op);
    // Build the sign value correction
    PcodeOp *sgnop = data.newOp(2,op->getAddr());
    data.opSetOpcode(sgnop,CPUI_INT_SRIGHT);
    Varnode *sgnvn = data.newUniqueOut(outSize,sgnop);
    data.opSetInput(sgnop,inVn,0);
    data.opSetInput(sgnop,data.newConstant(outSize,outSize*8-1),1);
    data.opInsertBefore(sgnop,op);
    // Add the correction into the division op
    data.opSetInput(op,newout,0);
    data.opSetInput(op,sgnvn,1);
    data.opSetOpcode(op,CPUI_INT_ADD);
  }
  return 1;
}

/// \class RuleSignDiv2
/// \brief Convert INT_SRIGHT form into INT_SDIV:  `(V + -1*(V s>> 31)) s>> 1  =>  V s/ 2`
void RuleSignDiv2::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SRIGHT);
}

int4 RuleSignDiv2::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *addout,*multout,*shiftout,*a;
  PcodeOp *addop,*multop,*shiftop;

  if (!op->getIn(1)->isConstant()) return 0;
  if (op->getIn(1)->getOffset() != 1) return 0;
  addout = op->getIn(0);
  if (!addout->isWritten()) return 0;
  addop = addout->getDef();
  if (addop->code() != CPUI_INT_ADD) return 0;
  int4 i;
  a = (Varnode *)0;
  for(i=0;i<2;++i) {
    multout = addop->getIn(i);
    if (!multout->isWritten()) continue;
    multop = multout->getDef();
    if (multop->code() != CPUI_INT_MULT)
      continue;
    if (!multop->getIn(1)->isConstant()) continue;
    if (multop->getIn(1)->getOffset() != 
	calc_mask(multop->getIn(1)->getSize()))
      continue;
    shiftout = multop->getIn(0);
    if (!shiftout->isWritten()) continue;
    shiftop = shiftout->getDef();
    if (shiftop->code() != CPUI_INT_SRIGHT)
      continue;
    if (!shiftop->getIn(1)->isConstant()) continue;
    int4 n = shiftop->getIn(1)->getOffset();
    a = shiftop->getIn(0);
    if (a != addop->getIn(1-i)) continue;
    if (n != 8*a->getSize() - 1) continue;
    if (a->isFree()) continue;
    break;
  }
  if (i==2) return 0;

  data.opSetInput(op,a,0);
  data.opSetInput(op,data.newConstant(a->getSize(),2),1);
  data.opSetOpcode(op,CPUI_INT_SDIV);
  return 1;
}

/// \class RuleDivChain
/// \brief Collapse two consecutive divisions:  `(x / c1) / c2  =>  x / (c1*c2)`
void RuleDivChain::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_DIV);
  oplist.push_back(CPUI_INT_SDIV);
}

int4 RuleDivChain::applyOp(PcodeOp *op,Funcdata &data)

{
  OpCode opc2 = op->code();
  Varnode *constVn2 = op->getIn(1);
  if (!constVn2->isConstant()) return 0;
  Varnode *vn = op->getIn(0);
  if (!vn->isWritten()) return 0;
  PcodeOp *divOp = vn->getDef();
  OpCode opc1 = divOp->code();
  if (opc1 != opc2 && (opc2 != CPUI_INT_DIV || opc1 != CPUI_INT_RIGHT))
    return 0;
  Varnode *constVn1 = divOp->getIn(1);
  if (!constVn1->isConstant()) return 0;
  // If the intermediate result is being used elsewhere, don't apply
  // Its likely collapsing the divisions will interfere with the modulo rules
  if (vn->loneDescend() == (PcodeOp *)0) return 0;
  uintb val1;
  if (opc1 == opc2) {
    val1 = constVn1->getOffset();
  }
  else {	// Unsigned case with INT_RIGHT
    int4 sa = constVn1->getOffset();
    val1 = 1;
    val1 <<= sa;
  }
  Varnode *baseVn = divOp->getIn(0);
  if (baseVn->isFree()) return 0;
  int4 sz = vn->getSize();
  uintb val2 = constVn2->getOffset();
  uintb resval = (val1 * val2) & calc_mask(sz);
  if (resval == 0) return 0;
  if (signbit_negative(val1, sz))
    val1 = (~val1 + 1) & calc_mask(sz);
  if (signbit_negative(val2, sz))
    val2 = (~val2 + 1) & calc_mask(sz);
  int4 bitcount = mostsigbit_set(val1) + mostsigbit_set(val2) + 2;
  if (opc2 == CPUI_INT_DIV && bitcount > sz * 8 ) return 0;	// Unsigned overflow
  if (opc2 == CPUI_INT_SDIV && bitcount > sz * 8 - 2) return 0;	// Signed overflow
  data.opSetInput(op, baseVn, 0);
  data.opSetInput(op,data.newConstant(sz, resval), 1);
  return 1;
}

/// \class RuleSignForm
/// \brief Normalize sign extraction:  `sub(sext(V),c)  =>  V s>> 31`
void RuleSignForm::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleSignForm::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *sextout,*a;
  PcodeOp *sextop;

  sextout = op->getIn(0);
  if (!sextout->isWritten()) return 0;
  sextop = sextout->getDef();
  if (sextop->code() != CPUI_INT_SEXT)
    return 0;
  a = sextop->getIn(0);
  int4 c = op->getIn(1)->getOffset();
  if (c < a->getSize()) return 0;
  if (a->isFree()) return 0;

  data.opSetInput(op,a,0);
  int4 n = 8*a->getSize()-1;
  data.opSetInput(op,data.newConstant(4,n),1);
  data.opSetOpcode(op,CPUI_INT_SRIGHT);
  return 1;
}

/// \class RuleSignForm2
/// \brief Normalize sign extraction:  `sub(sext(V) * small,c) s>> 31  =>  V s>> 31`
///
/// V and small must be small enough so that there is no overflow in the INT_MULT.
/// The SUBPIECE must be extracting the high part of the INT_MULT.
void RuleSignForm2::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SRIGHT);
}

int4 RuleSignForm2::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *constVn = op->getIn(1);
  if (!constVn->isConstant()) return 0;
  Varnode *inVn = op->getIn(0);
  int4 sizeout = inVn->getSize();
  if ((int4)constVn->getOffset() != sizeout*8 -1) return 0;
  if (!inVn->isWritten()) return 0;
  PcodeOp *subOp = inVn->getDef();
  if (subOp->code() != CPUI_SUBPIECE) return 0;
  int4 c = subOp->getIn(1)->getOffset();
  Varnode *multOut = subOp->getIn(0);
  int4 multSize = multOut->getSize();
  if (c + sizeout != multSize) return 0;	// Must be extracting high part
  if (!multOut->isWritten()) return 0;
  PcodeOp *multOp = multOut->getDef();
  if (multOp->code() != CPUI_INT_MULT) return 0;
  int4 slot;
  PcodeOp *sextOp;
  for(slot=0;slot<2;++slot) {			// Search for the INT_SEXT
    Varnode *vn = multOp->getIn(slot);
    if (!vn->isWritten()) continue;
    sextOp = vn->getDef();
    if (sextOp->code() == CPUI_INT_SEXT) break;
  }
  if (slot > 1) return 0;
  Varnode *a = sextOp->getIn(0);
  if (a->isFree() || a->getSize() != sizeout) return 0;
  Varnode *otherVn = multOp->getIn(1-slot);
  // otherVn must be a positive integer and small enough so the INT_MULT can't overflow into the sign-bit
  if (otherVn->isConstant()) {
    if (otherVn->getOffset() > calc_mask(sizeout)) return 0;
    if (2 * sizeout > multSize) return 0;
  }
  else if (otherVn->isWritten()) {
    PcodeOp *zextOp = otherVn->getDef();
    if (zextOp->code() != CPUI_INT_ZEXT) return 0;
    if (zextOp->getIn(0)->getSize() + sizeout > multSize) return 0;
  }
  else
    return 0;
  data.opSetInput(op, a, 0);
  return 0;
}

/// \class RuleSignNearMult
/// \brief Simplify division form: `(V + (V s>> 0x1f)>>(32-n)) & (-1<<n)  =>  (V s/ 2^n) * 2^n`
void RuleSignNearMult::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
}

int4 RuleSignNearMult::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(1)->isConstant()) return 0;
  if (!op->getIn(0)->isWritten()) return 0;
  PcodeOp *addop = op->getIn(0)->getDef();
  if (addop->code() != CPUI_INT_ADD) return 0;
  Varnode *shiftvn;
  PcodeOp *unshiftop = (PcodeOp *)0;
  int4 i;
  for(i=0;i<2;++i) {
    shiftvn = addop->getIn(i);
    if (!shiftvn->isWritten()) continue;
    unshiftop = shiftvn->getDef();
    if (unshiftop->code() == CPUI_INT_RIGHT) {
      if (!unshiftop->getIn(1)->isConstant()) continue;
      break;
    }
  }
  if (i==2) return 0;
  Varnode *x = addop->getIn(1-i);
  if (x->isFree()) return 0;
  int4 n = unshiftop->getIn(1)->getOffset();
  if (n<=0) return 0;
  n = shiftvn->getSize()*8 - n;
  if (n<=0) return 0;
  uintb mask = calc_mask(shiftvn->getSize());
  mask = (mask<<n)&mask;
  if (mask != op->getIn(1)->getOffset()) return 0;
  Varnode *sgnvn = unshiftop->getIn(0);
  if (!sgnvn->isWritten()) return 0;
  PcodeOp *sshiftop = sgnvn->getDef();
  if (sshiftop->code() != CPUI_INT_SRIGHT) return 0;
  if (!sshiftop->getIn(1)->isConstant()) return 0;
  if (sshiftop->getIn(0) != x) return 0;
  int4 val = sshiftop->getIn(1)->getOffset();
  if (val != 8*x->getSize()-1) return 0;

  uintb pow = 1;
  pow <<= n;
  PcodeOp *newdiv = data.newOp(2,op->getAddr());
  data.opSetOpcode(newdiv,CPUI_INT_SDIV);
  Varnode *divvn = data.newUniqueOut(x->getSize(),newdiv);
  data.opSetInput(newdiv,x,0);
  data.opSetInput(newdiv,data.newConstant(x->getSize(),pow),1);
  data.opInsertBefore(newdiv,op);

  data.opSetOpcode(op,CPUI_INT_MULT);
  data.opSetInput(op,divvn,0);
  data.opSetInput(op,data.newConstant(x->getSize(),pow),1);
  return 1;
}

/// \class RuleModOpt
/// \brief Simplify expressions that optimize INT_REM and INT_SREM
void RuleModOpt::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_DIV);
  oplist.push_back(CPUI_INT_SDIV);
}

int4 RuleModOpt::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *multop,*addop;
  Varnode *div,*x,*outvn,*outvn2,*div2;
  list<PcodeOp *>::const_iterator iter1,iter2;

  x = op->getIn(0);
  div = op->getIn(1);
  outvn = op->getOut();
  for(iter1=outvn->beginDescend();iter1!=outvn->endDescend();++iter1) {
    multop = *iter1;
    if (multop->code() != CPUI_INT_MULT) continue;
    div2 = multop->getIn(1);
    if (div2 == outvn)
      div2 = multop->getIn(0);
    // Check that div is 2's complement of div2
    if (div2->isConstant()) {
      if (!div->isConstant()) continue;
      uintb mask = calc_mask(div2->getSize());
      if ((((div2->getOffset() ^ mask)+1)&mask) != div->getOffset())
	continue;
    }
    else {
      if (!div2->isWritten()) continue;
      if (div2->getDef()->code() != CPUI_INT_2COMP) continue;
      if (div2->getDef()->getIn(0) != div) continue;
    }
    outvn2 = multop->getOut();
    for(iter2=outvn2->beginDescend();iter2!=outvn2->endDescend();++iter2) {
      addop = *iter2;
      if (addop->code() != CPUI_INT_ADD) continue;
      Varnode *lvn;
      lvn = addop->getIn(0);
      if (lvn == outvn2)
	lvn = addop->getIn(1);
      if (lvn != x) continue;
      data.opSetInput(addop,x,0);
      if (div->isConstant())
	data.opSetInput(addop,data.newConstant(div->getSize(),div->getOffset()),1);
      else
	data.opSetInput(addop,div,1);
      if (op->code() == CPUI_INT_DIV) // Remainder of proper signedness
	data.opSetOpcode(addop,CPUI_INT_REM);
      else
	data.opSetOpcode(addop,CPUI_INT_SREM);
      return 1;
    }
  }
  return 0;
}

/// \class RuleSignMod2nOpt
/// \brief Convert INT_SREM forms:  `(V + (sign >> (64-n)) & (2^n-1)) - (sign >> (64-n)  =>  V s% 2^n`
///
/// Note: `sign = V s>> 63`  The INT_AND may be performed on a truncated result and then reextended.
void RuleSignMod2nOpt::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_RIGHT);
}

int4 RuleSignMod2nOpt::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(1)->isConstant()) return 0;
  int4 shiftAmt = op->getIn(1)->getOffset();
  Varnode *a = checkSignExtraction(op->getIn(0));
  if (a == (Varnode *)0 || a->isFree()) return 0;
  Varnode *correctVn = op->getOut();
  int4 n = a->getSize() * 8 - shiftAmt;
  uintb mask = 1;
  mask = (mask << n) - 1;
  list<PcodeOp *>::const_iterator iter;
  for(iter=correctVn->beginDescend();iter!=correctVn->endDescend();++iter) {
    PcodeOp *multop = *iter;
    if (multop->code() != CPUI_INT_MULT) continue;
    Varnode *negone = multop->getIn(1);
    if (!negone->isConstant()) continue;
    if (negone->getOffset() != calc_mask(correctVn->getSize())) continue;
    PcodeOp *baseOp = multop->getOut()->loneDescend();
    if (baseOp == (PcodeOp *)0) continue;
    if (baseOp->code() != CPUI_INT_ADD) continue;
    int4 slot = 1 - baseOp->getSlot(multop->getOut());
    Varnode *andOut = baseOp->getIn(slot);
    if (!andOut->isWritten()) continue;
    PcodeOp *andOp = andOut->getDef();
    int4 truncSize = -1;
    if (andOp->code() == CPUI_INT_ZEXT) {	// Look for intervening extension after INT_AND
      andOut = andOp->getIn(0);
      if (!andOut->isWritten()) continue;
      andOp = andOut->getDef();
      if (andOp->code() != CPUI_INT_AND) continue;
      truncSize = andOut->getSize();		// If so we have a truncated form
    }
    else if (andOp->code() != CPUI_INT_AND)
      continue;

    Varnode *constVn = andOp->getIn(1);
    if (!constVn->isConstant()) continue;
    if (constVn->getOffset() != mask) continue;
    Varnode *addOut = andOp->getIn(0);
    if (!addOut->isWritten()) continue;
    PcodeOp *addOp = addOut->getDef();
    if (addOp->code() != CPUI_INT_ADD) continue;
    // Search for "a" as one of the inputs to addOp
    int4 aSlot;
    for(aSlot=0;aSlot < 2;++aSlot) {
      Varnode *vn = addOp->getIn(aSlot);
      if (truncSize >= 0) {
	if (!vn->isWritten()) continue;
	PcodeOp *subOp = vn->getDef();
	if (subOp->code() != CPUI_SUBPIECE) continue;
	if (subOp->getIn(1)->getOffset() != 0) continue;
	vn = subOp->getIn(0);
      }
      if (a == vn) break;
    }
    if (aSlot > 1) continue;
    // Verify that the other input to addOp is an INT_RIGHT by shiftAmt
    Varnode *extVn = addOp->getIn(1-aSlot);
    if (!extVn->isWritten()) continue;
    PcodeOp *shiftOp = extVn->getDef();
    if (shiftOp->code() != CPUI_INT_RIGHT) continue;
    constVn = shiftOp->getIn(1);
    if (!constVn->isConstant()) continue;
    int4 shiftval = constVn->getOffset();
    if (truncSize >= 0)
      shiftval += (a->getSize() - truncSize) * 8;
    if (shiftval != shiftAmt) continue;
    // Verify that the input to INT_RIGHT is a sign extraction of "a"
    extVn = checkSignExtraction(shiftOp->getIn(0));
    if (extVn == (Varnode *)0) continue;
    if (truncSize >= 0) {
      if (!extVn->isWritten()) continue;
      PcodeOp *subOp = extVn->getDef();
      if (subOp->code() != CPUI_SUBPIECE) continue;
      if ((int4)subOp->getIn(1)->getOffset() != truncSize) continue;
      extVn = subOp->getIn(0);
    }
    if (a != extVn) continue;

    data.opSetOpcode(baseOp, CPUI_INT_SREM);
    data.opSetInput(baseOp, a, 0);
    data.opSetInput(baseOp, data.newConstant(a->getSize(), mask+1), 1);
    return 1;
  }
  return 0;
}

/// \brief Verify that the given Varnode is a sign extraction of the form `V s>> 63`
///
/// If not, null is returned.  Otherwise the Varnode whose sign is extracted is returned.
/// \param outVn is the given Varnode
/// \return the Varnode being extracted or null
Varnode *RuleSignMod2nOpt::checkSignExtraction(Varnode *outVn)

{
  if (!outVn->isWritten()) return 0;
  PcodeOp *signOp = outVn->getDef();
  if (signOp->code() != CPUI_INT_SRIGHT)
    return (Varnode *)0;
  Varnode *constVn = signOp->getIn(1);
  if (!constVn->isConstant())
    return (Varnode *)0;
  int4 val = constVn->getOffset();
  Varnode *resVn = signOp->getIn(0);
  int4 insize = resVn->getSize();
  if (val != insize*8 - 1)
    return (Varnode *)0;
  return resVn;
}

/// \class RuleSignMod2Opt
/// \brief Convert INT_SREM form:  `(V - sign)&1 + sign  =>  V s% 2`
///
/// Note: `sign = V s>> 63`  The INT_AND may be performed on a truncated result and then reextended.
/// This is a specialized form of RuleSignMod2nOpt.
void RuleSignMod2Opt::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
}

int4 RuleSignMod2Opt::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *constVn = op->getIn(1);
  if (!constVn->isConstant()) return 0;
  if (constVn->getOffset() != 1) return 0;
  Varnode *addOut = op->getIn(0);
  if (!addOut->isWritten()) return 0;
  PcodeOp *addOp = addOut->getDef();
  if (addOp->code() != CPUI_INT_ADD) return 0;
  int4 multSlot;
  PcodeOp *multOp;
  bool trunc = false;
  for(multSlot = 0;multSlot < 2;++multSlot) {
    Varnode *vn = addOp->getIn(multSlot);
    if (!vn->isWritten()) continue;
    multOp = vn->getDef();
    if (multOp->code() != CPUI_INT_MULT) continue;
    constVn = multOp->getIn(1);
    if (!constVn->isConstant()) continue;
    if (constVn->getOffset() == calc_mask(constVn->getSize())) break;	// Check for INT_MULT by -1
  }
  if (multSlot > 1) return 0;
  Varnode *base = RuleSignMod2nOpt::checkSignExtraction(multOp->getIn(0));
  if (base == (Varnode *)0) return 0;
  Varnode *otherBase = addOp->getIn(1-multSlot);
  if (base != otherBase) {
    if (!base->isWritten() || !otherBase->isWritten()) return 0;
    PcodeOp *subOp = base->getDef();
    if (subOp->code() != CPUI_SUBPIECE) return 0;
    int4 truncAmt = subOp->getIn(1)->getOffset();
    if (truncAmt + base->getSize() != subOp->getIn(0)->getSize()) return 0;	// Must truncate all but high part
    base = subOp->getIn(0);
    subOp = otherBase->getDef();
    if (subOp->code() != CPUI_SUBPIECE) return 0;
    if (subOp->getIn(1)->getOffset() != 0) return 0;
    otherBase = subOp->getIn(0);
    if (otherBase != base) return 0;
    trunc = true;
  }
  if (base->isFree()) return 0;
  Varnode *andOut = op->getOut();
  if (trunc) {
    PcodeOp *extOp = andOut->loneDescend();
    if (extOp == (PcodeOp *)0 || extOp->code() != CPUI_INT_ZEXT) return 0;
    andOut = extOp->getOut();
  }
  list<PcodeOp *>::const_iterator iter;
  for(iter=andOut->beginDescend();iter!=andOut->endDescend();++iter) {
    PcodeOp *rootOp = *iter;
    if (rootOp->code() != CPUI_INT_ADD) continue;
    int4 slot = rootOp->getSlot(andOut);
    otherBase = RuleSignMod2nOpt::checkSignExtraction(rootOp->getIn(1-slot));
    if (otherBase != base) continue;
    data.opSetOpcode(rootOp, CPUI_INT_SREM);
    data.opSetInput(rootOp,base,0);
    data.opSetInput(rootOp,data.newConstant(base->getSize(), 2),1);
    return 1;
  }
  return 0;
}

/// \class RuleSignMod2nOpt2
/// \brief Convert INT_SREM form:  `V - (Vadj & ~(2^n-1)) =>  V s% 2^n`
///
/// Note: `Vadj = (V<0) ? V + 2^n-1 : V`
void RuleSignMod2nOpt2::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_MULT);
}

int4 RuleSignMod2nOpt2::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *constVn = op->getIn(1);
  if (!constVn->isConstant()) return 0;
  uintb mask = calc_mask(constVn->getSize());
  if (constVn->getOffset() != mask) return 0;	// Must be INT_MULT by -1
  Varnode *andOut = op->getIn(0);
  if (!andOut->isWritten()) return 0;
  PcodeOp *andOp = andOut->getDef();
  if (andOp->code() != CPUI_INT_AND) return 0;
  constVn = andOp->getIn(1);
  if (!constVn->isConstant()) return 0;
  uintb npow = (~constVn->getOffset() + 1) & mask;
  if (popcount(npow) != 1) return 0;		// constVn must be of form 11111..000..
  if (npow == 1) return 0;
  Varnode *adjVn = andOp->getIn(0);
  if (!adjVn->isWritten()) return 0;
  PcodeOp *adjOp = adjVn->getDef();
  Varnode *base;
  if (adjOp->code() == CPUI_INT_ADD) {
    if (npow != 2) return 0;		// Special mod 2 form
    base = checkSignExtForm(adjOp);
  }
  else if (adjOp->code() == CPUI_MULTIEQUAL) {
    base = checkMultiequalForm(adjOp, npow);
  }
  else
    return 0;
  if (base == (Varnode *)0) return 0;
  if (base->isFree()) return 0;
  Varnode *multOut = op->getOut();
  list<PcodeOp *>::const_iterator iter;
  for(iter=multOut->beginDescend();iter!=multOut->endDescend();++iter) {
    PcodeOp *rootOp = *iter;
    if (rootOp->code() != CPUI_INT_ADD) continue;
    int4 slot = rootOp->getSlot(multOut);
    if (rootOp->getIn(1-slot) != base) continue;
    if (slot == 0)
      data.opSetInput(rootOp,base,0);
    data.opSetInput(rootOp, data.newConstant(base->getSize(),npow), 1);
    data.opSetOpcode(rootOp, CPUI_INT_SREM);
    return 1;
  }
  return 0;
}

/// \brief Verify a form of `V - (V s>> 0x3f)`
///
/// \param op is the possible root INT_ADD of the form
/// \return the Varnode V in the form, or null if the form doesn't match
Varnode *RuleSignMod2nOpt2::checkSignExtForm(PcodeOp *op)

{
  int4 slot;
  for(slot=0;slot<2;++slot) {
    Varnode *minusVn = op->getIn(slot);
    if (!minusVn->isWritten()) continue;
    PcodeOp *multOp = minusVn->getDef();
    if (multOp->code() != CPUI_INT_MULT) continue;
    Varnode *constVn = multOp->getIn(1);
    if (!constVn->isConstant()) continue;
    if (constVn->getOffset() != calc_mask(constVn->getSize())) continue;
    Varnode *base = op->getIn(1-slot);
    Varnode *signExt = multOp->getIn(0);
    if (!signExt->isWritten()) continue;
    PcodeOp *shiftOp = signExt->getDef();
    if (shiftOp->code() != CPUI_INT_SRIGHT) continue;
    if (shiftOp->getIn(0) != base) continue;
    constVn = shiftOp->getIn(1);
    if (!constVn->isConstant()) continue;
    if ((int4)constVn->getOffset() != 8*base->getSize() - 1) continue;
    return base;
  }
  return (Varnode *)0;
}

/// \brief Verify an \e if block like `V = (V s< 0) ? V + 2^n-1 : V`
///
/// \param op is the MULTIEQUAL
/// \param npow is the constant 2^n
/// \return the Varnode V in the form, or null if the form doesn't match
Varnode *RuleSignMod2nOpt2::checkMultiequalForm(PcodeOp *op,uintb npow)

{
  if (op->numInput() != 2) return (Varnode *)0;
  npow -= 1;		// 2^n - 1
  int4 slot;
  Varnode *base;
  for(slot=0;slot<op->numInput();++slot) {
    Varnode *addOut = op->getIn(slot);
    if (!addOut->isWritten()) continue;
    PcodeOp *addOp = addOut->getDef();
    if (addOp->code() != CPUI_INT_ADD) continue;
    Varnode *constVn = addOp->getIn(1);
    if (!constVn->isConstant()) continue;
    if (constVn->getOffset() != npow) continue;
    base = addOp->getIn(0);
    Varnode *otherBase = op->getIn(1-slot);
    if (otherBase == base)
      break;
  }
  if (slot > 1) return (Varnode *)0;
  BlockBasic *bl = op->getParent();
  int4 innerSlot = 0;
  BlockBasic *inner = (BlockBasic*)bl->getIn(innerSlot);
  if (inner->sizeOut() != 1 || inner->sizeIn() != 1) {
    innerSlot = 1;
    inner = (BlockBasic*)bl->getIn(innerSlot);
    if (inner->sizeOut() != 1 || inner->sizeIn() != 1)
      return (Varnode *)0;
  }
  BlockBasic *decision = (BlockBasic*)inner->getIn(0);
  if (bl->getIn(1 - innerSlot) != decision) return (Varnode *)0;
  PcodeOp *cbranch = decision->lastOp();
  if (cbranch == (PcodeOp*)0 || cbranch->code() != CPUI_CBRANCH) return (Varnode *)0;
  Varnode *boolVn = cbranch->getIn(1);
  if (!boolVn->isWritten()) return (Varnode *)0;
  PcodeOp *lessOp = boolVn->getDef();
  if (lessOp->code() != CPUI_INT_SLESS) return (Varnode *)0;
  if (!lessOp->getIn(1)->isConstant()) return (Varnode *)0;
  if (lessOp->getIn(1)->getOffset() != 0) return (Varnode *)0;
  FlowBlock *negBlock = cbranch->isBooleanFlip() ? decision->getFalseOut() : decision->getTrueOut();
  int4 negSlot = (negBlock == inner) ? innerSlot : (1-innerSlot);
  if (negSlot != slot) return (Varnode *)0;
  return base;
}

/// \class RuleSegment
/// \brief Propagate constants through a SEGMENTOP
void RuleSegment::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SEGMENTOP);
}

int4 RuleSegment::applyOp(PcodeOp *op,Funcdata &data)

{
  SegmentOp *segdef = data.getArch()->userops.getSegmentOp(op->getIn(0)->getSpaceFromConst()->getIndex());
  if (segdef == (SegmentOp *)0)
    throw LowlevelError("Segment operand missing definition");

  Varnode *vn1 = op->getIn(1);
  Varnode *vn2 = op->getIn(2);

  if (vn1->isConstant() && vn2->isConstant()) {
    vector<uintb> bindlist;
    bindlist.push_back(vn1->getOffset());
    bindlist.push_back(vn2->getOffset());
    uintb val = segdef->execute(bindlist);
    data.opRemoveInput(op,2);
    data.opRemoveInput(op,1);
    data.opSetInput(op,data.newConstant(op->getOut()->getSize(),val),0);
    data.opSetOpcode(op,CPUI_COPY);
    return 1;
  }
  else if (segdef->hasFarPointerSupport()) {
    // If the hi and lo pieces come from a contigouous source
    if (!contiguous_test(vn1,vn2)) return 0;
    Varnode *whole = findContiguousWhole(data,vn1,vn2);
    if (whole == (Varnode *)0) return 0;
    if (whole->isFree()) return 0;
    // Use the contiguous source as the whole pointer
    data.opRemoveInput(op,2);
    data.opRemoveInput(op,1);
    data.opSetInput(op,whole,0);
    data.opSetOpcode(op,CPUI_COPY);
    return 1;
  }
  return 0;
}

/// \class RuleSubvarAnd
/// \brief Perform SubVariableFlow analysis triggered by INT_AND
void RuleSubvarAnd::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
}

int4 RuleSubvarAnd::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(1)->isConstant()) return 0;
  Varnode *vn = op->getIn(0);
  Varnode *outvn = op->getOut();
  //  if (vn->getSize() != 1) return 0; // Only for bitsize variables
  if (outvn->getConsume() != op->getIn(1)->getOffset()) return 0;
  if ((outvn->getConsume() & 1)==0) return 0;
  uintb cmask;
  if (outvn->getConsume() == (uintb)1)
    cmask = (uintb)1;
  else {
    cmask = calc_mask(vn->getSize());
    cmask >>=8;
    while(cmask != 0) {
      if (cmask == outvn->getConsume()) break;
      cmask >>=8;
    }
  }
  if (cmask == 0) return 0;
  //  if (vn->getConsume() == 0) return 0;
  //  if ((vn->getConsume() & 0xff)==0xff) return 0;
  //  if (op->getIn(1)->getOffset() != (uintb)1) return 0;
  if (op->getOut()->hasNoDescend()) return 0;
  SubvariableFlow subflow(&data,vn,cmask,false,false,false);
  if (!subflow.doTrace()) return 0;
  subflow.doReplacement();
  return 1;
}

/// \class RuleSubvarSubpiece
/// \brief Perform SubVariableFlow analysis triggered by SUBPIECE
void RuleSubvarSubpiece::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleSubvarSubpiece::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getIn(0);
  Varnode *outvn = op->getOut();
  int4 flowsize = outvn->getSize();
  uintb mask = calc_mask( flowsize );
  mask <<= 8*((int4)op->getIn(1)->getOffset());
  bool aggressive = outvn->isPtrFlow();
  if (!aggressive) {
    if (mask != vn->getConsume()) return 0;
    if (op->getOut()->hasNoDescend()) return 0;
  }
  bool big = false;
  if (flowsize >= 8 && vn->isInput()) {
    // Vector register inputs getting truncated to what actually gets used
    // happens occasionally.  We let SubvariableFlow deal with this special case
    // to avoid overlapping inputs
    // TODO: ActionLaneDivide should be handling this
    if (vn->loneDescend() == op)
      big = true;
  }
  SubvariableFlow subflow(&data,vn,mask,aggressive,false,big);
  if (!subflow.doTrace()) return 0;
  subflow.doReplacement();
  return 1;
}

/// \class RuleSplitFlow
/// \brief Try to detect and split artificially joined Varnodes
///
/// Look for SUBPIECE coming from a PIECE that has come through INDIRECTs and/or MULTIEQUAL
/// Then: check if the input to SUBPIECE can be viewed as two independent pieces
/// If so:  split the pieces into independent data-flows
void RuleSplitFlow::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_SUBPIECE);
}

int4 RuleSplitFlow::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 loSize = (int4)op->getIn(1)->getOffset();
  if (loSize == 0)			// Make sure SUBPIECE doesn't take least significant part
    return 0;
  Varnode *vn = op->getIn(0);
  if (!vn->isWritten())
    return 0;
  if (vn->isPrecisLo() || vn->isPrecisHi())
    return 0;
  if (op->getOut()->getSize() + loSize != vn->getSize())
    return 0;				// Make sure SUBPIECE is taking most significant part
  PcodeOp *concatOp = (PcodeOp *)0;
  PcodeOp *multiOp = vn->getDef();
  while(multiOp->code() == CPUI_INDIRECT) {	// PIECE may come through INDIRECT
    Varnode *tmpvn = multiOp->getIn(0);
    if (!tmpvn->isWritten()) return 0;
    multiOp = tmpvn->getDef();
  }
  if (multiOp->code() == CPUI_PIECE) {
    if (vn->getDef() != multiOp)
      concatOp = multiOp;
  }
  else if (multiOp->code() == CPUI_MULTIEQUAL) {	// Otherwise PIECE comes through MULTIEQUAL
    for(int4 i=0;i<multiOp->numInput();++i) {
      Varnode *invn = multiOp->getIn(i);
      if (!invn->isWritten()) continue;
      PcodeOp *tmpOp = invn->getDef();
      if (tmpOp->code() == CPUI_PIECE) {
	concatOp = tmpOp;
	break;
      }
    }
  }
  if (concatOp == (PcodeOp *)0)			// Didn't find the concatenate
    return 0;
  if (concatOp->getIn(1)->getSize() != loSize)
    return 0;
  SplitFlow splitFlow(&data,vn,loSize);
  if (!splitFlow.doTrace()) return 0;
  splitFlow.apply();
  return 1;
}

/// \class RulePtrFlow
/// \brief Mark Varnode and PcodeOp objects that are carrying or operating on pointers
///
/// This is used on architectures where the data-flow for pointer values needs to be
/// truncated.  This marks the places where the truncation needs to happen.  Then
/// the SubvariableFlow actions do the actual truncation.
RulePtrFlow::RulePtrFlow(const string &g,Architecture *conf)
  : Rule( g, 0, "ptrflow")
{
  glb = conf;
  hasTruncations = glb->getDefaultDataSpace()->isTruncated();
}

void RulePtrFlow::getOpList(vector<uint4> &oplist) const

{
  if (!hasTruncations) return;	// Only stick ourselves into pool if aggresiveness is turned on
  oplist.push_back(CPUI_STORE);
  oplist.push_back(CPUI_LOAD);
  oplist.push_back(CPUI_COPY);
  oplist.push_back(CPUI_MULTIEQUAL);
  oplist.push_back(CPUI_INDIRECT);
  oplist.push_back(CPUI_INT_ADD);
  oplist.push_back(CPUI_CALLIND);
  oplist.push_back(CPUI_BRANCHIND);
  oplist.push_back(CPUI_PTRSUB);
  oplist.push_back(CPUI_PTRADD);
}

/// Set \e ptrflow property on PcodeOp only if it is propagating
///
/// \param op is the PcodeOp
/// \return \b true if ptrflow property is newly set
bool RulePtrFlow::trialSetPtrFlow(PcodeOp *op)

{
  switch(op->code()) {
  case CPUI_COPY:
  case CPUI_MULTIEQUAL:
  case CPUI_INT_ADD:
  case CPUI_INDIRECT:
  case CPUI_PTRSUB:
  case CPUI_PTRADD:
    if (!op->isPtrFlow()) {
      op->setPtrFlow();
      return true;
    }
    break;
  default:
    break;
  }
  return false;
}

/// \brief Propagate \e ptrflow property to given Varnode and the defining PcodeOp
///
/// \param vn is the given Varnode
/// \return \b true if a change was made
bool RulePtrFlow::propagateFlowToDef(Varnode *vn)

{
  bool madeChange = false;
  if (!vn->isPtrFlow()) {
    vn->setPtrFlow();
    madeChange = true;
  }
  if (!vn->isWritten()) return madeChange;
  PcodeOp *op = vn->getDef();
  if (trialSetPtrFlow(op))
    madeChange = true;
  return madeChange;
}

/// \brief Propagate \e ptrflow property to given Varnode and to descendant PcodeOps
///
/// \param vn is the given Varnode
/// \return \b true if a change was made
bool RulePtrFlow::propagateFlowToReads(Varnode *vn)

{
  list<PcodeOp *>::const_iterator iter;
  bool madeChange = false;
  if (!vn->isPtrFlow()) {
    vn->setPtrFlow();
    madeChange = true;
  }
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    if (trialSetPtrFlow(op))
      madeChange = true;
  }
  return madeChange;
}

/// \brief Truncate pointer Varnode being read by given PcodeOp
///
/// Insert a SUBPIECE operation truncating the value to the size necessary
/// for a pointer into the given address space. Update the PcodeOp input.
/// \param spc is the given address space
/// \param op is the given PcodeOp reading the pointer
/// \param vn is the pointer Varnode
/// \param slot is the input slot reading the pointer
/// \param data is the function being analyzed
/// \return the new truncated Varnode
Varnode *RulePtrFlow::truncatePointer(AddrSpace *spc,PcodeOp *op,Varnode *vn,int4 slot,Funcdata &data)

{
  Varnode *newvn;
  PcodeOp *truncop = data.newOp(2,op->getAddr());
  data.opSetOpcode(truncop,CPUI_SUBPIECE);
  data.opSetInput(truncop,data.newConstant(vn->getSize(),0),1);
  if (vn->getSpace()->getType() == IPTR_INTERNAL) {
    newvn = data.newUniqueOut(spc->getAddrSize(),truncop);
  }
  else {
    Address addr = vn->getAddr();
    if (addr.isBigEndian())
      addr = addr + (vn->getSize() - spc->getAddrSize());
    addr.renormalize(spc->getAddrSize());
    newvn = data.newVarnodeOut(spc->getAddrSize(),addr,truncop);
  }
  data.opSetInput(op,newvn,slot);
  data.opSetInput(truncop,vn,0);
  data.opInsertBefore(truncop,op);
  return newvn;
}

int4 RulePtrFlow::applyOp(PcodeOp *op,Funcdata &data)

{ // Push pointer-ness 
  Varnode *vn;
  AddrSpace *spc;
  int4 madeChange = 0;

  switch(op->code()) {
  case CPUI_LOAD:
  case CPUI_STORE:
    vn = op->getIn(1);
    spc = op->getIn(0)->getSpaceFromConst();
    if (vn->getSize() > spc->getAddrSize()) {
      vn = truncatePointer(spc,op,vn,1,data);
      madeChange = 1;
    }
    if (propagateFlowToDef(vn))
      madeChange = 1;
    break;
  case CPUI_CALLIND:
  case CPUI_BRANCHIND:
    vn = op->getIn(0);
    spc = data.getArch()->getDefaultCodeSpace();
    if (vn->getSize() > spc->getAddrSize()) {
      vn = truncatePointer(spc,op,vn,0,data);
      madeChange = 1;
    }
    if (propagateFlowToDef(vn))
      madeChange = 1;
    break;
  case CPUI_NEW:
    vn = op->getOut();
    if (propagateFlowToReads(vn))
      madeChange = 1;
    break;
  case CPUI_INDIRECT:
    if (!op->isPtrFlow()) return 0;
    vn = op->getOut();
    if (propagateFlowToReads(vn))
      madeChange = 1;
    vn = op->getIn(0);
    if (propagateFlowToDef(vn))
      madeChange = 1;
    break;
  case CPUI_COPY:
  case CPUI_PTRSUB:
  case CPUI_PTRADD:
    if (!op->isPtrFlow()) return 0;
    vn = op->getOut();
    if (propagateFlowToReads(vn))
      madeChange = 1;
    vn = op->getIn(0);
    if (propagateFlowToDef(vn))
      madeChange = 1;
    break;
  case CPUI_MULTIEQUAL:
  case CPUI_INT_ADD:
    if (!op->isPtrFlow()) return 0;
    vn = op->getOut();
    if (propagateFlowToReads(vn))
      madeChange = 1;
    for(int4 i=0;i<op->numInput();++i) {
      vn = op->getIn(i);
      if (propagateFlowToDef(vn))
	madeChange = 1;
    }
    break;
  default:
    break;
  }
  return madeChange;
}

/// \class RuleSubvarCompZero
/// \brief Perform SubvariableFlow analysis triggered by testing of a single bit
///
/// Given a comparison (INT_EQUAL or INT_NOTEEQUAL_ to a constant,
/// check that input has only 1 bit that can possibly be non-zero
/// and that the constant is testing this.  This then triggers
/// the full SubvariableFlow analysis.
void RuleSubvarCompZero::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_NOTEQUAL);
  oplist.push_back(CPUI_INT_EQUAL);
}

int4 RuleSubvarCompZero::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(1)->isConstant()) return 0;
  Varnode *vn = op->getIn(0);
  uintb mask = vn->getNZMask();
  int4 bitnum = leastsigbit_set(mask);
  if (bitnum == -1) return 0;
  if ((mask >> bitnum) != 1) return 0; // Check if only one bit active

  // Check if the active bit is getting tested
  if ((op->getIn(1)->getOffset()!=mask)&&
      (op->getIn(1)->getOffset()!=0))
    return 0;

  if (op->getOut()->hasNoDescend()) return 0;
  // We do a basic check that the stream from which it looks like
  // the bit is getting pulled is not fully consumed
  if (vn->isWritten()) {
    PcodeOp *andop = vn->getDef();
    if (andop->numInput()==0) return 0;
    Varnode *vn0 = andop->getIn(0);
    switch(andop->code()) {
    case CPUI_INT_AND:
    case CPUI_INT_OR:
    case CPUI_INT_RIGHT:
      {
	if (vn0->isConstant()) return 0;
	uintb mask0 = vn0->getConsume() & vn0->getNZMask();
	uintb wholemask = calc_mask(vn0->getSize()) & mask0;
	// We really need a popcnt here
	// We want: if the number of bits that are both consumed
	// and not known to be zero are "big" then don't continue
	// because it doesn't look like a few bits getting manipulated
	// within a status register
	if ((wholemask & 0xff)==0xff) return 0;
	if ((wholemask & 0xff00)==0xff00) return 0;
      }
      break;
    default:
      break;
    }
  }
  
  SubvariableFlow subflow(&data,vn,mask,false,false,false);
  if (!subflow.doTrace()) {
    return 0;
  }
  subflow.doReplacement();
  return 1;
}

/// \class RuleSubvarShift
/// \brief Perform SubvariableFlow analysis triggered by INT_RIGHT
///
/// If the INT_RIGHT input has only 1 bit that can possibly be non-zero
/// and it is getting shifted into the least significant bit position,
/// trigger the full SubvariableFlow analysis.
void RuleSubvarShift::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_RIGHT);
}

int4 RuleSubvarShift::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getIn(0);
  if (vn->getSize() != 1) return 0;
  if (!op->getIn(1)->isConstant()) return 0;
  int4 sa = (int4)op->getIn(1)->getOffset();
  uintb mask = vn->getNZMask();
  if ((mask >> sa) != (uintb)1) return 0; // Pulling out a single bit
  mask = (mask >> sa) << sa;
  if (op->getOut()->hasNoDescend()) return 0;

  SubvariableFlow subflow(&data,vn,mask,false,false,false);
  if (!subflow.doTrace()) return 0;
  subflow.doReplacement();
  return 1;
}

/// \class RuleSubvarZext
/// \brief Perform SubvariableFlow analysis triggered by INT_ZEXT
void RuleSubvarZext::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ZEXT);
}

int4 RuleSubvarZext::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getOut();
  Varnode *invn = op->getIn(0);
  uintb mask = calc_mask(invn->getSize());

  SubvariableFlow subflow(&data,vn,mask,invn->isPtrFlow(),false,false);
  if (!subflow.doTrace()) return 0;
  subflow.doReplacement();
  return 1;
}

/// \class RuleSubvarSext
/// \brief Perform SubvariableFlow analysis triggered by INT_SEXT
void RuleSubvarSext::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SEXT);
}

int4 RuleSubvarSext::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getOut();
  Varnode *invn = op->getIn(0);
  uintb mask = calc_mask(invn->getSize());

  SubvariableFlow subflow(&data,vn,mask,isaggressive,true,false);
  if (!subflow.doTrace()) return 0;
  subflow.doReplacement();
  return 1;
}

void RuleSubvarSext::reset(Funcdata &data)

{
  isaggressive = data.getArch()->aggressive_ext_trim;
}

/// \class RuleSubfloatConvert
/// \brief Perform SubfloatFlow analysis triggered by FLOAT_FLOAT2FLOAT
void RuleSubfloatConvert::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_FLOAT_FLOAT2FLOAT);
}

int4 RuleSubfloatConvert::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *invn = op->getIn(0);
  Varnode *outvn = op->getOut();
  int4 insize = invn->getSize();
  int4 outsize = outvn->getSize();
  if (outsize > insize) {
    SubfloatFlow subflow(&data,outvn,insize);
    if (!subflow.doTrace()) return 0;
    subflow.apply();
  }
  else {
    SubfloatFlow subflow(&data,invn,outsize);
    if (!subflow.doTrace()) return 0;
    subflow.apply();
  }
  return 1;
}

/// \class RuleNegateNegate
/// \brief Simplify INT_NEGATE chains:  `~~V  =>  V`
void RuleNegateNegate::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_NEGATE);
}

int4 RuleNegateNegate::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn1 = op->getIn(0);
  if (!vn1->isWritten()) return 0;
  PcodeOp *neg2 = vn1->getDef();
  if (neg2->code() != CPUI_INT_NEGATE)
    return 0;
  Varnode *vn2 = neg2->getIn(0);
  if (vn2->isFree()) return 0;
  data.opSetInput(op,vn2,0);
  data.opSetOpcode(op,CPUI_COPY);
  return 1;
}

/// Check if given Varnode is a boolean value and break down its construction.
/// Varnode is assumed to be an input to a MULTIEQUAL
/// \param vn is the given root Varnode
/// \return \b true if it is a boolean expression
bool RuleConditionalMove::BoolExpress::initialize(Varnode *vn)

{
  if (!vn->isWritten()) return false;
  op = vn->getDef();
  opc = op->code();
  switch(opc) {
  case CPUI_COPY:
    in0 = op->getIn(0);
    if (in0->isConstant()) {
      optype = 0;
      val = in0->getOffset();
      return ((val & ~((uintb)1)) == 0);
    }
    return false;
  case CPUI_INT_EQUAL:
  case CPUI_INT_NOTEQUAL:
  case CPUI_INT_SLESS:
  case CPUI_INT_SLESSEQUAL:
  case CPUI_INT_LESS:
  case CPUI_INT_LESSEQUAL:
  case CPUI_INT_CARRY:
  case CPUI_INT_SCARRY:
  case CPUI_INT_SBORROW:
  case CPUI_BOOL_XOR:
  case CPUI_BOOL_AND:
  case CPUI_BOOL_OR:
  case CPUI_FLOAT_EQUAL:
  case CPUI_FLOAT_NOTEQUAL:
  case CPUI_FLOAT_LESS:
  case CPUI_FLOAT_LESSEQUAL:
    if (op->numInput() != 2) return false;
    in0 = op->getIn(0);
    in1 = op->getIn(1);
    optype = 2;
    break;
  case CPUI_BOOL_NEGATE:
  case CPUI_FLOAT_NAN:
    in0 = op->getIn(0);
    optype = 1;
    break;
  default:
    return false;
  }
  return true;
}

/// Evaluate if \b this expression can be easily propagated past a merge point.
/// Also can the Varnode be used past the merge, or does its value need to be reconstructed.
/// \param root is the split point
/// \param branch is the block on which the expression exists and after which is the merge
/// \return \b true if the expression can be propagated
bool RuleConditionalMove::BoolExpress::evaluatePropagation(FlowBlock *root,FlowBlock *branch)

{
  mustreconstruct = false;
  if (optype==0) return true;	// Constants can always be propagated
  if (root == branch) return true; // Can always propagate if there is no branch
  if (op->getParent() != branch) return true; // Can propagate if value formed before branch
  mustreconstruct = true;	// Final op is performed in branch, so it must be reconstructed
  if (in0->isFree() && !in0->isConstant()) return false;
  if (in0->isWritten() && (in0->getDef()->getParent()==branch)) return false;
  if (optype == 2) {
    if (in1->isFree() && !in1->isConstant()) return false;
    if (in1->isWritten() && (in1->getDef()->getParent()==branch)) return false;
  }
  return true;
}

/// Produce the boolean Varnode to use after the merge.
/// Either reuse the existing Varnode or reconstruct it,
/// making sure the expression does not depend on data in the branch.
/// \param insertop is point at which any reconstruction should be inserted
/// \param data is the function being analyzed
/// \return the Varnode representing the boolean expression
Varnode *RuleConditionalMove::BoolExpress::constructBool(PcodeOp *insertop,Funcdata &data)

{
  Varnode *resvn;
  if (mustreconstruct) {
    PcodeOp *newop = data.newOp(optype,op->getAddr());	// Keep the original address
    data.opSetOpcode(newop, opc );
    resvn = data.newUniqueOut(1,newop);
    if (in0->isConstant())
      in0 = data.newConstant(in0->getSize(),in0->getOffset());
    data.opSetInput(newop,in0,0);
    if (optype == 2) {		// Binary op
      if (in1->isConstant())
	in1 = data.newConstant(in1->getSize(),in1->getOffset());
      data.opSetInput(newop,in1,1);
    }
    data.opInsertBefore(newop,insertop);
  }
  else {
    if (optype == 0)
      resvn = data.newConstant(1,val);
    else
      resvn = op->getOut();
  }
  return resvn;
}

/// \brief Construct the boolean negation of a given boolean Varnode
///
/// \param vn is the given Varnode
/// \param op is the point at which to insert the BOOL_NEGATE op
/// \param data is the function being analyzed
/// \return the output of the new op
Varnode *RuleConditionalMove::constructNegate(Varnode *vn,PcodeOp *op,Funcdata &data)

{
  PcodeOp *negateop = data.newOp(1,op->getAddr());
  data.opSetOpcode(negateop,CPUI_BOOL_NEGATE);
  Varnode *resvn = data.newUniqueOut(1,negateop);
  data.opSetInput(negateop,vn,0);
  data.opInsertBefore(negateop,op);
  return resvn;
}

/// \class RuleConditionalMove
/// \brief Simplify various conditional move situations
///
/// The simplest situation is when the code looks like
/// \code
/// if (boolcond)
///   res0 = 1;
/// else
///   res1 = 0;
/// res = ? res0 : res1
/// \endcode
///
/// which gets simplified to `res = zext(boolcond)`
/// The other major variation looks like
/// \code
/// if (boolcond)
///    res0 = boolcond;
/// else
///    res1 = differentcond;
/// res = ? res0 : res1
/// \endcode
///
/// which gets simplified to `res = boolcond || differentcond`
void RuleConditionalMove::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_MULTIEQUAL);
}

int4 RuleConditionalMove::applyOp(PcodeOp *op,Funcdata &data)

{
  BoolExpress bool0;
  BoolExpress bool1;
  BlockBasic *bb;
  FlowBlock *inblock0,*inblock1;
  FlowBlock *rootblock0,*rootblock1;

  if (op->numInput() != 2) return 0; // MULTIEQUAL must have exactly 2 inputs

  if (!bool0.initialize(op->getIn(0))) return 0;
  if (!bool1.initialize(op->getIn(1))) return 0;

  // Look for the situation
  //               inblock0
  //             /         |
  // rootblock ->            bb
  //             |         /
  //               inblock1
  //
  // Either inblock0 or inblock1 can be empty
  bb = op->getParent();
  inblock0 = bb->getIn(0);
  if (inblock0->sizeOut() == 1) {
    if (inblock0->sizeIn() != 1) return 0;
    rootblock0 = inblock0->getIn(0);
  }
  else
    rootblock0 = inblock0;
  inblock1 = bb->getIn(1);
  if (inblock1->sizeOut() == 1) {
    if (inblock1->sizeIn() != 1) return 0;
    rootblock1 = inblock1->getIn(0);
  }
  else
    rootblock1 = inblock1;
  if (rootblock0 != rootblock1) return 0;

  // rootblock must end in CBRANCH, which gives the boolean for the conditional move
  PcodeOp *cbranch = rootblock0->lastOp();
  if (cbranch == (PcodeOp *)0) return 0;
  if (cbranch->code() != CPUI_CBRANCH) return 0;

  if (!bool0.evaluatePropagation(rootblock0,inblock0)) return 0;
  if (!bool1.evaluatePropagation(rootblock0,inblock1)) return 0;

  bool path0istrue;
  if (rootblock0 != inblock0)
    path0istrue = (rootblock0->getTrueOut() == inblock0);
  else
    path0istrue = (rootblock0->getTrueOut() != inblock1);
  if (cbranch->isBooleanFlip())
    path0istrue = !path0istrue;

  if (!bool0.isConstant() && !bool1.isConstant()) {
    if (inblock0 == rootblock0) {
      Varnode *boolvn = cbranch->getIn(1);
      bool andorselect = path0istrue;
      // Force 0 branch to either be boolvn OR !boolvn
      if (boolvn != op->getIn(0)) {
	if (!boolvn->isWritten()) return 0;
	PcodeOp *negop = boolvn->getDef();
	if (negop->code() != CPUI_BOOL_NEGATE) return 0;
	if (negop->getIn(0) != op->getIn(0)) return 0;
	andorselect = !andorselect;
      }
      OpCode opc = andorselect ? CPUI_BOOL_OR : CPUI_BOOL_AND;
      data.opUninsert( op );
      data.opSetOpcode(op, opc);
      data.opInsertBegin(op, bb);
      Varnode *firstvn = bool0.constructBool(op,data);
      Varnode *secondvn = bool1.constructBool(op,data);
      data.opSetInput(op,firstvn,0);
      data.opSetInput(op,secondvn,1);
      return 1;
    }
    else if (inblock1 == rootblock0) {
      Varnode *boolvn = cbranch->getIn(1);
      bool andorselect = !path0istrue;
      // Force 1 branch to either be boolvn OR !boolvn
      if (boolvn != op->getIn(1)) {
	if (!boolvn->isWritten()) return 0;
	PcodeOp *negop = boolvn->getDef();
	if (negop->code() != CPUI_BOOL_NEGATE) return 0;
	if (negop->getIn(0) != op->getIn(1)) return 0;
	andorselect = !andorselect;
      }
      data.opUninsert( op );
      OpCode opc = andorselect ? CPUI_BOOL_OR : CPUI_BOOL_AND;
      data.opSetOpcode(op, opc);
      data.opInsertBegin(op, bb);
      Varnode *firstvn = bool1.constructBool(op,data);
      Varnode *secondvn = bool0.constructBool(op,data);
      data.opSetInput(op,firstvn,0);
      data.opSetInput(op,secondvn,1);
      return 1;
    }
    return 0;
  }

  // Below here some change is being made
  data.opUninsert( op );	// Changing from MULTIEQUAL, this should be reinserted
  int4 sz = op->getOut()->getSize();
  if (bool0.isConstant() && bool1.isConstant()) {
    if (bool0.getVal() == bool1.getVal()) {
      data.opRemoveInput(op,1);
      data.opSetOpcode(op,CPUI_COPY);
      data.opSetInput(op, data.newConstant( sz, bool0.getVal() ), 0 );
      data.opInsertBegin(op,bb);
    }
    else {
      data.opRemoveInput(op,1);
      Varnode *boolvn = cbranch->getIn(1);
      bool needcomplement = ( (bool0.getVal()==0) == path0istrue );
      if (sz == 1) {
	if (needcomplement)
	  data.opSetOpcode(op,CPUI_BOOL_NEGATE);
	else
	  data.opSetOpcode(op,CPUI_COPY);
	data.opInsertBegin(op,bb);
	data.opSetInput(op, boolvn, 0);
      }
      else {
	data.opSetOpcode(op,CPUI_INT_ZEXT);
	data.opInsertBegin(op,bb);
	if (needcomplement)
	  boolvn = constructNegate(boolvn,op,data);
	data.opSetInput(op,boolvn,0);
      }
    }
  }
  else if (bool0.isConstant()) {
    bool needcomplement = (path0istrue != (bool0.getVal()!=0));
    OpCode opc = (bool0.getVal()!=0) ? CPUI_BOOL_OR : CPUI_BOOL_AND;
    data.opSetOpcode(op,opc);
    data.opInsertBegin(op,bb);
    Varnode *boolvn = cbranch->getIn(1);
    if (needcomplement)
      boolvn = constructNegate(boolvn,op,data);
    Varnode *body1 = bool1.constructBool(op,data);
    data.opSetInput(op,boolvn,0);
    data.opSetInput(op,body1,1);
  }
  else {			// bool1 must be constant
    bool needcomplement = (path0istrue == (bool1.getVal()!=0));
    OpCode opc = (bool1.getVal()!=0) ? CPUI_BOOL_OR : CPUI_BOOL_AND;
    data.opSetOpcode(op,opc);
    data.opInsertBegin(op,bb);
    Varnode *boolvn = cbranch->getIn(1);
    if (needcomplement)
      boolvn = constructNegate(boolvn,op,data);
    Varnode *body0 = bool0.constructBool(op,data);
    data.opSetInput(op,boolvn,0);
    data.opSetInput(op,body0,1);
  }
  return 1;
}

/// \class RuleFloatCast
/// \brief Replace (casttosmall)(casttobig)V with identity or with single cast
void RuleFloatCast::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_FLOAT_FLOAT2FLOAT);
  oplist.push_back(CPUI_FLOAT_TRUNC);
}

int4 RuleFloatCast::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn1 = op->getIn(0);
  if (!vn1->isWritten()) return 0;
  PcodeOp *castop = vn1->getDef();
  OpCode opc2 = castop->code();
  if ((opc2 != CPUI_FLOAT_FLOAT2FLOAT)&&(opc2 != CPUI_FLOAT_INT2FLOAT))
    return 0;
  OpCode opc1 = op->code();
  Varnode *vn2 = castop->getIn(0);
  int4 insize1 = vn1->getSize();
  int4 insize2 = vn2->getSize();
  int4 outsize = op->getOut()->getSize();

  if (vn2->isFree()) return 0;	// Don't propagate free
  
  if ((opc2 == CPUI_FLOAT_FLOAT2FLOAT)&&(opc1 == CPUI_FLOAT_FLOAT2FLOAT)) {
    if (insize1 > outsize) {	// op is superfluous
      data.opSetInput(op,vn2,0);
      if (outsize == insize2)
	data.opSetOpcode(op,CPUI_COPY);	// We really have the identity
      return 1;
    }
    else if (insize2 < insize1) { // Convert two increases -> one combined increase
      data.opSetInput(op,vn2,0);
      return 1;
    }
  }
  else if ((opc2 == CPUI_FLOAT_INT2FLOAT)&&(opc1 == CPUI_FLOAT_FLOAT2FLOAT)) {
    // Convert integer straight into final float size
    data.opSetInput(op,vn2,0);
    data.opSetOpcode(op,CPUI_FLOAT_INT2FLOAT);
    return 1;
  }
  else if ((opc2 == CPUI_FLOAT_FLOAT2FLOAT)&&(opc1 == CPUI_FLOAT_TRUNC)) {
    // Convert float straight into final integer
    data.opSetInput(op,vn2,0);
    return 1;
  }

  return 0;
}

/// \class RuleIgnoreNan
/// \brief Remove certain NaN operations by assuming their result is always \b false
///
/// This rule can be configured to remove either all FLOAT_NAN operations or only those that
/// protect floating-point comparisons.
void RuleIgnoreNan::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_FLOAT_NAN);
}

/// \brief Check if a boolean Varnode incorporates a floating-point comparison with the given value
///
/// The Varnode can either be the direct output of a comparison, or it can be a BOOL_OR or BOOL_AND,
/// combining output from the comparison.
/// \param floatVar is the given value the comparison must take as input
/// \param root is the boolean Varnode
/// \return \b true if the boolean Varnode incorporates the comparison
bool RuleIgnoreNan::checkBackForCompare(Varnode *floatVar,Varnode *root)

{
  if (!root->isWritten()) return false;
  PcodeOp *def1 = root->getDef();
  if (!def1->isBoolOutput()) return false;
  if (def1->getOpcode()->isFloatingPointOp()) {
    if (def1->numInput() != 2) return false;
    if (functionalEquality(floatVar, def1->getIn(0)))
      return true;
    if (functionalEquality(floatVar, def1->getIn(1)))
      return true;
    return false;
  }
  OpCode opc = def1->code();
  if (opc != CPUI_BOOL_AND || opc != CPUI_BOOL_OR)
    return false;
  for(int4 i=0;i<2;++i) {
    Varnode *vn = def1->getIn(i);
    if (!vn->isWritten()) continue;
    PcodeOp *def2 = vn->getDef();
    if (!def2->isBoolOutput()) continue;
    if (!def2->getOpcode()->isFloatingPointOp()) continue;
    if (def2->numInput() != 2) continue;
    if (functionalEquality(floatVar, def2->getIn(0)))
      return true;
    if (functionalEquality(floatVar, def2->getIn(1)))
      return true;
  }
  return false;
}

/// \brief Test if the given Varnode is produced by a NaN operation.
///
/// The Varnode can be the direct or negated output of a NaN.
/// \param vn is the given Varnode
/// \return \b true if the Varnode is the output of the NaN
bool RuleIgnoreNan::isAnotherNan(Varnode *vn)

{
  if (!vn->isWritten()) return false;
  PcodeOp *op = vn->getDef();
  OpCode opc = op->code();
  if (opc == CPUI_BOOL_NEGATE) {
    vn = op->getIn(0);
    if (!vn->isWritten()) return false;
    op = vn->getDef();
    opc = op->code();
  }
  return (opc == CPUI_FLOAT_NAN);
}

/// \brief Test if a boolean expression incorporates a floating-point comparison, and remove the NaN data-flow if it does
///
/// The given PcodeOp takes input from a NaN operation through a specific slot. We look for a floating-point comparison
/// PcodeOp (FLOAT_LESS, FLOAT_LESSEQUAL, FLOAT_EQUAL, or FLOAT_NOTEQUAL) that is combined with the given PcodeOp and
/// has the same input Varnode as the NaN.  The data-flow must be combined either through a BOOL_OR or BOOL_AND
/// operation, or the given PcodeOp must be a CBRANCH that protects immediate control-flow to another CBRANCH
/// taking the result of the comparison as input.  If a matching comparison is found, the NaN input to the given
/// PcodeOp is removed, assuming the output of the NaN operation is always \b false.
/// Input from an unmodified NaN result must be combined through a BOOL_OR, but a NaN result that has been negated
/// must combine through a BOOL_AND.
/// \param floatVar is the input Varnode to NaN operation
/// \param op is the given PcodeOp to test
/// \param slot is the input index of the NaN operation
/// \param matchCode is BOOL_AND if the NaN result has been negated, BOOL_OR if not
/// \param count is incremented if a comparison is found and the NaN input is removed
/// \param data is the function
/// \return the output of the given PcodeOp if it has an opcode matching \b matchCode
Varnode *RuleIgnoreNan::testForComparison(Varnode *floatVar,PcodeOp *op,int4 slot,OpCode matchCode,int4 &count,Funcdata &data)

{
  if (op->code() == matchCode) {
    Varnode *vn = op->getIn(1 - slot);
    if (checkBackForCompare(floatVar,vn)) {
      data.opSetOpcode(op,CPUI_COPY);
      data.opRemoveInput(op,1);
      data.opSetInput(op,vn,0);
      count += 1;
    }
    else if (isAnotherNan(vn)) {
      return op->getOut();
    }
  }
  else if (op->code() == CPUI_CBRANCH) {
    BlockBasic *parent = op->getParent();
    PcodeOp *lastOp;
    int4 outDir = (matchCode == CPUI_BOOL_OR) ? 0 : 1;
    if (op->isBooleanFlip())
      outDir = 1 - outDir;
    FlowBlock *outBranch = parent->getOut(outDir);
    lastOp = outBranch->lastOp();
    if (lastOp != (PcodeOp*)0 && lastOp->code() == CPUI_CBRANCH) {
      FlowBlock *otherBranch = parent->getOut(1 - outDir);
      if (outBranch->getOut(0) == otherBranch || outBranch->getOut(1) == otherBranch) {
	if (checkBackForCompare(floatVar,lastOp->getIn(1))) {
	  data.opSetInput(op,data.newConstant(1,(matchCode == CPUI_BOOL_OR) ? 0 : 1),1);
	  count += 1;
	}
      }
    }
  }
  return (Varnode *)0;
}

int4 RuleIgnoreNan::applyOp(PcodeOp *op,Funcdata &data)

{
  if (data.getArch()->nan_ignore_all) {
    // Treat these NaN operation as always returning false (0)
    data.opSetOpcode(op,CPUI_COPY);
    data.opSetInput(op,data.newConstant(1,0),0);
    return 1;
  }
  Varnode *floatVar = op->getIn(0);
  if (floatVar->isFree()) return 0;
  Varnode *out1 = op->getOut();
  int4 count = 0;
  list<PcodeOp *>::const_iterator iter1 = out1->beginDescend();
  while(iter1 != out1->endDescend()) {
    PcodeOp *boolRead1 = *iter1;
    ++iter1;	// out1 may be truncated from boolRead1 below, advance iterator now
    Varnode *out2;
    OpCode matchCode = CPUI_BOOL_OR;
    if (boolRead1->code() == CPUI_BOOL_NEGATE) {
      matchCode = CPUI_BOOL_AND;
      out2 = boolRead1->getOut();
    }
    else {
      out2 = testForComparison(floatVar, boolRead1, boolRead1->getSlot(out1), matchCode, count, data);
    }
    if (out2 == (Varnode *)0) continue;
    list<PcodeOp *>::const_iterator iter2 = out2->beginDescend();
    while(iter2 != out2->endDescend()) {
      PcodeOp *boolRead2 = *iter2;
      ++iter2;
      Varnode *out3 = testForComparison(floatVar,boolRead2, boolRead2->getSlot(out2), matchCode, count, data);
      if (out3 == (Varnode *)0) continue;
      list<PcodeOp *>::const_iterator iter3 = out3->beginDescend();
      while(iter3 != out3->endDescend()) {
	PcodeOp *boolRead3 = *iter3;
	++iter3;
	testForComparison(floatVar, boolRead3, boolRead3->getSlot(out3), matchCode, count, data);
      }
    }
  }
  return (count > 0) ? 1 : 0;
}

/// \class RuleUnsigned2Float
/// \brief Simplify conversion:  `T = int2float((X >> 1) | X & #1);  T + T   =>  int2float( zext(X) )`
///
/// Architectures like x86 can use this sequence to simulate an unsigned integer to floating-point conversion,
/// when they don't have the conversion in hardware.
void RuleUnsigned2Float::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_FLOAT_INT2FLOAT);
}

int4 RuleUnsigned2Float::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *invn = op->getIn(0);
  if (!invn->isWritten()) return 0;
  PcodeOp *orop = invn->getDef();
  if (orop->code() != CPUI_INT_OR) return 0;
  if (!orop->getIn(0)->isWritten() || !orop->getIn(1)->isWritten()) return 0;
  PcodeOp *shiftop = orop->getIn(0)->getDef();
  PcodeOp *andop;
  if (shiftop->code() != CPUI_INT_RIGHT) {
    andop = shiftop;
    shiftop = orop->getIn(1)->getDef();
  }
  else {
    andop = orop->getIn(1)->getDef();
  }
  if (shiftop->code() != CPUI_INT_RIGHT) return 0;
  if (!shiftop->getIn(1)->constantMatch(1)) return 0;	// Shift to right by 1 exactly to clear high-bit
  Varnode *basevn = shiftop->getIn(0);
  if (basevn->isFree()) return 0;
  if (andop->code() == CPUI_INT_ZEXT) {
    if (!andop->getIn(0)->isWritten()) return 0;
    andop = andop->getIn(0)->getDef();
  }
  if (andop->code() != CPUI_INT_AND) return 0;
  if (!andop->getIn(1)->constantMatch(1)) return 0;	// Mask off least significant bit
  Varnode *vn = andop->getIn(0);
  if (basevn != vn) {
    if (!vn->isWritten()) return 0;
    PcodeOp *subop = vn->getDef();
    if (subop->code() != CPUI_SUBPIECE) return 0;
    if (subop->getIn(1)->getOffset() != 0) return 0;
    vn = subop->getIn(0);
    if (basevn != vn) return 0;
  }
  Varnode *outvn = op->getOut();
  list<PcodeOp *>::const_iterator iter;
  for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
    PcodeOp *addop = *iter;
    if (addop->code() != CPUI_FLOAT_ADD) continue;
    if (addop->getIn(0) != outvn) continue;
    if (addop->getIn(1) != outvn) continue;
    PcodeOp *zextop = data.newOp(1,addop->getAddr());
    data.opSetOpcode(zextop, CPUI_INT_ZEXT);
    Varnode *zextout = data.newUniqueOut(TypeOpFloatInt2Float::preferredZextSize(basevn->getSize()), zextop);
    data.opSetOpcode(addop, CPUI_FLOAT_INT2FLOAT);
    data.opRemoveInput(addop, 1);
    data.opSetInput(zextop, basevn, 0);
    data.opSetInput(addop, zextout, 0);
    data.opInsertBefore(zextop, addop);
    return 1;
  }
  return 0;
}

/// \class RuleInt2FloatCollapse
/// \brief Collapse equivalent FLOAT_INT2FLOAT computations along converging data-flow paths
///
/// Look for two code paths with different ways of calculating an unsigned integer to floating-point conversion,
/// one of which is chosen by examining the most significant bit of the integer.  The two paths can be collapsed
/// into a single FLOAT_INT2FLOAT operation.
void RuleInt2FloatCollapse::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_FLOAT_INT2FLOAT);
}

int4 RuleInt2FloatCollapse::applyOp(PcodeOp *op,Funcdata &data)

{
  if (!op->getIn(0)->isWritten()) return 0;
  PcodeOp *zextop = op->getIn(0)->getDef();
  if (zextop->code() != CPUI_INT_ZEXT) return 0;	// Original FLOAT_INT2FLOAT must be unsigned form
  Varnode *basevn = zextop->getIn(0);
  if (basevn->isFree()) return 0;
  PcodeOp *multiop = op->getOut()->loneDescend();
  if (multiop == (PcodeOp *)0) return 0;
  if (multiop->code() != CPUI_MULTIEQUAL) return 0;	// Output comes together with 1 other flow
  if (multiop->numInput() != 2) return 0;
  int4 slot = multiop->getSlot(op->getOut());
  Varnode *otherout = multiop->getIn(1-slot);
  if (!otherout->isWritten()) return 0;
  PcodeOp *op2 = otherout->getDef();
  if (op2->code() != CPUI_FLOAT_INT2FLOAT) return 0;	// The other flow must be a signed FLOAT_INT2FLOAT
  if (basevn != op2->getIn(0)) return 0;		// taking the same input
  int4 dir2unsigned;					// Control path to unsigned conversion
  FlowBlock *cond = FlowBlock::findCondition(multiop->getParent(), slot, multiop->getParent(), 1-slot, dir2unsigned);
  if (cond == (FlowBlock *)0) return 0;
  PcodeOp *cbranch = cond->lastOp();
  if (cbranch == (PcodeOp *)0 || cbranch->code() != CPUI_CBRANCH) return 0;
  if (!cbranch->getIn(1)->isWritten()) return 0;
  if (cbranch->isBooleanFlip()) return 0;
  PcodeOp *compare = cbranch->getIn(1)->getDef();
  if (compare->code() != CPUI_INT_SLESS) return 0;
  if (compare->getIn(1)->constantMatch(0)) {		// If condition is (basevn < 0)
    if (compare->getIn(0) != basevn) return 0;
    if (dir2unsigned != 1) return 0;	// True branch must be the unsigned FLOAT_INT2FLOAT
  }
  else if (compare->getIn(0)->constantMatch(calc_mask(basevn->getSize()))) {	// If condition is (-1 < basevn)
    if (compare->getIn(1) != basevn) return 0;
    if (dir2unsigned == 1) return 0;	// True branch must be to signed FLOAT_INT2FLOAT
  }
  else
    return 0;
  BlockBasic *outbl = multiop->getParent();
  data.opUninsert(multiop);
  data.opSetOpcode(multiop, CPUI_FLOAT_INT2FLOAT);		// Redefine the MULTIEQUAL as unsigned FLOAT_INT2FLOAT
  data.opRemoveInput(multiop, 0);
  PcodeOp *newzext = data.newOp(1, multiop->getAddr());
  data.opSetOpcode(newzext, CPUI_INT_ZEXT);
  Varnode *newout = data.newUniqueOut(TypeOpFloatInt2Float::preferredZextSize(basevn->getSize()), newzext);
  data.opSetInput(newzext,basevn,0);
  data.opSetInput(multiop, newout, 0);
  data.opInsertBegin(multiop, outbl);		// Reinsert modified MULTIEQUAL after any other MULTIEQUAL
  data.opInsertBefore(newzext, multiop);
  return 1;
}

/// \class RuleFuncPtrEncoding
/// \brief Eliminate ARM/THUMB style masking of the low order bits on function pointers
///
/// NOTE: The emulation philosophy is that it really isn't eliminated but,
/// the CALLIND operator is now dealing with it.  Hence actions like ActionDeindirect
/// that are modeling a CALLIND's behavior need to take this into account.
void RuleFuncPtrEncoding::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_CALLIND);
}

int4 RuleFuncPtrEncoding::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 align = data.getArch()->funcptr_align;
  if (align == 0) return 0;
  Varnode *vn = op->getIn(0);
  if (!vn->isWritten()) return 0;
  PcodeOp *andop = vn->getDef();
  if (andop->code() != CPUI_INT_AND) return 0;
  Varnode *maskvn = andop->getIn(1);
  if (!maskvn->isConstant()) return 0;
  uintb val = maskvn->getOffset();
  uintb testmask = calc_mask(maskvn->getSize());
  uintb slide = ~((uintb)0);
  slide <<= align;
  if ((testmask & slide)==val) { // 1-bit encoding
    data.opRemoveInput(andop,1);	// Eliminate the mask
    data.opSetOpcode(andop,CPUI_COPY);
    return 1;
  }
  return 0;
}

/// \brief Make sure comparisons match properly for a three-way
///
/// Given `zext(V < W) + zext(X <= Y)`, make sure comparisons match, i.e  V matches X and W matches Y.
/// Take into account that the LESSEQUAL may have been converted to a LESS.
/// Return:
///    - 0 if configuration is correct
///    - 1 if correct but roles of \b lessop and \b lessequalop must be swapped
///    - -1 if not the correct configuration
/// \param lessop is the putative LESS PcodeOp
/// \param lessequalop is the putative LESSEQUAL PcodeOp
/// \return 0, 1, or -1
int4 RuleThreeWayCompare::testCompareEquivalence(PcodeOp *lessop,PcodeOp *lessequalop)

{
  bool twoLessThan;
  if (lessop->code() == CPUI_INT_LESS) {	// Make sure second zext is matching lessequal
    if (lessequalop->code() == CPUI_INT_LESSEQUAL)
      twoLessThan = false;
    else if (lessequalop->code() == CPUI_INT_LESS)
      twoLessThan = true;
    else
      return -1;
  }
  else if (lessop->code() == CPUI_INT_SLESS) {
    if (lessequalop->code() == CPUI_INT_SLESSEQUAL)
      twoLessThan = false;
    else if (lessequalop->code() == CPUI_INT_SLESS)
      twoLessThan = true;
    else
      return -1;
  }
  else if (lessop->code() == CPUI_FLOAT_LESS) {
    if (lessequalop->code() == CPUI_FLOAT_LESSEQUAL)
      twoLessThan = false;
    else
      return -1;				// No partial form for floating-point comparison
  }
  else
    return -1;
  Varnode *a1 = lessop->getIn(0);
  Varnode *a2 = lessequalop->getIn(0);
  Varnode *b1 = lessop->getIn(1);
  Varnode *b2 = lessequalop->getIn(1);
  int4 res = 0;
  if (a1 != a2) {	// Make sure a1 and a2 are equivalent
    if ((!a1->isConstant())||(!a2->isConstant())) return -1;
    if ((a1->getOffset() != a2->getOffset())&&twoLessThan) {
      if (a2->getOffset() + 1 == a1->getOffset()) {
	twoLessThan = false;		// -lessequalop- is LESSTHAN, equivalent to LESSEQUAL
      }
      else if (a1->getOffset() + 1 == a2->getOffset()) {
	twoLessThan = false;		// -lessop- is LESSTHAN, equivalent to LESSEQUAL
	res = 1;			// we need to swap
      }
      else
	return -1;
    }
  }
  if (b1 != b2) {	// Make sure b1 and b2 are equivalent
    if ((!b1->isConstant())||(!b2->isConstant())) return -1;
    if ((b1->getOffset() != b2->getOffset())&&twoLessThan) {
      if (b1->getOffset() + 1 == b2->getOffset()) {
	twoLessThan = false;
      }
      else if (b2->getOffset() + 1 == b1->getOffset()) {
	twoLessThan = false;
	res = 1;			// we need to swap
      }
    }
    else
      return -1;
  }
  if (twoLessThan)
    return -1;				// Did not compensate for two LESSTHANs with differing constants
  return res;
}

/// \brief Detect a three-way calculation
///
/// A \b three-way expression looks like:
///  - `zext( V < W ) + zext( V <= W ) - 1`  in some permutation
///
/// The comparisons can signed, unsigned, or floating-point.
/// \param op is the putative root INT_ADD of the calculation
/// \param isPartial is set to \b true if a partial form is detected
/// \return the less-than op or NULL if no three-way was detected
PcodeOp *RuleThreeWayCompare::detectThreeWay(PcodeOp *op,bool &isPartial)

{
  Varnode *vn1, *vn2, *tmpvn;
  PcodeOp *zext1, *zext2;
  PcodeOp *addop, *lessop, *lessequalop;
  uintb mask;
  vn2 = op->getIn(1);
  if (vn2->isConstant()) {		// Form 1 :  (z + z) - 1
    mask = calc_mask(vn2->getSize());
    if (mask != vn2->getOffset()) return (PcodeOp *)0;		// Match the -1
    vn1 = op->getIn(0);
    if (!vn1->isWritten()) return (PcodeOp *)0;
    addop = vn1->getDef();
    if (addop->code() != CPUI_INT_ADD) return (PcodeOp *)0;	// Match the add
    tmpvn = addop->getIn(0);
    if (!tmpvn->isWritten()) return (PcodeOp *)0;
    zext1 = tmpvn->getDef();
    if (zext1->code() != CPUI_INT_ZEXT) return (PcodeOp *)0;	// Match the first zext
    tmpvn = addop->getIn(1);
    if (!tmpvn->isWritten()) return (PcodeOp *)0;
    zext2 = tmpvn->getDef();
    if (zext2->code() != CPUI_INT_ZEXT) return (PcodeOp *)0;	// Match the second zext
  }
  else if (vn2->isWritten()) {
    PcodeOp *tmpop = vn2->getDef();
    if (tmpop->code() == CPUI_INT_ZEXT) {	// Form 2 : (z - 1) + z
      zext2 = tmpop;					// Second zext is already matched
      vn1 = op->getIn(0);
      if (!vn1->isWritten()) return (PcodeOp *)0;
      addop = vn1->getDef();
      if (addop->code() != CPUI_INT_ADD) {	// Partial form:  (z + z)
	zext1 = addop;
	if (zext1->code() != CPUI_INT_ZEXT)
	  return (PcodeOp *)0;			// Match the first zext
	isPartial = true;
      }
      else {
	tmpvn = addop->getIn(1);
	if (!tmpvn->isConstant()) return (PcodeOp *)0;
	mask = calc_mask(tmpvn->getSize());
	if (mask != tmpvn->getOffset()) return (PcodeOp *)0;	// Match the -1
	tmpvn = addop->getIn(0);
	if (!tmpvn->isWritten()) return (PcodeOp *)0;
	zext1 = tmpvn->getDef();
	if (zext1->code() != CPUI_INT_ZEXT) return (PcodeOp *)0;	// Match the first zext
      }
    }
    else if (tmpop->code() == CPUI_INT_ADD) {	// Form 3 : z + (z - 1)
      addop = tmpop;				// Matched the add
      vn1 = op->getIn(0);
      if (!vn1->isWritten()) return (PcodeOp *)0;
      zext1 = vn1->getDef();
      if (zext1->code() != CPUI_INT_ZEXT) return (PcodeOp *)0;	// Match the first zext
      tmpvn = addop->getIn(1);
      if (!tmpvn->isConstant()) return (PcodeOp *)0;
      mask = calc_mask(tmpvn->getSize());
      if (mask != tmpvn->getOffset()) return (PcodeOp *)0;	// Match the -1
      tmpvn = addop->getIn(0);
      if (!tmpvn->isWritten()) return (PcodeOp *)0;
      zext2 = tmpvn->getDef();
      if (zext2->code() != CPUI_INT_ZEXT) return (PcodeOp *)0;	// Match the second zext
    }
    else
      return (PcodeOp *)0;
  }
  else
    return (PcodeOp *)0;
  vn1 = zext1->getIn(0);
  if (!vn1->isWritten()) return (PcodeOp *)0;
  vn2 = zext2->getIn(0);
  if (!vn2->isWritten()) return (PcodeOp *)0;
  lessop = vn1->getDef();
  lessequalop = vn2->getDef();
  OpCode opc = lessop->code();
  if ((opc != CPUI_INT_LESS)&&(opc != CPUI_INT_SLESS)&&(opc != CPUI_FLOAT_LESS)) {	// Make sure first zext is less
    PcodeOp *tmpop = lessop;
    lessop = lessequalop;
    lessequalop = tmpop;
  }
  int4 form = testCompareEquivalence(lessop,lessequalop);
  if (form < 0)
    return (PcodeOp *)0;
  if (form == 1) {
    PcodeOp *tmpop = lessop;
    lessop = lessequalop;
    lessequalop = tmpop;
  }
  return lessop;
}

/// \class RuleThreeWayCompare
/// \brief Simplify expressions involving \e three-way comparisons
///
/// A \b three-way comparison is the expression
///  - `X = zext( V < W ) + ZEXT( V <= W ) - 1` in some permutation
///
/// This gives the result (-1, 0, or 1) depending on whether V is
/// less-than, equal, or greater-than W.  This Rule looks for secondary
/// comparisons of the three-way, such as
///  - `X < 1`  which simplifies to
///  - `V <= W`
void RuleThreeWayCompare::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_SLESS);
  oplist.push_back(CPUI_INT_SLESSEQUAL);
  oplist.push_back(CPUI_INT_EQUAL);
  oplist.push_back(CPUI_INT_NOTEQUAL);
}

int4 RuleThreeWayCompare::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 constSlot=0;
  int4 form;
  Varnode *tmpvn = op->getIn(constSlot);
  if (!tmpvn->isConstant()) {		// One of the two inputs must be a constant
    constSlot = 1;
    tmpvn = op->getIn(constSlot);
    if (!tmpvn->isConstant()) return 0;
  }
  uintb val = tmpvn->getOffset();	// Encode const value (-1, 0, 1, 2) as highest 3 bits of form (000, 001, 010, 011)
  if (val <= 2)
    form = (int)val + 1;
  else if (val == calc_mask(tmpvn->getSize()))
    form = 0;
  else
    return 0;

  tmpvn = op->getIn(1-constSlot);
  if (!tmpvn->isWritten()) return 0;
  if (tmpvn->getDef()->code() != CPUI_INT_ADD) return 0;
  bool isPartial = false;
  PcodeOp *lessop = detectThreeWay(tmpvn->getDef(),isPartial);
  if (lessop == (PcodeOp *)0)
    return 0;
  if (isPartial) {	// Only found a partial three-way
    if (form == 0)
      return 0;		// -1 const value is now out of range
    form -= 1;		// Subtract 1 (from both sides of equation) to complete the three-way form
  }
  form <<= 1;
  if (constSlot == 1)			// Encode const position (0 or 1) as next bit
    form += 1;
  OpCode lessform = lessop->code();	// Either INT_LESS, INT_SLESS, or FLOAT_LESS
  form <<= 2;
  if (op->code() == CPUI_INT_SLESSEQUAL)
    form += 1;
  else if (op->code() == CPUI_INT_EQUAL)
    form += 2;
  else if (op->code() == CPUI_INT_NOTEQUAL)
    form += 3;
					// Encode base op (SLESS, SLESSEQUAL, EQUAL, NOTEQUAL) as final 2 bits

  Varnode *bvn = lessop->getIn(0);	// First parameter to LESSTHAN is second parameter to cmp3way function
  Varnode *avn = lessop->getIn(1);	// Second parameter to LESSTHAN is first parameter to cmp3way function
  if ((!avn->isConstant())&&(avn->isFree())) return 0;
  if ((!bvn->isConstant())&&(bvn->isFree())) return 0;
  switch(form) {
  case 1:	// -1  s<= threeway   =>   always true
  case 21:	// threeway  s<=  1   =>   always true
    data.opSetOpcode(op,CPUI_INT_EQUAL);
    data.opSetInput(op,data.newConstant(1,0),0);
    data.opSetInput(op,data.newConstant(1,0),1);
    break;
  case 4:	// threeway  s<  -1   =>   always false
  case 16:	//  1  s<  threeway   =>   always false
    data.opSetOpcode(op,CPUI_INT_NOTEQUAL);
    data.opSetInput(op,data.newConstant(1,0),0);
    data.opSetInput(op,data.newConstant(1,0),1);
    break;
  case 2:	// -1  ==  threeway   =>   a < b
  case 5:	// threeway  s<= -1   =>   a < b
  case 6:	// threeway  ==  -1   =>   a < b
  case 12:	// threeway  s<   0   =>   a < b
    data.opSetOpcode(op,lessform);
    data.opSetInput(op,avn,0);
    data.opSetInput(op,bvn,1);
    break;
  case 13:	// threeway  s<=  0   =>   a <= b
  case 19:	//  1  !=  threeway   =>   a <= b
  case 20:	// threeway  s<   1   =>   a <= b
  case 23:	// threeway  !=   1   =>   a <= b
    data.opSetOpcode(op,(OpCode)(lessform+1));		// LESSEQUAL form
    data.opSetInput(op,avn,0);
    data.opSetInput(op,bvn,1);
    break;
  case 8:	//  0  s<  threeway   =>   a > b
  case 17:	//  1  s<= threeway   =>   a > b
  case 18:	//  1  ==  threeway   =>   a > b
  case 22:	// threeway  ==   1   =>   a > b
    data.opSetOpcode(op,lessform);
    data.opSetInput(op,bvn,0);
    data.opSetInput(op,avn,1);
    break;
  case 0:	// -1  s<  threeway   =>   a >= b
  case 3:	// -1  !=  threeway   =>   a >= b
  case 7:	// threeway  !=  -1   =>   a >= b
  case 9:	//  0  s<= threeway   =>   a >= b
    data.opSetOpcode(op,(OpCode)(lessform+1));		// LESSEQUAL form
    data.opSetInput(op,bvn,0);
    data.opSetInput(op,avn,1);
    break;
  case 10:	//  0  ==  threeway   =>   a == b
  case 14:	// threeway  ==   0   =>   a == b
    if (lessform == CPUI_FLOAT_LESS)			// Choose the right equal form
      lessform = CPUI_FLOAT_EQUAL;			// float form
    else
      lessform = CPUI_INT_EQUAL;			// or integer form
    data.opSetOpcode(op,lessform);
    data.opSetInput(op,avn,0);
    data.opSetInput(op,bvn,1);
    break;
  case 11:	//  0  !=  threeway   =>   a != b
  case 15:	// threeway  !=   0   =>   a != b
    if (lessform == CPUI_FLOAT_LESS)			// Choose the right notequal form
      lessform = CPUI_FLOAT_NOTEQUAL;			// float form
    else
      lessform = CPUI_INT_NOTEQUAL;			// or integer form
    data.opSetOpcode(op,lessform);
    data.opSetInput(op,avn,0);
    data.opSetInput(op,bvn,1);
    break;
  default:
    return 0;
  }
  return 1;
}

/// \class RulePopcountBoolXor
/// \brief Simplify boolean expressions that are combined through POPCOUNT
///
/// Expressions involving boolean values (b1 and b2) are converted, such as:
///  - `popcount((b1 << 6) | (b2 << 2)) & 1  =>   b1 ^ b2`
void RulePopcountBoolXor::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_POPCOUNT);
}

int4 RulePopcountBoolXor::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *outVn = op->getOut();
  list<PcodeOp *>::const_iterator iter;

  for(iter=outVn->beginDescend();iter!=outVn->endDescend();++iter) {
    PcodeOp *baseOp = *iter;
    if (baseOp->code() != CPUI_INT_AND) continue;
    Varnode *tmpVn = baseOp->getIn(1);
    if (!tmpVn->isConstant()) continue;
    if (tmpVn->getOffset() != 1) continue;	// Masking 1 bit means we are checking parity of POPCOUNT input
    if (tmpVn->getSize() != 1) continue;	// Must be boolean sized output
    Varnode *inVn = op->getIn(0);
    if (!inVn->isWritten()) return 0;
    int4 count = popcount(inVn->getNZMask());
    if (count == 1) {
      int4 leastPos = leastsigbit_set(inVn->getNZMask());
      int4 constRes;
      Varnode *b1 = getBooleanResult(inVn, leastPos, constRes);
      if (b1 == (Varnode *)0) continue;
      data.opSetOpcode(baseOp, CPUI_COPY);	// Recognized  popcount( b1 << #pos ) & 1
      data.opRemoveInput(baseOp, 1);		// Simplify to  COPY(b1)
      data.opSetInput(baseOp, b1, 0);
      return 1;
    }
    if (count == 2) {
      int4 pos0 = leastsigbit_set(inVn->getNZMask());
      int4 pos1 = mostsigbit_set(inVn->getNZMask());
      int4 constRes0,constRes1;
      Varnode *b1 = getBooleanResult(inVn, pos0, constRes0);
      if (b1 == (Varnode *)0 && constRes0 != 1) continue;
      Varnode *b2 = getBooleanResult(inVn, pos1, constRes1);
      if (b2 == (Varnode *)0 && constRes1 != 1) continue;
      if (b1 == (Varnode *)0 && b2 == (Varnode *)0) continue;
      if (b1 == (Varnode *)0)
	b1 = data.newConstant(1, 1);
      if (b2 == (Varnode *)0)
	b2 = data.newConstant(1, 1);
      data.opSetOpcode(baseOp, CPUI_INT_XOR);	// Recognized  popcount ( b1 << #pos1 | b2 << #pos2 ) & 1
      data.opSetInput(baseOp, b1, 0);
      data.opSetInput(baseOp, b2, 1);
      return 1;
    }
  }
  return 0;
}

/// \brief Extract boolean Varnode producing bit at given Varnode and position
///
/// The boolean value may be shifted, extended and combined with other booleans through a
/// series of operations. We return the Varnode that is the
/// actual result of the boolean operation.  If the given Varnode is constant, return
/// null but pass back whether the given bit position is 0 or 1.  If no boolean value can be
/// found, return null and pass back -1.
/// \param vn is the given Varnode containing the extended/shifted boolean
/// \param bitPos is the bit position of the desired boolean value
/// \param constRes is used to pass back a constant boolean result
/// \return the boolean Varnode producing the desired value or null
Varnode *RulePopcountBoolXor::getBooleanResult(Varnode *vn,int4 bitPos,int4 &constRes)

{
  constRes = -1;
  uintb mask = 1;
  mask <<= bitPos;
  Varnode *vn0;
  Varnode *vn1;
  int4 sa;
  for(;;) {
    if (vn->isConstant()) {
      constRes = (vn->getOffset() >> bitPos) & 1;
      return (Varnode *)0;
    }
    if (!vn->isWritten()) return (Varnode *)0;
    if (bitPos == 0 && vn->getSize() == 1 && vn->getNZMask() == mask)
      return vn;
    PcodeOp *op = vn->getDef();
    switch(op->code()) {
      case CPUI_INT_AND:
	if (!op->getIn(1)->isConstant()) return (Varnode *)0;
	vn = op->getIn(0);
	break;
      case CPUI_INT_XOR:
      case CPUI_INT_OR:
	vn0 = op->getIn(0);
	vn1 = op->getIn(1);
	if ((vn0->getNZMask() & mask) != 0) {
	  if ((vn1->getNZMask() & mask) != 0)
	    return (Varnode *)0;		// Don't have a unique path
	  vn = vn0;
	}
	else if ((vn1->getNZMask() & mask) != 0) {
	  vn = vn1;
	}
	else
	  return (Varnode *)0;
	break;
      case CPUI_INT_ZEXT:
      case CPUI_INT_SEXT:
	vn = op->getIn(0);
	if (bitPos >= vn->getSize() * 8) return (Varnode *)0;
	break;
      case CPUI_SUBPIECE:
	sa = (int4)op->getIn(1)->getOffset() * 8;
	bitPos += sa;
	mask <<= sa;
	vn = op->getIn(0);
	break;
      case CPUI_PIECE:
	vn0 = op->getIn(0);
	vn1 = op->getIn(1);
	sa = (int4)vn1->getSize() * 8;
	if (bitPos >= sa) {
	  vn = vn0;
	  bitPos -= sa;
	  mask >>= sa;
	}
	else {
	  vn = vn1;
	}
	break;
      case CPUI_INT_LEFT:
	vn1 = op->getIn(1);
	if (!vn1->isConstant()) return (Varnode *)0;
	sa = (int4) vn1->getOffset();
	if (sa > bitPos) return (Varnode *)0;
	bitPos -= sa;
	mask >>= sa;
	vn = op->getIn(0);
	break;
      case CPUI_INT_RIGHT:
      case CPUI_INT_SRIGHT:
	vn1 = op->getIn(1);
	if (!vn1->isConstant()) return (Varnode *)0;
	sa = (int4) vn1->getOffset();
	vn = op->getIn(0);
	bitPos += sa;
	if (bitPos >= vn->getSize() * 8) return (Varnode *)0;
	mask <<= sa;
	break;
      default:
	return (Varnode *)0;
    }
  }
}

/// \brief Return \b true if concatenating with a SUBPIECE of the given Varnode is unusual
///
/// \param vn is the given Varnode
/// \param data is the function containing the Varnode
/// \return \b true if the configuration is a pathology
bool RulePiecePathology::isPathology(Varnode *vn,Funcdata &data)

{
  vector<PcodeOp *> worklist;
  int4 pos = 0;
  int4 slot = 0;
  bool res = false;
  for(;;) {
    if (vn->isInput() && !vn->isPersist()) {
      res = true;
      break;
    }
    PcodeOp *op = vn->getDef();
    while(!res && op != (PcodeOp *)0) {
      switch(op->code()) {
	case CPUI_COPY:
	  vn = op->getIn(0);
	  op = vn->getDef();
	  break;
	case CPUI_MULTIEQUAL:
	  if (!op->isMark()) {
	    op->setMark();
	    worklist.push_back(op);
	  }
	  op = (PcodeOp *)0;
	  break;
	case CPUI_INDIRECT:
	  if (op->getIn(1)->getSpace()->getType() == IPTR_IOP) {
	    PcodeOp *callOp = PcodeOp::getOpFromConst(op->getIn(1)->getAddr());
	    if (callOp->isCall()) {
	      FuncCallSpecs *fspec = data.getCallSpecs(callOp);
	      if (fspec != (FuncCallSpecs *) 0 && !fspec->isOutputActive()) {
		res = true;
	      }
	    }
	  }
	  op = (PcodeOp *)0;
	  break;
	case CPUI_CALL:
	case CPUI_CALLIND:
	{
	  FuncCallSpecs *fspec = data.getCallSpecs(op);
	  if (fspec != (FuncCallSpecs *)0 && !fspec->isOutputActive()) {
	    res = true;
	  }
	  break;
	}
	default:
	  op = (PcodeOp *)0;
	  break;
      }
    }
    if (res) break;
    if (pos >= worklist.size()) break;
    op = worklist[pos];
    if (slot < op->numInput()) {
      vn = op->getIn(slot);
      slot += 1;
    }
    else {
      pos += 1;
      if (pos >= worklist.size()) break;
      vn = worklist[pos]->getIn(0);
      slot = 1;
    }
  }
  for(int4 i=0;i<worklist.size();++i)
    worklist[i]->clearMark();
  return res;
}

/// \brief Given a known pathological concatenation, trace it forward to CALLs and RETURNs
///
/// If the pathology reaches a CALL or RETURN, it is noted, through the FuncProto or FuncCallSpecs
/// object, that the parameter or return value is only partially consumed.  The subvariable flow
/// rules can then decide whether or not to truncate this part of the data-flow.
/// \param op is CPUI_PIECE op that is the pathological concatenation
/// \param data is the function containing the data-flow
/// \return a non-zero value if new bytes are labeled as unconsumed
int4 RulePiecePathology::tracePathologyForward(PcodeOp *op,Funcdata &data)

{
  int4 count = 0;
  const FuncCallSpecs *fProto;
  vector<PcodeOp *> worklist;
  int4 pos = 0;
  op->setMark();
  worklist.push_back(op);
  while(pos < worklist.size()) {
    PcodeOp *curOp = worklist[pos];
    pos += 1;
    Varnode *outVn = curOp->getOut();
    list<PcodeOp *>::const_iterator iter;
    list<PcodeOp *>::const_iterator enditer = outVn->endDescend();
    for(iter=outVn->beginDescend();iter!=enditer;++iter) {
      curOp = *iter;
      switch(curOp->code()) {
	case CPUI_COPY:
	case CPUI_INDIRECT:
	case CPUI_MULTIEQUAL:
	  if (!curOp->isMark()) {
	    curOp->setMark();
	    worklist.push_back(curOp);
	  }
	  break;
	case CPUI_CALL:
	case CPUI_CALLIND:
	  fProto = data.getCallSpecs(curOp);
	  if (fProto != (FuncProto *)0 && !fProto->isInputActive() && !fProto->isInputLocked()) {
	    int4 bytesConsumed = op->getIn(1)->getSize();
	    for(int4 i=1;i<curOp->numInput();++i) {
	      if (curOp->getIn(i) == outVn) {
		if (fProto->setInputBytesConsumed(i, bytesConsumed))
		  count += 1;
	      }
	    }
	  }
	  break;
	case CPUI_RETURN:
	  if (!data.getFuncProto().isOutputLocked()) {
	    if (data.getFuncProto().setReturnBytesConsumed(op->getIn(1)->getSize()))
	      count += 1;
	  }
	  break;
	default:
	  break;
      }
    }
  }
  for(int4 i=0;i<worklist.size();++i)
    worklist[i]->clearMark();
  return count;
}

/// \class RulePiecePathology
/// \brief Search for concatenations with unlikely things to inform return/parameter consumption calculation
///
/// For that can read/write part of a general purpose register, a small return value can get concatenated
/// with unrelated data when the function writes directly to part of the return register. This searches
/// for a characteristic pathology:
/// \code
///     retreg = CALL();
///     ...
///     retreg = CONCAT(SUBPIECE(retreg,#4),smallval);
/// \endcode
void RulePiecePathology::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_PIECE);
}

int4 RulePiecePathology::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *vn = op->getIn(0);
  if (!vn->isWritten()) return 0;
  PcodeOp *subOp = vn->getDef();

  // Make sure we are concatenating the most significant bytes of a truncation
  OpCode opc = subOp->code();
  if (opc == CPUI_SUBPIECE) {
    if (subOp->getIn(1)->getOffset() == 0) return 0;
    if (!isPathology(subOp->getIn(0),data)) return 0;
  }
  else if (opc == CPUI_INDIRECT) {
    if (!subOp->isIndirectCreation()) return 0;					// Indirect concatenation
    Varnode *lsbVn = op->getIn(1);
    if (!lsbVn->isWritten()) return 0;
    PcodeOp *lsbOp = lsbVn->getDef();
    if ((lsbOp->getEvalType() & (PcodeOp::binary | PcodeOp::unary)) == 0) {	// from either a unary/binary operation
      if (!lsbOp->isCall()) return 0;						// or a CALL
      FuncCallSpecs *fc = data.getCallSpecs(lsbOp);
      if (fc == (FuncCallSpecs *)0) return 0;
      if (!fc->isOutputLocked()) return 0;					// with a locked output
    }
    Address addr = lsbVn->getAddr();
    if (addr.getSpace()->isBigEndian())
      addr = addr - vn->getSize();
    else
      addr = addr + lsbVn->getSize();
    if (addr != vn->getAddr()) return 0;					// into a contiguous register
  }
  else
    return 0;
  return tracePathologyForward(op, data);
}

/// \class RuleXorSwap
/// \brief Simplify limited chains of XOR operations
///
/// `V = (a ^ b) ^ a => V = b`
/// `V = a ^ (b ^ a) => V = b`
void RuleXorSwap::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_XOR);
}

int4 RuleXorSwap::applyOp(PcodeOp *op,Funcdata &data)

{
  for(int4 i=0;i<2;++i) {
    Varnode *vn = op->getIn(i);
    if (!vn->isWritten()) continue;
    PcodeOp *op2 = vn->getDef();
    if (op2->code() != CPUI_INT_XOR) continue;
    Varnode *othervn = op->getIn(1-i);
    Varnode *vn0 = op2->getIn(0);
    Varnode *vn1 = op2->getIn(1);
    if (othervn == vn0 && !vn1->isFree()) {
      data.opRemoveInput(op, 1);
      data.opSetOpcode(op, CPUI_COPY);
      data.opSetInput(op, vn1, 0);
      return 1;
    }
    else if (othervn == vn1 && !vn0->isFree()) {
      data.opRemoveInput(op, 1);
      data.opSetOpcode(op, CPUI_COPY);
      data.opSetInput(op, vn0, 0);
      return 1;
    }
  }
  return 0;
}

/// \class RuleLzcountShiftBool
/// \brief Simplify equality checks that use lzcount:  `lzcount(X) >> c  =>  X == 0` if X is 2^c bits wide
///
/// Some compilers check if a value is equal to zero by checking the most
/// significant bit in lzcount; for instance on a 32-bit system,
/// the result of lzcount on zero would have the 5th bit set.
///  - `lzcount(a ^ 3) >> 5  =>  a ^ 3 == 0  =>  a == 3` (by RuleXorCollapse)
///  - `lzcount(a - 3) >> 5  =>  a - 3 == 0  =>  a == 3` (by RuleEqual2Zero)
void RuleLzcountShiftBool::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_LZCOUNT);
}

int4 RuleLzcountShiftBool::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *outVn = op->getOut();
  list<PcodeOp *>::const_iterator iter, iter2;
  uintb max_return = 8 * op->getIn(0)->getSize();
  if (popcount(max_return) != 1) {
    // This rule only makes sense with sizes that are powers of 2; if the maximum value
    // returned by lzcount was, say, 24, then both 16 >> 4 and 24 >> 4
    // are 1, and thus the check does not make sense.  (Such processors couldn't
    // use lzcount for checking equality in any case.)
    return 0;
  }

  for(iter=outVn->beginDescend();iter!=outVn->endDescend();++iter) {
    PcodeOp *baseOp = *iter;
    if (baseOp->code() != CPUI_INT_RIGHT && baseOp->code() != CPUI_INT_SRIGHT) continue;
    Varnode *vn1 = baseOp->getIn(1);
    if (!vn1->isConstant()) continue;
    uintb shift = vn1->getOffset();
    if ((max_return >> shift) == 1) {
      // Becomes a comparison with zero
      PcodeOp* newOp = data.newOp(2, baseOp->getAddr());
      data.opSetOpcode(newOp, CPUI_INT_EQUAL);
      Varnode* b = data.newConstant(op->getIn(0)->getSize(), 0);
      data.opSetInput(newOp, op->getIn(0), 0);
      data.opSetInput(newOp, b, 1);

      // CPUI_INT_EQUAL must produce a 1-byte boolean result
      Varnode* eqResVn = data.newUniqueOut(1, newOp);

      data.opInsertBefore(newOp, baseOp);

      // Because the old output had size op->getIn(0)->getSize(),
      // we have to guarantee that a Varnode of this size gets outputted
      // to the descending PcodeOps. This is handled here with CPUI_INT_ZEXT.
      data.opRemoveInput(baseOp, 1);
      if (baseOp->getOut()->getSize() == 1)
	data.opSetOpcode(baseOp, CPUI_COPY);
      else
	data.opSetOpcode(baseOp, CPUI_INT_ZEXT);
      data.opSetInput(baseOp, eqResVn, 0);
      return 1;
    }
  }
  return 0;
}

/// \class RuleFloatSign
/// \brief Convert floating-point \e sign bit manipulation into FLOAT_ABS or FLOAT_NEG
///
/// Transform floating-point specific operations
///   -- `x & 0x7fffffff  =>  ABS(f)`
///   -- 'x ^ 0x80000000  =>  -f`
///
/// A Varnode is determined to be floating-point by participation in other floating-point operations,
/// not based on the data-type of the Varnode.
void RuleFloatSign::getOpList(vector<uint4> &oplist) const

{
  uint4 list[] = { CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN,
      CPUI_FLOAT_ADD, CPUI_FLOAT_DIV, CPUI_FLOAT_MULT, CPUI_FLOAT_SUB, CPUI_FLOAT_NEG, CPUI_FLOAT_ABS,
      CPUI_FLOAT_SQRT, CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND,
      CPUI_FLOAT_INT2FLOAT, CPUI_FLOAT_TRUNC };
  oplist.insert(oplist.end(),list,list+18);
}

int4 RuleFloatSign::applyOp(PcodeOp *op,Funcdata &data)

{
  int4 res = 0;
  OpCode opc = op->code();
  if (opc != CPUI_FLOAT_INT2FLOAT) {
    Varnode *vn = op->getIn(0);
    if (vn->isWritten()) {
      PcodeOp *signOp = vn->getDef();
      OpCode resCode = TypeOp::floatSignManipulation(signOp);
      if (resCode != CPUI_MAX) {
	data.opRemoveInput(signOp, 1);
	data.opSetOpcode(signOp, resCode);
	res = 1;
      }
    }
    if (op->numInput() == 2) {
      vn = op->getIn(1);
      if (vn->isWritten()) {
	PcodeOp *signOp = vn->getDef();
	OpCode resCode = TypeOp::floatSignManipulation(signOp);
	if (resCode != CPUI_MAX) {
	  data.opRemoveInput(signOp, 1);
	  data.opSetOpcode(signOp, resCode);
	  res = 1;
	}
      }
    }
  }
  if (op->isBoolOutput() || opc == CPUI_FLOAT_TRUNC)
    return res;
  list<PcodeOp *>::const_iterator iter;
  Varnode *outvn = op->getOut();
  for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
    PcodeOp *readOp = *iter;
    OpCode resCode = TypeOp::floatSignManipulation(readOp);
    if (resCode != CPUI_MAX) {
      data.opRemoveInput(readOp, 1);
      data.opSetOpcode(readOp, resCode);
      res = 1;
    }
  }
  return res;
}

/// \class RuleFloatSignCleanup
/// \brief Convert floating-point \e sign bit manipulation into FLOAT_ABS or FLOAT_NEG
///
/// A Varnode is determined to be floating-point by examining its data-type.
void RuleFloatSignCleanup::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_AND);
  oplist.push_back(CPUI_INT_XOR);
}

int4 RuleFloatSignCleanup::applyOp(PcodeOp *op,Funcdata &data)

{
  if (op->getOut()->getType()->getMetatype() != TYPE_FLOAT) {
      return 0;
  }
  OpCode opc = TypeOp::floatSignManipulation(op);
  if (opc == CPUI_MAX)
    return 0;
  data.opRemoveInput(op, 1);
  data.opSetOpcode(op, opc);
  return 1;
}

/// \class RuleOrCompare
/// \brief Simplify INT_OR in comparisons with 0.
///
/// `(V | W) == 0` => '(V == 0) && (W == 0)'
/// `(V | W) != 0` => '(V != 0) || (W != 0)'
void RuleOrCompare::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_OR);
}

int4 RuleOrCompare::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *outvn = op->getOut();
  list<PcodeOp *>::const_iterator iter;
  bool hasCompares = false;
  for(iter=outvn->beginDescend();iter!=outvn->endDescend();++iter) {
    PcodeOp *compOp = *iter;
    OpCode opc = compOp->code();
    if (opc != CPUI_INT_EQUAL && opc != CPUI_INT_NOTEQUAL)
      return 0;
    if (!compOp->getIn(1)->constantMatch(0))
      return 0;
    hasCompares = true;
  }
  if (!hasCompares)
    return 0;

  Varnode* V = op->getIn(0);
  Varnode* W = op->getIn(1);

  // make sure V and W are in SSA form
  if (V->isFree()) return 0;
  if (W->isFree()) return 0;

  iter = outvn->beginDescend();
  while(iter!=outvn->endDescend()) {
    PcodeOp *equalOp = *iter;
    OpCode opc = equalOp->code();
    ++iter;		// Advance iterator immediately as equalOp gets modified
    // construct the new segment:
    // if the original condition was INT_EQUAL: BOOL_AND(INT_EQUAL(V, 0:|V|), INT_EQUAL(W, 0:|W|))
    // if the original condition was INT_NOTEQUAL: BOOL_OR(INT_NOTEQUAL(V, 0:|V|), INT_NOTEQUAL(W, 0:|W|))
    Varnode* zero_V = data.newConstant(V->getSize(), 0);
    Varnode* zero_W = data.newConstant(W->getSize(), 0);
    PcodeOp* eq_V = data.newOp(2, equalOp->getAddr());
    data.opSetOpcode(eq_V, opc);
    data.opSetInput(eq_V, V, 0);
    data.opSetInput(eq_V, zero_V, 1);
    PcodeOp* eq_W = data.newOp(2, equalOp->getAddr());
    data.opSetOpcode(eq_W, opc);
    data.opSetInput(eq_W, W, 0);
    data.opSetInput(eq_W, zero_W, 1);

    Varnode* eq_V_out = data.newUniqueOut(1, eq_V);
    Varnode* eq_W_out = data.newUniqueOut(1, eq_W);

    // make sure the comparisons' output is already defined
    data.opInsertBefore(eq_V, equalOp);
    data.opInsertBefore(eq_W, equalOp);

    // change the original INT_EQUAL into a BOOL_AND, and INT_NOTEQUAL becomes BOOL_OR
    data.opSetOpcode(equalOp, opc == CPUI_INT_EQUAL ? CPUI_BOOL_AND : CPUI_BOOL_OR);
    data.opSetInput(equalOp, eq_V_out, 0);
    data.opSetInput(equalOp, eq_W_out, 1);
  }

  return 1;
}

/// \class RulePtrsubOr
/// \brief Simplify INT_OR just to INT_ADD when used with
/// PTRSUB due to alignment guarantees (stack for example)
///   e = (c | d) - c
///
/// `PTRSUB(V,c) | d` => 'PTRSUB(V,c) + e`
void RulePtrsubOr::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_OR);
}

int4 RulePtrsubOr::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *c[2];
  uintb val[2];

  PcodeOp *ptrsubop = op->getIn(0)->getDef();
  if (ptrsubop == (PcodeOp *)0) return 0;
  if (ptrsubop->code() != CPUI_PTRSUB) return 0;
  Varnode *basevn = ptrsubop->getIn(0);
  // Base varnode must be a pure value and not some calculated one
  if (basevn->getDef() != (PcodeOp *)0) return 0;
  TypePointer *ptype = (TypePointer *)basevn->getType();
  if (ptype->getMetatype() != TYPE_PTR) return 0;
  TypeSpacebase *sb = (TypeSpacebase *) ptype->getPtrTo();
  if (sb->getMetatype() != TYPE_SPACEBASE) return 0;

  c[0] = ptrsubop->getIn(1);
  c[1] = op->getIn(1);
  if (!c[0]->isConstant()) return 0;
  if (!c[1]->isConstant()) return 0;

  // calculate offset
  val[0] = c[0]->getOffset();
  val[1] = c[1]->getOffset();
  uintb off = (val[0] | val[1]) - val[0];
  int4 sz = c[1]->getSize();
  data.opSetOpcode(op,CPUI_INT_ADD);
  data.opSetInput(op,data.newConstant(sz,off&calc_mask(sz)),1);
  return 0;
}

  /// \class RulePtrsubAdjust
/// \brief Adjust constants inside ptrsub added with
/// variable and constant so it fits better
///
/// `PTRSUB(V,c) + (W + d)` => 'PTRSUB(V,c+e) + (W + d-e)`
void RulePtrsubAdjust::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ADD);
}

int4 RulePtrsubAdjust::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *newvn[2];
  Varnode *c[2];
  uintb val[2];

  PcodeOp *ptrsubop = op->getIn(0)->getDef();
  if (ptrsubop == (PcodeOp *)0) return 0;
  if (ptrsubop->code() != CPUI_PTRSUB) return 0;
  Varnode *basevn = ptrsubop->getIn(0);
  c[0] = ptrsubop->getIn(1);

  PcodeOp *addop = op->getIn(1)->getDef();
  if (addop == (PcodeOp *)0) return 0;
  if (addop->code() != CPUI_INT_ADD) return 0;
  Varnode *invn = addop->getIn(0);
  c[1] = addop->getIn(1);

  if (basevn->isConstant()) return 0;
  if (invn->isConstant()) return 0;
  if (!c[0]->isConstant()) return 0;
  if (!c[1]->isConstant()) return 0;

  val[0] = c[0]->getOffset();
  val[1] = c[1]->getOffset();

  TypePointer *ptype = (TypePointer *)basevn->getType();
  if (ptype->getMetatype() != TYPE_PTR) return 0;
  TypeSpacebase *sb = (TypeSpacebase *)ptype->getPtrTo();
  if (sb->getMetatype() != TYPE_SPACEBASE) return 0;
  Scope *scope = sb->getMap();

  Address addr = sb->getAddress(val[0],basevn->getSize(),op->getAddr());
  if (addr.isInvalid()) return 0;
  SymbolEntry *entry1 = scope->queryContainer(addr,1,Address());
  if (entry1 == (SymbolEntry *)0) return 0;

  uintb off = (intb)entry1->getSize();
  if (off <= val[1]) return 0;
  uintb diff = off - val[1];
  addr = sb->getAddress(val[0] + off,basevn->getSize(),op->getAddr());
  SymbolEntry *entry2 = scope->queryContainer(addr,1,Address());
  if (entry2 == (SymbolEntry *)0) return 0;
  Datatype *dt = entry2->getSymbol()->getType();
  if (dt->getMetatype() != TYPE_ARRAY) return 0;
  while (dt->getMetatype() == TYPE_ARRAY) {
    dt = ((TypeArray *)dt)->getBase();
  }
  if (diff > dt->getSize()) return 0;

  int4 sz = c[0]->getSize();
  newvn[0] = data.newConstant(sz,(val[0] + off) & calc_mask(sz));
  newvn[1] = data.newConstant(sz,(val[1] - off) & calc_mask(sz));
  PcodeOp *newptrsubop = data.newOpBefore(op,CPUI_PTRSUB,basevn,newvn[0]);
  PcodeOp *newaddop = data.newOpBefore(op,CPUI_INT_ADD,invn,newvn[1]);
  data.opSetInput(op,newptrsubop->getOut(),0);
  data.opSetInput(op,newaddop->getOut(),1);
  return 1;
}

PcodeOp *RuleInferPointerMult::getCounterInitOp(PcodeOp *multiop,int4 &slot)

{
  PcodeOp *op = multiop;
  // Skip copy if present
  Varnode *vn = multiop->getIn(0);
  if (vn->getDef() != (PcodeOp *)0) {
    if (vn->getDef()->code() == CPUI_COPY) {
      op = vn->getDef();
    }
  }

  vn = op->getIn(0);
  if (vn->isConstant()) {
    slot = 0;
    return op;
  }

  PcodeOp *initop = vn->getDef();
  if (initop != (PcodeOp *)0) {
    if (initop->code() == CPUI_INT_MULT) {
      Varnode *avn = initop->getIn(1);
      if (avn->isConstant()) {
        if (initop->getOut()->loneDescend() == (PcodeOp *)0) return (PcodeOp *)0;
	slot = 1;
	return initop;
      }
    }
  }
  return (PcodeOp *)0;
}

intb RuleInferPointerMult::getCounterIncrement(PcodeOp *op)

{
  // Increment must be constant
  Varnode *cvn = op->getIn(1);
  if (!cvn->isConstant()) return 0;
  Varnode *invn = op->getIn(0);
  if (invn->isFree()) return 0;

  PcodeOp *multiop = invn->getDef();
  if (multiop == (PcodeOp *)0) return 0;
  if (multiop->code() != CPUI_MULTIEQUAL) return 0;

  // Check multi input
  Varnode *inmulti = multiop->getIn(1);
  if (inmulti->isFree()) return 0;
  PcodeOp *inadd = inmulti->getDef();
  if (inadd == (PcodeOp *)0) return 0;
  // Must loop to INT_ADD
  if (inadd != op) return 0;

  int4 slot;
  PcodeOp *initop = getCounterInitOp(multiop,slot);
  if (initop == (PcodeOp *)0) return 0;
  return sign_extend(cvn->getOffset(),8*cvn->getSize()-1);
}

intb RuleInferPointerMult::getCounterMultiplier(PcodeOp *op)

{
  // Increment must be constant
  Varnode *cvn = op->getIn(1);
  if (!cvn->isConstant()) return 0;
  Varnode *invn = op->getIn(0);
  if (invn->isFree()) return 0;

  PcodeOp *multiop = op->getOut()->loneDescend();
  // Should not touch if haven't split out other descendants yet
  if (multiop == (PcodeOp *)0) return 0;
  if (multiop->code() != CPUI_MULTIEQUAL) return 0;

  // Check multi input
  Varnode *inmulti = multiop->getIn(1);
  if (inmulti->isFree()) return 0;
  PcodeOp *inmult = inmulti->getDef();
  if (inmult == (PcodeOp *)0) return 0;
  // Must loop to intmult
  if (inmult != op) return 0;

  int4 slot;
  PcodeOp *initop = getCounterInitOp(multiop,slot);
  // Seems to be required since we have multiequal which requires at least 2 definitions
  if (initop == (PcodeOp *)0) return 0;
  return sign_extend(cvn->getOffset(),8*cvn->getSize()-1);
}

bool RuleInferPointerMult::formIncrement(PcodeOp *op,Funcdata &data)

{
  if (!data.hasTypeRecoveryStarted()) return false;

  // Specific to this form
  if (op->code() != CPUI_INT_ADD) return false;

  // Should not touch if haven't split out other descendants yet
  if (op->getOut()->loneDescend() == (PcodeOp *)0) return false;

  intb increment = getCounterIncrement(op);
  if (increment == 0) return false;
  if (increment == 1) return false;
  if (increment == -1) return false;

  Varnode *invn0 = op->getIn(0);
  if (invn0->isFree()) return false;
  PcodeOp *multiop = invn0->getDef();
  int4 slot;
  PcodeOp *initop = getCounterInitOp(multiop, slot);
  if (initop == 0) return false;
  Varnode *initvn = initop->getIn(slot);

  intb a = sign_extend(initvn->getOffset(),8*initvn->getSize()-1);
  bool isnegative = increment < 0;
  intb b = isnegative ? -increment : increment;
  if (a % b != 0) return false;

  Varnode *out = multiop->getOut();
  if (out->isFree()) return false;
  set<Varnode *> visitedVarnodes;
  if (!checkPointerUsages(out,visitedVarnodes,data)) return false;
  visitedVarnodes.clear();

  // Collect descends
  vector<PcodeOp *> descends;
  vector<PcodeOp *> mainops;
  for(list<PcodeOp *>::const_iterator iter=out->beginDescend();iter!=out->endDescend();++iter) {
    PcodeOp *descend = *iter;
    bool isMain;
    if (!testMainOp(op,descend,isMain)) return false;
    // Main op is processed separately
    if (isMain)
      mainops.push_back(descend);
    else
      descends.push_back(descend);
  }

  intb val = isnegative ? -1 : 1;
  for(vector<PcodeOp *>::const_iterator iter=mainops.begin();iter!=mainops.end();++iter) {
    PcodeOp *mainop = *iter;
    Varnode *invn1 = mainop->getIn(1);
    int4 sz = invn1->getSize();
    data.opSetInput(mainop,data.newConstant(sz,val & calc_mask(sz)),1);
  }
  val = isnegative ? -increment : increment;
  int4 sz = out->getSize();
  for(vector<PcodeOp *>::const_iterator iter=descends.begin();iter!=descends.end();++iter) {
    PcodeOp *descend = *iter;
    PcodeOp *newop = data.newOpAfter(multiop,CPUI_INT_MULT,out,data.newConstant(sz,val & calc_mask(sz)));
    int4 slot = descend->getSlot(out);
    data.opSetInput(descend,newop->getOut(),slot);
  }
  // Also divide initializer
  if (a != 0) {
    val = a / b;
    data.opSetInput(initop,data.newConstant(initvn->getSize(),val & calc_mask(initvn->getSize())),slot);
  }
  return true;
}

bool RuleInferPointerMult::formAssignment(PcodeOp *op,Funcdata &data)

{
  if (!data.hasTypeRecoveryStarted()) return false;

  // Specific to this form
  if (op->code() != CPUI_INT_MULT) return false;

  intb multiplier = getCounterMultiplier(op);
  if (multiplier < 2) return false;

  PcodeOp *multiop = op->getOut()->loneDescend();
  int4 slot;
  PcodeOp *initop = getCounterInitOp(multiop, slot);
  if (initop == 0) return false;
  Varnode *initvn = initop->getIn(slot);

  intb a = sign_extend(initvn->getOffset(),8*initvn->getSize()-1);
  intb b = multiplier;
  if (a % b != 0) return false;

  Varnode *out = multiop->getOut();
  if (out->isFree()) return false;
  set<Varnode *> visitedVarnodes;
  if (!checkPointerUsages(out,visitedVarnodes,data)) return false;
  visitedVarnodes.clear();

  // Collect descends
  vector<PcodeOp *> descends;
  vector<PcodeOp *> mainops;
  for(list<PcodeOp *>::const_iterator iter=out->beginDescend();iter!=out->endDescend();++iter) {
    PcodeOp *descend = *iter;
    bool isMain;
    if (!testMainOp(op,descend,isMain)) return false;
    // Main op is processed separately
    if (isMain)
      mainops.push_back(descend);
    else
      descends.push_back(descend);
  }

  // Should not have any usage of main op
  if (!mainops.empty()) return false;
  intb val = 1;
  Varnode *invn1 = op->getIn(1);
  int4 sz = invn1->getSize();
  data.opSetInput(op,data.newConstant(sz,val & calc_mask(sz)),1);
  val = multiplier;
  sz = out->getSize();
  for(vector<PcodeOp *>::const_iterator iter=descends.begin();iter!=descends.end();++iter) {
    PcodeOp *descend = *iter;
    PcodeOp *newop = data.newOpAfter(multiop,CPUI_INT_MULT,out,data.newConstant(sz,val & calc_mask(sz)));
    int4 slot = descend->getSlot(out);
    data.opSetInput(descend,newop->getOut(),slot);
  }
  // Also divide initializer
  if (a != 0) {
    val = a / b;
    data.opSetInput(initop,data.newConstant(initvn->getSize(),val & calc_mask(initvn->getSize())),slot);
  }
  return true;
}

void RuleInferPointerMult::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ADD);
  oplist.push_back(CPUI_INT_MULT);
}

/// \class RuleInferPointerMult
/// \brief Infer pointer counter multiplication everywhere it is used but make assignments simpler instead
/// Only possible if written twice. The forms:
/// 1) The first is the initializer and the second is the increment:
///  - `V = W * c; ... = V; V = V +- c => V = W; ... = V * c; V = V +- 1`
/// 2) The first is the initializer and the second is the assignment:
///  - `V = W * c; ... = V; V = X * c => V = W; ... = V * c; V = X`
int4 RuleInferPointerMult::applyOp(PcodeOp *op,Funcdata &data)

{
  if (formIncrement(op,data)) return 1;
  if (formAssignment(op,data)) return 1;
  return 0;
}

bool RuleInferPointerMult::canApply(PcodeOp *op,Funcdata &data)

{
  intb increment = getCounterIncrement(op);
  if (increment == 0) return false;
  if (increment == 1) return false;
  if (increment == -1) return false;

  Varnode *invn0 = op->getIn(0);
  if (invn0->isFree()) return false;
  PcodeOp *multiop = invn0->getDef();
  int4 slot;
  PcodeOp *initop = getCounterInitOp(multiop, slot);
  if (initop == 0) return false;
  Varnode *initvn = initop->getIn(slot);

  Varnode *out = multiop->getOut();
  if (out->isFree()) return false;

  return true;
}

bool RuleInferPointerMult::checkPointerUsages(Varnode *vn,set<Varnode *> visitedVarnodes,Funcdata &data)

{
  if (visitedVarnodes.find(vn) != visitedVarnodes.end()) return false;
  visitedVarnodes.insert(vn);
  PcodeOp *multiop = vn->getDef();
  if (multiop == (PcodeOp *)0) return false;
  if (multiop->code() != CPUI_MULTIEQUAL) return false;

  for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    PcodeOp *descend = op;
    OpCode opc = descend->code();
    if (opc == CPUI_MULTIEQUAL) {
      if (descend == multiop) continue;
      // Check if used somewhere farther
      if (checkPointerUsages(descend->getOut(),visitedVarnodes,data)) return true;
    }
    if (!(opc == CPUI_INT_ADD || opc == CPUI_INT_MULT)) continue;
    if (descend->getOut() != (Varnode *)0) {
      PcodeOp *lone = descend->getOut()->loneDescend();
      if (lone != (PcodeOp *)0) {
	if (lone->code() == CPUI_LOAD) return true;
	if (lone->code() == CPUI_STORE) return true;
      }
    }
    Varnode *out = vn;
    PcodeOp *addop = op;
    if (!addop->containsInput(out)) return false;
    int4 addslot = addop->getSlot(out);
    while (opc == CPUI_INT_ADD || opc == CPUI_INT_MULT) {
      addop = descend;
      if (!addop->containsInput(out)) return false;
      addslot = addop->getSlot(out);

      // Check if any of the other add inputs are defined as the result of some pointer operation
      for (int4 i=0;i<addop->numInput();++i) {
	if (i == addslot) continue;
	Varnode *invn = addop->getIn(i);
	PcodeOp *inop = invn->getDef();
	if (inop == (PcodeOp *)0) continue;
	if (inop->code() == CPUI_PTRADD) return true;
	if (inop->code() == CPUI_PTRSUB) return true;
      }

      out = addop->getOut();
      descend = out->loneDescend();
      if (descend == (PcodeOp *)0) break;
      opc = descend->code();
    }

    if (descend == (PcodeOp *)0) continue;
    opc = descend->code();
    if (opc == CPUI_LOAD || opc == CPUI_STORE) {
      Varnode *ptrvn = addop->getIn(1-addslot);
      Datatype *ptrdt = ptrvn->getTypeReadFacing(addop);
      Varnode *othervn = addop->getIn(addslot);
      Datatype *otherdt = othervn->getTypeReadFacing(addop);
      if (ptrdt->getMetatype() != TYPE_PTR) continue;
      return true;
    }
    if (opc = CPUI_CALL) {
      FuncCallSpecs *fc = data.getCallSpecs(descend);
      int4 slot = descend->getSlot(out);
      if (fc == (FuncCallSpecs *)0) continue;
      ProtoParameter *param = fc->getParam(slot-1);
      if (param == (ProtoParameter *)0) continue;
      Datatype *dt = param->getType();
      if (dt->getMetatype() != TYPE_PTR) continue;
      return true;
    }
  }
  return false;
}

bool RuleInferPointerMult::testMainOp(PcodeOp *mainop,PcodeOp *otherop,bool &isMain)

{
  if (otherop == mainop) {
    isMain = true;
    return true;
  }
  intb increment = getCounterIncrement(mainop);
  if (otherop->code() != CPUI_INT_ADD) {
    isMain = false;
    return true;
  }
  if (otherop->getIn(0) != mainop->getIn(0)) {
    isMain = false;
    return true;
  }
  if (!otherop->getIn(1)->isConstant()) {
    isMain = false;
    return true;
  }
  Varnode *cvn = otherop->getIn(1);
  intb c = sign_extend(cvn->getOffset(),8*cvn->getSize()-1);
  if (c != increment) {
    isMain = false;
    return true;
  }
  PcodeOp *lone = otherop->getOut()->loneDescend();
  // TODO investigate cases
  if (lone != (PcodeOp *)0) {
    if (lone->code() == CPUI_LOAD) {
      isMain = false;
      return true;
    }
    if (lone->code() == CPUI_STORE) {
      isMain = false;
      return true;
    }
    if (lone->code() == CPUI_INDIRECT) {
      isMain = true;
      return false;
    }
  }
  if (otherop->getAddr() == mainop->getAddr()) {
    isMain = true;
    return false;
  }
  isMain = false;
  return false;
}

PcodeOp *RuleInferPointerAdd::getCounterInitOp(PcodeOp *multiop,int4 &slot)

{
  PcodeOp *op = multiop;
  // Skip copy if present
  Varnode *vn = multiop->getIn(0);
  if (vn->getDef() != (PcodeOp *)0) {
    if (vn->getDef()->code() == CPUI_COPY) {
      op = vn->getDef();
    }
  }

  slot = 0;
  vn = op->getIn(slot);
  if (vn->isConstant()) {
    if (op->getOut()->loneDescend() == (PcodeOp *)0) return (PcodeOp *)0;
    return op;
  }

  PcodeOp *initop = vn->getDef();
  if (initop != (PcodeOp *)0) {
    if (initop->code() == CPUI_INT_ADD) {
      slot = 1;
      Varnode *cvn = initop->getIn(slot);
      if (cvn->isConstant()) {
        if (initop->getOut()->loneDescend() == (PcodeOp *)0) return (PcodeOp *)0;
        return initop;
      }
    }
  }
  return (PcodeOp *)0;
}

intb RuleInferPointerAdd::getCounterIncrement(PcodeOp *op)

{
  // Increment must be constant
  Varnode *cvn = op->getIn(1);
  if (!cvn->isConstant()) return 0;
  Varnode *invn = op->getIn(0);
  if (invn->isFree()) return 0;

  PcodeOp *multiop = invn->getDef();
  if (multiop == (PcodeOp *)0) return 0;
  if (multiop->code() != CPUI_MULTIEQUAL) return 0;

  // Check multi input
  Varnode *inmulti = multiop->getIn(1);
  if (inmulti->isFree()) return 0;
  PcodeOp *inadd = inmulti->getDef();
  if (inadd == (PcodeOp *)0) return 0;
  // Must loop to INT_ADD
  if (inadd != op) return 0;

  int4 slot;
  PcodeOp *initop = getCounterInitOp(multiop,slot);
  if (initop == (PcodeOp *)0) return 0;
  return sign_extend(cvn->getOffset(),8*cvn->getSize()-1);
}

bool RuleInferPointerAdd::getOffsets(PcodeOp *op,PcodeOp *initop,int4 slot,intb increment,intb &shiftOffset,intb &initialOffset,int4 &size)

{
  bool isSpaceBase = false;
  if (initop == (PcodeOp *)0) return false;
  Varnode *initvn = initop->getIn(slot);
  if (!initvn->isConstant()) return false;
  size = initvn->getSize();
  initialOffset = sign_extend(initvn->getOffset(),8*size-1);

  shiftOffset = sign_extend(initvn->getOffset(),8*size-1);
  if (initop->code() == CPUI_INT_ADD && initop->getIn(1 - slot)->isSpacebase()) return false;
  intb step;
  if (increment < 0) {
    step = -increment;
  }
  else {
    step = increment;
  }
  if (shiftOffset < 0) return true;
  shiftOffset = shiftOffset % step;
  if (shiftOffset == 0) return false;
  return true;
}

bool RuleInferPointerAdd::formConstant(PcodeOp *op,Funcdata &data)

{
  // Should not touch if haven't split out other descendants yet
  if (op->getOut()->loneDescend() == (PcodeOp *)0) return false;

  intb increment = getCounterIncrement(op);
  if (increment == 0) return false;

  PcodeOp *multiOp = op->getIn(0)->getDef();
  int4 slot;
  PcodeOp *initOp = getCounterInitOp(multiOp, slot);

  intb shiftOffset;
  intb initialOffset;
  int4 size;
  if (!getOffsets(op,initOp,slot,increment,shiftOffset,initialOffset,size)) return false;

  Varnode *multiOut = multiOp->getOut();
  if (multiOut->isFree()) return false;
  if (multiOut->getSize() != size) return false;
  set<Varnode *> visitedVarnodes;
  if (!RuleInferPointerMult::checkPointerUsages(multiOut,visitedVarnodes,data)) return false;
  visitedVarnodes.clear();

  // Collect descends
  vector<PcodeOp *> descends;
  for(list<PcodeOp *>::const_iterator iter=multiOut->beginDescend();iter!=multiOut->endDescend();++iter) {
    PcodeOp *descend = *iter;

    // Check slot repetition
    int4 firstSlot = descend->getSlot(multiOut);
    list<PcodeOp *>::const_iterator endIter = multiOut->endDescend();
    int4 repeatSlot = descend->getRepeatSlot(multiOut,firstSlot,endIter);
    if (repeatSlot != -1) return false; // Don't know how to handle this case yet

    bool isMain;
    if (!RuleInferPointerMult::testMainOp(op,descend,isMain)) return false;
    // Main op isn't processed
    if (isMain) continue;
    descends.push_back(descend);
  }

  for(vector<PcodeOp *>::const_iterator iter=descends.begin();iter!=descends.end();++iter) {
    PcodeOp *descend = *iter;
    PcodeOp *newop = data.newOpAfter(multiOp,CPUI_INT_ADD,multiOut,data.newConstant(size,shiftOffset&calc_mask(size)));
    int4 slot = descend->getSlot(multiOut);
    data.opSetInput(descend,newop->getOut(),slot);
  }
  // Also subtract initializer
  data.opSetInput(initOp,data.newConstant(size,initialOffset-shiftOffset),slot);
  return true;
}

bool RuleInferPointerAdd::formSpacebase(PcodeOp *op,Funcdata &data)

{
  // Should not touch if haven't split out other descendants yet
  if (op->getOut()->loneDescend() == (PcodeOp *)0) return false;

  intb increment = getCounterIncrement(op);
  if (increment == 0) return false;

  PcodeOp *multiOp = op->getIn(0)->getDef();
  int4 slot; // Slot with constant
  PcodeOp *initOp = getCounterInitOp(multiOp,slot);

  if (initOp == (PcodeOp *)0) return false;
  if (initOp->code() != CPUI_INT_ADD) return false;
  Varnode *cvn = initOp->getIn(slot);
  if (!cvn->isConstant()) return false;
  int4 size = cvn->getSize();
  Varnode *spacebasevn = initOp->getIn(1-slot);
  if (spacebasevn->isFree()) return false;
  if (!spacebasevn->isSpacebase()) return false;
  Varnode *initopOut = initOp->getOut();
  if (initopOut->isFree()) return false;

  Varnode *multiOut = multiOp->getOut();
  if (multiOut->isFree()) return false;
  if (multiOut->getSize() != size) return false;
  set<Varnode *> visitedVarnodes;
  if (!RuleInferPointerMult::checkPointerUsages(multiOut,visitedVarnodes,data)) return false;
  visitedVarnodes.clear();

  // Collect descends
  vector<PcodeOp *> descends;
  for(list<PcodeOp *>::const_iterator iter=multiOut->beginDescend();iter!=multiOut->endDescend();++iter) {
    PcodeOp *descend = *iter;

    // Check slot repetition
    int4 firstSlot = descend->getSlot(multiOut);
    list<PcodeOp *>::const_iterator endIter = multiOut->endDescend();
    int4 repeatSlot = descend->getRepeatSlot(multiOut,firstSlot,endIter);
    if (repeatSlot != -1) return false; // Don't know how to handle this case yet

    bool isMain;
    if (!RuleInferPointerMult::testMainOp(op,descend,isMain)) return false;
    // Main op isn't processed
    if (isMain) continue;
    descends.push_back(descend);
  }

  if (descends.empty()) return false;
  for(vector<PcodeOp *>::const_iterator iter=descends.begin();iter!=descends.end();++iter) {
    PcodeOp *descend = *iter;
    PcodeOp *newop = data.newOpAfter(multiOp,CPUI_INT_ADD,multiOut,initopOut);
    int4 slot = descend->getSlot(multiOut);
    data.opSetInput(descend,newop->getOut(),slot);
  }
  // Also subtract initializer
  PcodeOp *newop = data.newOpBefore(multiOp,CPUI_COPY,data.newConstant(size,0));
  data.opSetInput(multiOp,newop->getOut(),0);
  return true;
}

void RuleInferPointerAdd::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ADD);
}

/// \class RuleInferPointerAdd
/// \brief Infer pointer counter addition everywhere it is used but make assignments simpler instead
/// Only possible if writen twice. First is the initializer and the second is the increment:
///  - `V = W + X; ... = V; V = V + c => V = W; ... = V + X; V = V + c`
int4 RuleInferPointerAdd::applyOp(PcodeOp *op,Funcdata &data)

{
  if (formConstant(op,data)) return 1;
  if (formSpacebase(op,data)) return 1;
  return 0;
}

bool RuleInferPointerAdd::canApply(PcodeOp *op,Funcdata &data)

{
  intb increment = getCounterIncrement(op);
  if (increment == 0) return false;

  Varnode *invn0 = op->getIn(0);
  if (invn0->isFree()) return false;
  PcodeOp *multiop = invn0->getDef();
  int4 slot;
  PcodeOp *initop = getCounterInitOp(multiop, slot);
  if (initop == 0) return false;
  Varnode *initvn = initop->getIn(slot);

  Varnode *out = multiop->getOut();
  if (out->isFree()) return false;

  return true;
}

// Returns change of counter or 0 if not a valid counter vn
intb RulePointerComparison::getCounterIncrement(Varnode *vn)

{
  PcodeOp *op = vn->getDef();
  if (op == (PcodeOp *)0) return 0;
  if (op->code() == CPUI_PTRADD) {
    op = op->getIn(0)->getDef();
  }

  PcodeOp *multiop = op;
  if (multiop == (PcodeOp *)0) return 0;
  if (multiop->code() != CPUI_MULTIEQUAL) return 0;

  PcodeOp *addop = multiop->getIn(1)->getDef();
  if (addop == (PcodeOp *)0) return 0;
  if (addop->code() != CPUI_PTRADD) return 0;
  if (addop->getIn(0)->getDef() != multiop) return 0; // Must loop to multi

  Varnode *in1 = addop->getIn(1);
  Varnode *in2 = addop->getIn(2);
  // The increment must be a constant
  if (!in1->isConstant()) return 0;
  if (!in2->isConstant()) return 0;
  intb val1 = sign_extend(in1->getOffset(),8*in1->getSize()-1);
  intb val2 = sign_extend(in2->getOffset(),8*in2->getSize()-1);
  return val1*val2;
}

Varnode *RulePointerComparison::getSpacebase(Varnode* vn)

{
  Varnode *currentVn = vn;
  while (!currentVn->isSpacebase()) {
    PcodeOp *op = currentVn->getDef();
    if (op == (PcodeOp *)0) {
      return (Varnode *)0;
    }
    Varnode *in1,*in2;
    intb val1,val2;
    switch (op->code()) {
      case CPUI_PTRADD:
      case CPUI_PTRSUB:
      case CPUI_INT_ADD:
	currentVn = op->getIn(0);
	break;
      default:
	return (Varnode *)0;
    }
  }
  return currentVn;
}

// This goes right to spacebase register and sums up everything on its way
bool RulePointerComparison::getOffset(Varnode* vn,intb &offset)

{
  offset = 0;
  Varnode *currentVn = vn;
  while (!currentVn->isSpacebase()) {
    PcodeOp *op = currentVn->getDef();
    if (op == (PcodeOp *)0) {
      offset = 0;
      return false;
    }
    Varnode *in1,*in2;
    intb val1,val2;
    switch (op->code()) {
      case CPUI_PTRADD:
	in1 = op->getIn(1);
	in2 = op->getIn(2);
	if (!in1->isConstant()) return false; // Cannot fetch constant
	if (!in2->isConstant()) return false; // Cannot fetch constant
	val1 = sign_extend(in1->getOffset(),8*in1->getSize()-1);
	val2 = sign_extend(in2->getOffset(),8*in2->getSize()-1);
	offset += val1*val2;
	currentVn = op->getIn(0);
	break;
      case CPUI_PTRSUB:
	in1 = op->getIn(1);
	if (!in1->isConstant()) return false; // Cannot fetch constant
	val1 = sign_extend(in1->getOffset(),8*in1->getSize()-1);
	offset += val1;
	currentVn = op->getIn(0);
	break;
      case CPUI_INT_ADD:
	in1 = op->getIn(1);
	if (!in1->isConstant()) return false; // Cannot fetch constant
	val1 = sign_extend(in1->getOffset(),8*in1->getSize()-1);
	offset += val1;
	currentVn = op->getIn(0);
	break;
      default:
	offset = 0; // Either not implemented or not supported
	return false;
    }
  }
  return true;
}

/// \brief Calculate difference between end and begin reference values
///
/// \param op is main pcodeop
/// \param referenceSlot is slot of end varnode
/// \param difference is reference to store difference
/// \return true if valid false otherwise
bool RulePointerComparison::getDifference(PcodeOp *op,int4 referenceSlot,intb &difference)

{
  difference = 0;
  Varnode *otherVn = op->getIn(1-referenceSlot);
  Varnode *endVn = op->getIn(referenceSlot);
  intb endOffset;
  if (!getOffset(endVn,endOffset)) return false;

  PcodeOp *otherOp = otherVn->getDef();
  if (otherOp == (PcodeOp *)0) return false;
  if (otherOp->code() == CPUI_PTRADD) {
    otherOp = otherOp->getIn(0)->getDef();
  }

  PcodeOp *multiop = otherOp;
  if (multiop == (PcodeOp *)0) return 0;
  if (multiop->code() != CPUI_MULTIEQUAL) return 0;

  Varnode *beginVn = multiop->getIn(0);
  intb beginOffset;
  if (!getOffset(beginVn,beginOffset)) return false;

  difference = endOffset - beginOffset;
  return true;
}

PcodeOp *RulePointerComparison::getNewOp(PcodeOp *op,Funcdata &data,Varnode *input,intb change)

{
  intb endOffset;
  if (!getOffset(input,endOffset)) return (PcodeOp *)0;
  Varnode *invn = getSpacebase(input);
  if (invn == (Varnode *)0) return (PcodeOp *)0;
  return data.newOpBefore(op,CPUI_PTRSUB,invn,data.newConstant(input->getSize(),endOffset+change));
}

// pointer variable < reference value
// increment and difference are positive
bool RulePointerComparison::form1(PcodeOp *op,Funcdata &data,bool is_signed)

{
  if (is_signed) {
    if (op->code() != CPUI_INT_SLESS) return false;
  }
  else {
    if (op->code() != CPUI_INT_LESS) return false;
  }
  intb increment = getCounterIncrement(op->getIn(0));
  if (increment <= 0) return false;
  intb difference;
  if (!getDifference(op,1,difference)) return false; // Reference value isn't valid
  if (difference <= 0) return false;
  intb change = 0;
  intb remainder = difference % increment;
  if (remainder == 0) {
    change = -increment;
  }
  else {
    change = -remainder;
  }
  PcodeOp *newop = getNewOp(op,data,op->getIn(1),change);
  if (newop == (PcodeOp *)0) return false;
  if (is_signed) {
    data.opSetOpcode(op,CPUI_INT_SLESSEQUAL);
  }
  else {
    data.opSetOpcode(op,CPUI_INT_LESSEQUAL);
  }
  data.opSetInput(op,newop->getOut(),1);
  return true;
}

// reference value < pointer variable
// increment and difference are negative
bool RulePointerComparison::form2(PcodeOp *op,Funcdata &data,bool is_signed)

{
  if (is_signed) {
    if (op->code() != CPUI_INT_SLESS) return false;
  }
  else {
    if (op->code() != CPUI_INT_LESS) return false;
  }
  intb increment = getCounterIncrement(op->getIn(1));
  if (increment >= 0) return false;
  intb difference;
  if (!getDifference(op,0,difference)) return false; // Reference value isn't valid
  if (difference >= 0) return false;
  intb change = 0;
  intb remainder = (-difference) % (-increment);
  if (remainder == 0) {
    change = -increment;
  }
  else {
    change = remainder;
  }
  PcodeOp *newop = getNewOp(op,data,op->getIn(0),change);
  if (newop == (PcodeOp *)0) return false;
  if (is_signed) {
    data.opSetOpcode(op,CPUI_INT_SLESSEQUAL);
  }
  else {
    data.opSetOpcode(op,CPUI_INT_LESSEQUAL);
  }
  data.opSetInput(op,newop->getOut(),0);
  return true;
}

// pointer variable != reference value
bool RulePointerComparison::form3(PcodeOp *op,Funcdata &data)

{
  if (op->code() != CPUI_INT_NOTEQUAL) return false;
  intb increment = getCounterIncrement(op->getIn(0));
  if (increment == 0) return false;
  intb difference;
  if (!getDifference(op,1,difference)) return false; // Reference value isn't valid
  if (difference == 0) return false;
  bool isnegative;
  if (difference > 0 && increment > 0) {
    isnegative = false;
  }
  else if (difference < 0 && increment < 0) {
    isnegative = true;
  }
  else {
    return false; // Directions don't match
  }
  intb change = 0;
  intb remainder;
  if (isnegative) {
    remainder = (-difference) % (-increment);
  }
  else {
    remainder = difference % increment;
  }
  if (remainder == 0) {
    change = -increment;
  }
  else {
    if (isnegative) {
      change = remainder;
    }
    else {
      change = -remainder;
    }
  }
  Varnode *invn = op->getIn(0);
  PcodeOp *newop = getNewOp(op,data,op->getIn(1),change);
  if (newop == (PcodeOp *)0) return false;
  data.opSetOpcode(op,CPUI_INT_LESSEQUAL);
  if (isnegative) {
    data.opSetInput(op,newop->getOut(),0);
    data.opSetInput(op,invn,1);
  }
  else {
    data.opSetInput(op,newop->getOut(),1);
  }
  return true;
}

void RulePointerComparison::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_LESS);
  oplist.push_back(CPUI_INT_SLESS);
  oplist.push_back(CPUI_INT_NOTEQUAL);
}

int4 RulePointerComparison::applyOp(PcodeOp *op,Funcdata &data)

{
  bool is_signed = false;
  if (op->code() == CPUI_INT_SLESS) {
    is_signed = true;
  }
  if (form1(op,data,is_signed)) return 1;
  if (form2(op,data,is_signed)) return 1;
  if (form3(op,data)) return 1;
  return 0;
}

void RuleInferVbptr::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_LOAD);
}

int4 RuleInferVbptr::applyOp(PcodeOp *op,Funcdata &data)

{
  // Parse pcodeops
  PcodeOp *addop = op->getIn(1)->getDef();
  if (addop == (PcodeOp *)0) return 0;
  OpCode opc = addop->code();
  if (opc != CPUI_PTRADD && opc != CPUI_INT_ADD)
    return 0;
  PcodeOp *loadop = addop->getIn(0)->getDef();
  if (loadop == (PcodeOp *)0) return 0;
  if (loadop->code() != CPUI_LOAD) return 0;

  // Get pointer size
  int8 step = op->getOut()->getSize();
  int8 index = 0;
  int8 offset = 0;
  Varnode *ptr0vn = loadop->getIn(1);
  if (ptr0vn->getSize() != step) return 0;
  Datatype *ptr0dt = (Datatype *)0;
  PcodeOp *ptrop = (PcodeOp *)0;
  int4 ptrslot = 1;

  PcodeOp *ptrsubop = ptr0vn->getDef();
  if (ptrsubop != (PcodeOp *)0) {
    opc = ptrsubop->code();
    if (opc != CPUI_PTRSUB && opc != CPUI_INT_ADD)
      return 0;
    if (opc == CPUI_PTRSUB) {
      Varnode *ptr0vn = ptrsubop->getIn(0);
      Varnode *offsetvn = ptrsubop->getIn(1);
      if (!offsetvn->isConstant()) return 0;
      offset = sign_extend(offsetvn->getOffset(),8*offsetvn->getSize()-1);
      ptrop = ptrsubop;
      ptrslot = 0;
      ptr0dt = ptr0vn->getTypeReadFacing(ptrop);
    }
    if (opc == CPUI_INT_ADD) {
      Varnode *ptr0vn = ptrsubop->getIn(0);
      Varnode *offsetvn = ptrsubop->getIn(1);
      if (!offsetvn->isConstant()) return 0;
      offset = sign_extend(offsetvn->getOffset(),8*offsetvn->getSize()-1);
      ptrop = ptrsubop;
      ptrslot = 0;
      ptr0dt = ptr0vn->getTypeReadFacing(ptrop);
    }
  }
  else {
    ptrop = loadop;
    ptr0dt = ptr0vn->getTypeReadFacing(ptrop);
  }

  Varnode *ptr1vn = addop->getIn(0);
  if (ptr1vn->getSize() != step) return 0;
  opc = addop->code();
  if (opc == CPUI_PTRADD) {
    Varnode *stepvn = addop->getIn(2);
    if (!stepvn->isConstant()) return 0;
    if (stepvn->getOffset() != step) return 0;
    Varnode *indexvn = addop->getIn(1);
    if (!indexvn->isConstant()) return 0;
    index = indexvn->getOffset();
  }
  if (opc == CPUI_INT_ADD) {
    Varnode *indexvn = addop->getIn(1);
    if (!indexvn->isConstant()) return 0;
    index = indexvn->getOffset();
    if (index % step != 0) return 0;
    index /= step;
  }
  if (index == 0) return 0;

  if (op->getOut()->getSize() != step) return 0;
  if (ptr0dt->getMetatype() != TYPE_PTR) return 0;
  TypeStruct *outerdt = 0;
  if (ptr0dt->getSubMeta() == SUB_PTRREL) {
    TypePointerRel *outerptrdt = dynamic_cast<TypePointerRel *>(ptr0dt);
    int4 ptrreloffset = outerptrdt->getPointerOffset();
    if (ptrreloffset != 0) {
      offset += ptrreloffset;
    }
    outerdt = dynamic_cast<TypeStruct *>(outerptrdt->getParent());
  }
  else {
    TypePointer *outerptrdt = dynamic_cast<TypePointer *>(ptr0dt);
    outerdt = dynamic_cast<TypeStruct *>(outerptrdt->getPtrTo());
  }
  if (outerdt == (TypeStruct *)0) return 0;
  int8 newoffset;
  const TypeField *vbptrfield = outerdt->findTruncation(offset,ptrop->getOut()->getSize(),ptrop,ptrslot,newoffset);
  if (vbptrfield == (TypeField *)0) return 0;
  while (vbptrfield->type->getMetatype() == TYPE_STRUCT) {
    outerdt = dynamic_cast<TypeStruct *>(vbptrfield->type);
    int8 structoffset;
    vbptrfield = outerdt->findTruncation(newoffset,ptrop->getOut()->getSize(),ptrop,ptrslot,structoffset);
    newoffset = structoffset;
    if (vbptrfield == (TypeField *)0) return 0;
  }
  if (newoffset != 0) return 0;
  if (vbptrfield->name != Funcdata::FIELD_VBPTR) return 0;

  // Fill "super::..." fields
  vector<const TypeField *> superFields;
  int8 i;
  for (i=0;i<=index;++i) {
    superFields.push_back((TypeField *)0);
  }
  string superPrefix("super::");
  vector<TypeField>::const_iterator iter;
  for (iter=outerdt->beginField(),i=1;iter!=outerdt->endField()&&i<=index;++iter) {
    const TypeField &field(*iter);
    if (field.name.substr(0,superPrefix.size()) == superPrefix) {
      superFields[i] = &field;
      ++i;
    }
  }
  const TypeField *superfield = superFields[index];
  if (superfield == (const TypeField *)0) return 0;
  intb value = sign_extend(superfield->offset,8*step-1);
  value -= vbptrfield->offset;
  data.opSetOpcode(op,CPUI_COPY);
  data.opSetInput(op,data.newConstant(step,value),0);
  data.opRemoveInput(op,1);
  return 1;
}

map<Varnode *,uintb>::iterator RuleByteLoop::VarnodeValues::getEntry(Varnode *key)

{
  map<Varnode *,uintb>::iterator iter;
  for(iter=vals.begin();iter!=vals.end();++iter) {
    Varnode *vn = (*iter).first;

    Address vnAddress = vn->getAddr();
    Address keyAddress = key->getAddr();
    int4 vnSize = vn->getSize();
    int4 keySize = key->getSize();

    if (vnAddress != keyAddress) continue;
    if (vnSize != keySize) continue;
    return iter;
  }
  return vals.end();
}

bool RuleByteLoop::VarnodeValues::contains(Varnode *key)

{
  if (key->isConstant()) return true;
  return getEntry(key) != vals.end();
}

void RuleByteLoop::VarnodeValues::removeValue(Varnode *key)

{
  while (contains(key)) {
    vals.erase((*getEntry(key)).first);
  }
}

void RuleByteLoop::VarnodeValues::putValue(Varnode *key,uintb value)

{
  if (key->getSize() > 8) return; // large varnodes aren't supported
  if (key == (Varnode *)0) return;
  removeValue(key); // must deduplicate entries
  vals[key]=value&calc_mask(key->getSize());
}

/// \brief Return offset if key is or has association with a constant
///
/// \param key is varnode representing constant
/// \return value by key
uintb RuleByteLoop::VarnodeValues::getValue(Varnode *key,bool issigned)

{
  if (key->isConstant()) {
    if (issigned) {
      return sign_extend(key->getOffset(),8*key->getSize()-1);
    }
    return key->getOffset()&calc_mask(key->getSize());
  }
  if (!contains(key)) return 0;
  if (issigned) {
    sign_extend(getEntry(key)->second,8*key->getSize()-1);
  }
  return getEntry(key)->second&calc_mask(key->getSize());
}

void RuleByteLoop::VarnodeValues::clear(void)

{
  vals.clear();
}

/// \brief Initialize counts and counterVn
///
/// \return false if cannot proceed applying rule and true if everything is fine
bool RuleByteLoop::setCountsCountervn(LoopData &loopData)

{
  if (loopData.condOp != (PcodeOp *)0 && loopData.condOp->code() == CPUI_INT_LESS) {
    if (loopData.condOp->getIn(0)->isConstant() && !loopData.condOp->getIn(1)->isConstant()) {
      loopData.counts = loopData.condOp->getIn(0)->getOffset() + 1;
      loopData.counterVn = loopData.condOp->getIn(1); // find counter varnode (usually labeled i or j in sleigh files)
    } else if (loopData.condOp->getIn(1)->isConstant() && !loopData.condOp->getIn(0)->isConstant()) {
      loopData.counts = loopData.condOp->getIn(1)->getOffset();
      loopData.counterVn = loopData.condOp->getIn(0);
    }
    else
      return false; // not exactly 1 constant
  }
  else {
    return false; // not conditional op
  }
  return true;
}

/// \brief Initialize initOp
///
/// \return false if cannot proceed applying rule and true if everything is fine
bool RuleByteLoop::setInitOp(LoopData &loopData)
{
  loopData.initOp = loopData.counterVn->getDef();
  if (loopData.initOp == (PcodeOp *)0) return false;
  if (loopData.initOp->code() != CPUI_MULTIEQUAL) return false;
  for(int4 i=0;i<2;++i) {
    PcodeOp *curop = loopData.initOp->getIn(i)->getDef();
    if (curop != (PcodeOp *)0 && curop->code() == CPUI_COPY) {
      loopData.initOp = curop;
      break;
    }
  }
  if (loopData.initOp->code() != CPUI_COPY) return false;
  if (!loopData.initOp->getIn(0)->isConstant()) return false;
  if (loopData.initOp->getIn(0)->getOffset() != 0) return false; // counter must be initialized to 0
  return true;
}

/// \brief Initialize extractlist, insertlist and multiplier
///
/// \return false if cannot proceed applying rule and true if everything is fine
bool RuleByteLoop::initExtractInsertListsMultiplier(LoopData &loopData)

{
  list<PcodeOp *>::const_iterator iter;
  for(iter=loopData.counterVn->beginDescend();iter!=loopData.counterVn->endDescend();++iter) {
    PcodeOp *curop = *iter;
    if (curop->code() == CPUI_INT_MULT) {
      int4 slot = 1 - curop->getSlot(loopData.counterVn);
      Varnode *multVn = curop->getIn(slot);
      if (multVn->isConstant()) {
	intb off = multVn->getOffset();
	off = sign_extend(off,8*multVn->getSize()-1);
	if (off < 0) {
	  loopData.multiplier = -off;
	  curop = curop->getOut()->loneDescend();
	  if (curop == (PcodeOp *)0) return false;
	  if (curop->code() != CPUI_INT_ADD) return false;
	  curop = curop->getOut()->loneDescend();
	  if (curop == (PcodeOp *)0) return false;
	}
	else if (off > 0) {
	  loopData.multiplier = off;
	  curop = curop->getOut()->loneDescend();
	  if (curop == (PcodeOp *)0) return false;
	}
	else
	  return false;
      }
    }
    if (curop->code() == CPUI_CALLOTHER) {
      string nm = curop->getOpcode()->getOperatorName(curop);
      if (nm == Funcdata::extractind && curop->getOut() != (Varnode *)0) {
	if (curop->numInput() != 3) return false;
	loopData.extractlist.push_back(curop);
      }
      else if (nm == Funcdata::insertind && loopData.insertlist.empty()) // Don't add another insertind to the list if already have one, take another rule pass instead
	loopData.insertlist.push_back(curop);
    }
  }

  if (loopData.extractlist.empty() || loopData.insertlist.empty()) return false;
  if (loopData.insertlist[0]->numInput() != 4) return false;
  if (loopData.insertlist[0]->getOut() == (Varnode *)0) return false;
  if (loopData.insertlist[0]->getOut()->loneDescend() == (PcodeOp *)0) return false;
  if (loopData.insertlist[0]->getOut()->loneDescend()->code() != CPUI_MULTIEQUAL) return false;
  // The multiplier is number of bytes of each array element
  // The counts are number of performed operations
  if (loopData.insertlist[0]->getIn(2)->getSize() != loopData.multiplier) return false;
  if (loopData.insertlist[0]->getOut()->getSize() != loopData.insertlist[0]->getIn(1)->getSize()) return false;
  if ((loopData.insertlist[0]->getIn(1)->getSize() % loopData.insertlist[0]->getIn(2)->getSize()) != 0) return false;
  if ((loopData.insertlist[0]->getIn(1)->getSize() / loopData.insertlist[0]->getIn(2)->getSize()) != loopData.counts) return false;
  if (loopData.counts < 2) return false;

  return true;
}

map<Varnode *,vector<uint1>>::iterator RuleByteLoop::LargeVarnodeValues::getEntry(Varnode *key)

{
  map<Varnode *,vector<uint1>>::iterator iter;
  for(iter=vals.begin();iter!=vals.end();++iter) {
    Varnode *vn = (*iter).first;
    if (vn->getAddr()!=key->getAddr()) continue;
    if (vn->getSize()!=key->getSize()) continue;
    return iter;
  }
  return vals.end();
}

bool RuleByteLoop::LargeVarnodeValues::contains(Varnode *key)

{
  return getEntry(key) != vals.end();
}

uintb RuleByteLoop::LargeVarnodeValues::getValue(Varnode *key,uintb off,int4 sz)

{
  uintb val = 0;
  if (!contains(key)) return val;
  if (sz > sizeof(uintb)) return val;
  vector<uint1> a = getEntry(key)->second;
  if (off + sz > a.size()) return val;
  for (int4 i=0;i<sz;++i) {
    val |= a[off+i]<<(i*8);
  }
  return val;
}

void RuleByteLoop::LargeVarnodeValues::clear(void)

{
  vals.clear();
}

/// \brief compute and save value to the vals map
vector<uint1> RuleByteLoop::LargeVarnodeValues::fetchValue(Varnode *key)

{
  if (contains(key)) return getEntry(key)->second;
  vector<uint1> res; // empty vector
  if (key->isConstant()) {
    uintb val = key->getOffset();
    for (int4 i=0;i<key->getSize();++i) {
      char r = val >> (8*i);
      res.push_back(r);
    }
    vals[key] = res;
    return res;
  }
  PcodeOp *curop = key->getDef();
  if (curop == (PcodeOp *)0) return res;
  OpCode opc = curop->code();
  vector<uint1> in0,in1;
  int4 sz;
  switch (opc) {
    case CPUI_PIECE:
      in0 = fetchValue(curop->getIn(0));
      in1 = fetchValue(curop->getIn(1));
      if (in0.empty() || in1.empty()) return res;
      for (int4 i=0;i<in1.size();++i) {
	res.push_back(in1[i]);
      }
      for (int4 i=0;i<in0.size();++i) {
	res.push_back(in0[i]);
      }
      vals[key] = res;
      return res;
    case CPUI_INT_ZEXT:
      in0 = fetchValue(curop->getIn(0));
      if (in0.empty()) return res;
      for (int4 i=0;i<in0.size();++i) {
	res.push_back(in0[i]);
      }
      sz = curop->getOut()->getSize() - curop->getIn(0)->getSize();
      for (int4 i=0;i<sz;++i) {
	res.push_back(0);
      }
      vals[key] = res;
      return res;
    default:
      return res;
  }
  return res;
}

void RuleByteLoop::collectLargeVarnodeValues(LoopData &loopData)

{
  for (int4 i = 0; i < loopData.extractlist.size(); ++i) {
    PcodeOp *curop = loopData.extractlist[i];
    loopData.largevalues.fetchValue(curop->getIn(1));
  }
}

BlockBasic *RuleByteLoop::getFallthru(PcodeOp *op)

{
  if (op->getParent() == (BlockBasic *)0) return (BlockBasic *)0;
  if (op->getParent()->sizeOut() == 0) return (BlockBasic *)0;
  if (op->getParent()->sizeOut() == 1)
    return (BlockBasic *)(op->isFallthruTrue() ? 0 : op->getParent()->getFalseOut());
  return (BlockBasic *)(op->isFallthruTrue() ? op->getParent()->getTrueOut() : op->getParent()->getFalseOut());
}

BlockBasic *RuleByteLoop::getNonFallthru(PcodeOp *op)

{
  if (op->getParent() == (BlockBasic *)0) return (BlockBasic *)0;
  if (op->getParent()->sizeOut() == 0) return (BlockBasic *)0;
  if (op->getParent()->sizeOut() == 1)
    return (BlockBasic *)(op->isFallthruTrue() ? op->getParent()->getFalseOut() : 0);
  return (BlockBasic *)(op->isFallthruTrue() ? op->getParent()->getFalseOut() : op->getParent()->getTrueOut());
}

BlockBasic *RuleByteLoop::evaluateBlock(BlockBasic *bl,LoopData &loopData,Funcdata &data)

{
  list<PcodeOp *>::iterator iter;
  for(iter=bl->beginOp();iter!=bl->endOp();++iter) {
    PcodeOp *op = *iter;
    OpCode opc = op->code();
    Varnode *out = op->getOut();
    if (opc == CPUI_CALLOTHER && op->getOpcode()->getOperatorName(op) == Funcdata::insertind) {
      if (!loopData.result.empty()) {
	uintb in3 = loopData.values.getValue(op->getIn(3),false);
	if (loopData.values.dynamicInsert != (PcodeOp *)0) {
	  loopData.result[in3] = loopData.values.dynamicInsert;
	  loopData.values.dynamicInsert = (PcodeOp *)0;
	  continue;
	}
	else if (loopData.values.contains(op->getIn(2))) {
	  Varnode *newVn = data.newConstant(loopData.multiplier,loopData.values.getValue(op->getIn(2),false));
	  PcodeOp *newOp = data.newOp(1,loopData.endOp->getAddr());
	  data.newUniqueOut(loopData.multiplier,newOp);
	  data.opSetOpcode(newOp,CPUI_COPY);
	  data.opSetInput(newOp,newVn,0);
	  loopData.result[in3] = newOp;
	  continue;
	}
      }
    }
    if (out != (Varnode *)0 && out->getSize() > sizeof(uintb)) continue;
    string nm;
    switch (opc) {
      case CPUI_COPY:
      {
	if (!loopData.values.contains(op->getIn(0))) return (BlockBasic *)0;
	if (out == (Varnode *)0) return (BlockBasic *)0;
	uintb in0 = loopData.values.getValue(op->getIn(0),false);
	uintb res = in0;
	loopData.values.putValue(out,res);
	break;
      }
      case CPUI_BRANCH:
	if (bl->sizeOut() != 1) return (BlockBasic *)0;
	return (BlockBasic *)bl->getFalseOut();
	break;
      case CPUI_CBRANCH:
      {
	if (bl->sizeOut() != 2) return (BlockBasic *)0;
	if (!loopData.values.contains(op->getIn(1))) return (BlockBasic *)0;
	uintb in1 = loopData.values.getValue(op->getIn(1),false);
	if (in1 != 0) return (BlockBasic *)bl->getOut(1);
	return (BlockBasic *)bl->getOut(0);
      }
      case CPUI_CALLOTHER:
      {
	nm = op->getOpcode()->getOperatorName(op);
	if (nm == Funcdata::extractind) {
	  if (!loopData.values.contains(op->getIn(2))) return (BlockBasic *)0;
	  if (out == (Varnode *)0) continue;
	  uintb in2 = loopData.values.getValue(op->getIn(2),false);
	  if (out->getSize() > sizeof(uintb)) continue;
	  if (loopData.cachereadonly&&op->getIn(1)->isReadOnly()) {
	    if (op->getIn(1)->getAddr().isBigEndian()) {
	      in2 = op->getIn(1)->getSize() - out->getSize() - in2;
	    }
	    MemoryImage mem(op->getIn(1)->getSpace(),4,16,data.getArch()->loader);
	    uintb res = mem.getValue(op->getIn(1)->getOffset() + in2,op->getOut()->getSize());
	    loopData.values.putValue(out,res);
	  }
	  else if (loopData.largevalues.contains(op->getIn(1))) {
	    uintb res = loopData.largevalues.getValue(op->getIn(1),in2,out->getSize());
	    loopData.values.putValue(out,res);
	  }
	  else if (op->getOut()->loneDescend() != (PcodeOp *)0) {
	    PcodeOp *insertOp = out->loneDescend();
	    insertOp = out->loneDescend();
	    while (insertOp != (PcodeOp *) 0 && insertOp->code() == CPUI_MULTIEQUAL) {
	      insertOp = insertOp->getOut()->loneDescend();
	    }
	    if (insertOp != loopData.insertlist[0]) continue;
	    if (!loopData.result.empty()) {
	      PcodeOp *newOp = data.newOp(2,loopData.endOp->getAddr());
	      data.opSetOpcode(newOp,CPUI_SUBPIECE);
	      Varnode *input = op->getIn(1);
	      data.opSetInput(newOp,input,0);
	      input = data.newConstant(op->getIn(2)->getSize(),in2);
	      data.opSetInput(newOp,input,1);
	      data.newUniqueOut(loopData.multiplier,newOp);
	      loopData.values.dynamicInsert = newOp;
	    }
	  }
	}
	break;
      }
      case CPUI_INT_EQUAL:
      {
	if (!loopData.values.contains(op->getIn(0))) return (BlockBasic *)0;
	if (!loopData.values.contains(op->getIn(1))) return (BlockBasic *)0;
	if (out == (Varnode *)0) return (BlockBasic *)0;
	uintb in0 = loopData.values.getValue(op->getIn(0),false);
	uintb in1 = loopData.values.getValue(op->getIn(1),false);
	uintb res = (in0 == in1) ? 1 : 0;
	loopData.values.putValue(out,res);
	break;
      }
      case CPUI_INT_NOTEQUAL:
      {
	if (!loopData.values.contains(op->getIn(0))) return (BlockBasic *)0;
	if (!loopData.values.contains(op->getIn(1))) return (BlockBasic *)0;
	if (out == (Varnode *)0) return (BlockBasic *)0;
	uintb in0 = loopData.values.getValue(op->getIn(0),false);
	uintb in1 = loopData.values.getValue(op->getIn(1),false);
	uintb res = (in0 != in1) ? 1 : 0;
	loopData.values.putValue(out,res);
	break;
      }
      case CPUI_INT_SLESS:
      {
	if (!loopData.values.contains(op->getIn(0))) return (BlockBasic *)0;
	if (!loopData.values.contains(op->getIn(1))) return (BlockBasic *)0;
	if (out == (Varnode *)0) return (BlockBasic *)0;
	intb in0 = loopData.values.getValue(op->getIn(0),true);
	intb in1 = loopData.values.getValue(op->getIn(1),true);
	uintb res = (in0 < in1) ? 1 : 0;
	loopData.values.putValue(out,res);
	break;
      }
      case CPUI_INT_SLESSEQUAL:
      {
	if (!loopData.values.contains(op->getIn(0))) return (BlockBasic *)0;
	if (!loopData.values.contains(op->getIn(1))) return (BlockBasic *)0;
	if (out == (Varnode *)0) return (BlockBasic *)0;
	intb in0 = loopData.values.getValue(op->getIn(0),true);
	intb in1 = loopData.values.getValue(op->getIn(1),true);
	uintb res = (in0 <= in1) ? 1 : 0;
	loopData.values.putValue(out,res);
	break;
      }
      case CPUI_INT_LESS:
      {
	if (!loopData.values.contains(op->getIn(0))) return (BlockBasic *)0;
	if (!loopData.values.contains(op->getIn(1))) return (BlockBasic *)0;
	if (out == (Varnode *)0) return (BlockBasic *)0;
	uintb in0 = loopData.values.getValue(op->getIn(0),false);
	uintb in1 = loopData.values.getValue(op->getIn(1),false);
	uintb res = (in0 < in1) ? 1 : 0;
	loopData.values.putValue(out,res);
	break;
      }
      case CPUI_INT_ADD:
      {
	if (!loopData.values.contains(op->getIn(0))) return (BlockBasic *)0;
	if (!loopData.values.contains(op->getIn(1))) return (BlockBasic *)0;
	if (out == (Varnode *)0) return (BlockBasic *)0;
	uintb in0 = loopData.values.getValue(op->getIn(0),false);
	uintb in1 = loopData.values.getValue(op->getIn(1),false);
	uintb res = in0 + in1;
	loopData.values.putValue(out,res);
	break;
      }
      case CPUI_INT_AND:
      {
	if (!loopData.values.contains(op->getIn(0))) return (BlockBasic *)0;
	if (!loopData.values.contains(op->getIn(1))) return (BlockBasic *)0;
	if (out == (Varnode *)0) return (BlockBasic *)0;
	uintb in0 = loopData.values.getValue(op->getIn(0),false);
	uintb in1 = loopData.values.getValue(op->getIn(1),false);
	uintb res = in0 & in1;
	loopData.values.putValue(out,res);
	break;
      }
      case CPUI_INT_RIGHT:
      {
	if (!loopData.values.contains(op->getIn(0))) return (BlockBasic *)0;
	if (!loopData.values.contains(op->getIn(1))) return (BlockBasic *)0;
	if (out == (Varnode *)0) return (BlockBasic *)0;
	uintb in0 = loopData.values.getValue(op->getIn(0),false);
	uintb in1 = loopData.values.getValue(op->getIn(1),false);
	uintb res = 0;
	if (in1 >= 8*out->getSize()) {
	  res = in0 < 0 ? calc_mask(out->getSize()) : 0;
	}
	else {
	  res = in0 >> in1;
	}
	loopData.values.putValue(out,res);
	break;
      }
      case CPUI_INT_SRIGHT:
      {
	if (!loopData.values.contains(op->getIn(0))) return (BlockBasic *)0;
	if (!loopData.values.contains(op->getIn(1))) return (BlockBasic *)0;
	if (out == (Varnode *)0) return (BlockBasic *)0;
	intb in0 = loopData.values.getValue(op->getIn(0),true);
	intb in1 = loopData.values.getValue(op->getIn(1),true);
	uintb off = loopData.values.getValue(op->getIn(1),false);
	intb res = 0;
	if (off >= 8*out->getSize()) {
	  res = in0 < 0 ? calc_mask(out->getSize()) : 0;
	}
	else {
	  res = in0 >> in1;
	}
	loopData.values.putValue(out,res);
	break;
      }
      case CPUI_INT_MULT:
      {
	if (!loopData.values.contains(op->getIn(0))) return (BlockBasic *)0;
	if (!loopData.values.contains(op->getIn(1))) return (BlockBasic *)0;
	if (out == (Varnode *)0) return (BlockBasic *)0;
	uintb in0 = loopData.values.getValue(op->getIn(0),false);
	uintb in1 = loopData.values.getValue(op->getIn(1),false);
	uintb res = in0 * in1;
	loopData.values.putValue(out,res);
	break;
      }
      case CPUI_MULTIEQUAL:
	break;
      default:
	break;
    }
  }
  return getFallthru(bl->lastOp());
}

/// \class RuleByteLoop
/// \brief Simplify loop with insertind
///
/// loop with insertind and various operations may be converted just to consecutive pieces if control register gets replaced with constants
void RuleByteLoop::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_CBRANCH);
}

int4 RuleByteLoop::applyOp(PcodeOp *op,Funcdata &data)

{
  PcodeOp *branchOp = op;
  FlowBlock *condBlock = branchOp->getParent();
  if (!condBlock->hasLoopIn()) return 0;

  // Initialize loop data
  LoopData loopData;
  loopData.cachereadonly = data.getArch()->readonlypropagate;
  loopData.condOp = branchOp->getIn(1)->getDef();
  loopData.endOp = branchOp->getIn(1)->getDef();

  if (!setCountsCountervn(loopData)) return 0;
  if (!setInitOp(loopData)) return 0;
  if (!initExtractInsertListsMultiplier(loopData)) return 0;
  collectLargeVarnodeValues(loopData);

  loopData.values.putValue(loopData.counterVn,0);
  BlockBasic *curbl = (BlockBasic *)condBlock;
  BlockBasic *endbl = getNonFallthru(branchOp);
  loopData.endOp = *(endbl->beginOp());
  while (curbl != endbl) {
    if (curbl == (BlockBasic *)0)
      return 0;
    curbl = evaluateBlock(curbl,loopData,data); // This just validates code without changes
  }

  for (int4 i=0;i<loopData.counts;++i) {
    loopData.result.push_back((PcodeOp *)0);
  }

  loopData.values.putValue(loopData.counterVn,0);
  curbl = (BlockBasic *)condBlock;
  while (curbl != endbl) {
    curbl = evaluateBlock(curbl,loopData,data);
  }

  Varnode *objinitval = loopData.insertlist[0]->getIn(1);
  while (objinitval->getDef()->code() == CPUI_MULTIEQUAL) {
    objinitval = objinitval->getDef()->getIn(0);
  }

  // Prepare results
  PcodeOp *curop = (PcodeOp *)0;
  for (int4 i=0;i<loopData.counts;++i) {
    curop = loopData.result[i];
    if (curop == (PcodeOp *) 0) {
      curop = data.newOp(2,loopData.endOp->getAddr()); // create subpiece of itself at this index
      data.opSetOpcode(curop,CPUI_SUBPIECE);
      data.opSetInput(curop,objinitval,0);
      int4 indexsz = loopData.insertlist[0]->getIn(3)->getSize(); // use index size from insertind
      Varnode *input = data.newConstant(indexsz,loopData.multiplier*i);
      data.opSetInput(curop,input,1);
      data.newUniqueOut(loopData.multiplier,curop);
      loopData.result[i] = curop; // and put in result instead of null
    }
    data.opInsertBefore(curop,loopData.endOp);
  }

  // Link results into piece op
  AddrSpace *space = data.getArch()->getDefaultDataSpace();
  PcodeOp *prevop = (PcodeOp *)0;
  for (int4 i = 0; i < loopData.result.size(); ++i) {
    curop = loopData.result[i];
    if (curop == (PcodeOp *) 0) continue;
    if (prevop == (PcodeOp *) 0) {
      prevop = curop;
      continue;
    }
    PcodeOp *newop = data.newOp(2,loopData.endOp->getAddr());
    data.opSetOpcode(newop,CPUI_PIECE);
    Varnode *input0 = curop->getOut();
    data.opSetInput(newop,input0,0);
    Varnode *input1 = prevop->getOut();
    data.opSetInput(newop,input1,1);
    data.newUniqueOut(input0->getSize()+input1->getSize(),newop);
    data.opInsertBefore(newop,loopData.endOp);
    prevop = newop;
  }
  if (prevop == (PcodeOp *)0) return 0;

  // Commit final piece op
  curop = loopData.insertlist[0]->getOut()->loneDescend();
  data.opSetInput(curop,prevop->getOut(),0);
  data.opSetInput(curop,prevop->getOut(),1);
  data.opDestroy(loopData.insertlist[0]);
  return 1;
}

void RuleSpacebaseAdd::getOpList(vector<uint4> &oplist) const

{
  oplist.push_back(CPUI_INT_ADD);
}

int4 RuleSpacebaseAdd::applyOp(PcodeOp *op,Funcdata &data)

{
  Varnode *in0 = op->getIn(0);
  Varnode *in1 = op->getIn(1);
  if (!in0->isSpacebase()) return 0;
  if (!in1->isConstant()) return 0;

  TypePointer *ptype = (TypePointer *)in0->getType();
  if (ptype->getMetatype() != TYPE_PTR) return 0;
  TypeSpacebase *sb = (TypeSpacebase *)ptype->getPtrTo();
  if (sb->getMetatype() != TYPE_SPACEBASE) return 0;

  Scope *scope = sb->getMap();
  Address addr = sb->getAddress(in1->getOffset(),in0->getSize(),op->getAddr());
  if (addr.isInvalid()) return 0;
  SymbolEntry *entry = scope->queryContainer(addr,1,Address());
  // Absence of user-defined entry means it will be created there automatically
  if (entry == (SymbolEntry *)0) {
    // Treat this as if located directly at this place
    data.opSetOpcode(op,CPUI_PTRSUB);
    return 1;
  }
  int4 off = (int4)(addr.getOffset()-entry->getAddr().getOffset())+entry->getOffset();

  if (off == 0) {
    data.opSetOpcode(op,CPUI_PTRSUB);
    return 1;
  }

  Varnode *cvn = data.newConstant(in0->getSize(),in1->getOffset()-off);
  PcodeOp *newop = data.newOpBefore(op,CPUI_PTRSUB,in0,cvn);
  cvn = data.newConstant(in0->getSize(),off);
  data.opSetInput(op,newop->getOut(),0);
  data.opSetInput(op,cvn,1);
  return 1;
}

} // End namespace ghidra
