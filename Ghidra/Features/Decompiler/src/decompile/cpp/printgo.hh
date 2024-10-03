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
/// \file printjava.hh
/// \brief Classes supporting the java-language back-end to the decompiler

#ifndef __PRINTJAVA_HH__
#define __PRINTJAVA_HH__

#include "printc.hh"

namespace ghidra {

/// \brief Factory and static initializer for the "go-language" back-end to the decompiler
///
/// The singleton adds itself to the list of possible back-end languages for the decompiler
/// and it acts as a factory for producing the PrintGo object for emitting go-language tokens.
class PrintGoCapability : public PrintLanguageCapability {
  static PrintGoCapability printGoCapability;		///< The singleton instance
  PrintGoCapability(void);					///< Singleton constructor
  PrintGoCapability(const PrintGoCapability &op2);		///< Not implemented
  PrintGoCapability &operator=(const PrintGoCapability &op);	///< Not implemented
public:
  virtual PrintLanguage *buildLanguage(Architecture *glb);
};

/// \brief The go-language token emitter
///
/// This builds heavily on the c-language PrintC emitter.  Most operator tokens, the format of
/// function prototypes, and code structuring are shared.
class PrintGo : public PrintC {
  void resetDefaultsPrintGo(void);			///< Set options that are specific to Go
public:
  static const string KEYWORD_FALLTHROUGH;	///< "fallthrough" keyword
  PrintGo(Architecture *g,const string &nm="go-language");	///< Constructor
  virtual void resetDefaults(void);
  virtual void docFunction(const Funcdata *fd);
  virtual bool doEmitWideCharPrefix(void) const { return false; }
  virtual void adjustTypeOperators(void);
  virtual bool fallthroughPrints(FlowBlock *bl2);
  virtual void emitBlockSwitch(const BlockSwitch *bl);
};

} // End namespace ghidra
#endif
