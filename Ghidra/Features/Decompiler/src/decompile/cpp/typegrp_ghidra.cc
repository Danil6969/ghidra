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
#include "typegrp_ghidra.hh"

namespace ghidra {

Datatype *TypeFactoryGhidra::findById(const string &n,uint8 id,int4 sz)

{
  Datatype *ct = TypeFactory::findById(n,id,sz); // Try internal find
  if (ct != (Datatype *)0) return ct;
  ArchitectureGhidra *ghidra = (ArchitectureGhidra *)glb;
  PackedDecode decoder(ghidra);
  try {
    if (!ghidra->getDataType(n,id,decoder)) // See if ghidra knows about type
      return (Datatype *)0;
  }
  catch(DecoderError &err) {
    throw LowlevelError("Decoder error: "+err.explain);
  }
  ct = decodeType(decoder); // Parse ghidra's type
  return ct;
}

vector<Datatype *> TypeFactoryGhidra::findAll(const string &n)
{
  vector<Datatype *> datatypes;
  ArchitectureGhidra *ghidra = (ArchitectureGhidra *)glb;
  PackedDecode decoder(ghidra);
  try {
    if (!ghidra->getAllDataTypes(n,decoder)) // See if ghidra knows about type
      return datatypes;
    uint4 elemId = decoder.openElement(ELEM_INTEGER_SIZE);
    intb size = decoder.readSignedInteger();
    decoder.closeElement(elemId);
    for (int4 i=0;i<size;++i) {
      Datatype *ct = decodeType(decoder); // Parse ghidra's type
      datatypes.push_back(ct);
    }
  }
  catch(DecoderError &err) {
    throw LowlevelError("Decoder error: "+err.explain);
  }
  return datatypes;
}

} // End namespace ghidra
