/* Copyright 2019-present Derek So
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Derek So (dts76@cornell.edu)
 *
 */

#include "mtpsa_counter.h"

namespace bm {

namespace mtpsa {

void
MTPSA_Counter::count(const Data &index) {
  const Packet &packet = get_packet();
  const PHV *phv = packet.get_phv();
  const unsigned permissions = phv->get_packet_permissions();
  if (!(permissions & MTPSA_PERM_COUNTER))
    _counter->get_counter(index.get<size_t>()).increment_counter(packet);
}

Counter &
MTPSA_Counter::get_counter(size_t idx) {
  return _counter->get_counter(idx);
}

const Counter &
MTPSA_Counter::get_counter(size_t idx) const {
  return _counter->get_counter(idx);
}

Counter::CounterErrorCode
MTPSA_Counter::reset_counters(){
  return _counter->reset_counters();
}

BM_REGISTER_EXTERN_W_NAME(Counter, MTPSA_Counter);
BM_REGISTER_EXTERN_W_NAME_METHOD(Counter, MTPSA_Counter, count, const Data &);

}  // namespace bm::mtpsa

}  // namespace bm

int import_counters(){
  return 0;
}
