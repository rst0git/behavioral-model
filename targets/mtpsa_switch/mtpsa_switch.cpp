/* Copyright 2013-present Barefoot Networks, Inc.
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
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>

#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>

#include "mtpsa_switch.h"

namespace {

struct hash_ex {
  uint32_t operator()(const char *buf, size_t s) const {
    const uint32_t p = 16777619;
    uint32_t hash = 2166136261;

    for (size_t i = 0; i < s; i++)
      hash = (hash ^ buf[i]) * p;

    hash += hash << 13;
    hash ^= hash >> 7;
    hash += hash << 3;
    hash ^= hash >> 17;
    hash += hash << 5;
    return static_cast<uint32_t>(hash);
  }
};

struct bmv2_hash {
  uint64_t operator()(const char *buf, size_t s) const {
    return bm::hash::xxh64(buf, s);
  }
};

}  // namespace

REGISTER_HASH(hash_ex);
REGISTER_HASH(bmv2_hash);

extern int import_primitives();
extern int import_counters();

namespace bm {

namespace mtpsa {

packet_id_t MtPsaSwitch::packet_id = 0;

MtPsaSwitch::MtPsaSwitch(bool enable_swap)
  : Switch(enable_swap),
    input_buffer(1024),
    egress_buffers(nb_user_threads, 64, EgressThreadMapper(nb_user_threads)),
    output_buffer(128),
    my_transmit_fn([this](port_t port_num, packet_id_t pkt_id, const char *buffer, int len) {
        _BM_UNUSED(pkt_id);
        this->transmit_fn(port_num, buffer, len);
    }),
    pre(new McSimplePreLAG()),
    start(clock::now()) {
  add_component<McSimplePreLAG>(pre);

  add_required_field("psa_ingress_parser_input_metadata", "ingress_port");
  add_required_field("psa_ingress_parser_input_metadata", "packet_path");

  add_required_field("psa_ingress_input_metadata", "ingress_port");
  add_required_field("psa_ingress_input_metadata", "packet_path");
  add_required_field("psa_ingress_input_metadata", "ingress_timestamp");
  add_required_field("psa_ingress_input_metadata", "parser_error");

  add_required_field("psa_ingress_output_metadata", "class_of_service");
  add_required_field("psa_ingress_output_metadata", "clone");
  add_required_field("psa_ingress_output_metadata", "clone_session_id");
  add_required_field("psa_ingress_output_metadata", "drop");
  add_required_field("psa_ingress_output_metadata", "resubmit");
  add_required_field("psa_ingress_output_metadata", "multicast_group");
  add_required_field("psa_ingress_output_metadata", "egress_port");

  add_required_field("psa_egress_parser_input_metadata", "egress_port");
  add_required_field("psa_egress_parser_input_metadata", "packet_path");

  add_required_field("psa_egress_input_metadata", "class_of_service");
  add_required_field("psa_egress_input_metadata", "egress_port");
  add_required_field("psa_egress_input_metadata", "packet_path");
  add_required_field("psa_egress_input_metadata", "instance");
  add_required_field("psa_egress_input_metadata", "egress_timestamp");
  add_required_field("psa_egress_input_metadata", "parser_error");

  add_required_field("psa_egress_output_metadata", "clone");
  add_required_field("psa_egress_output_metadata", "clone_session_id");
  add_required_field("psa_egress_output_metadata", "drop");

  add_required_field("psa_egress_deparser_input_metadata", "egress_port");

  force_arith_header("psa_ingress_parser_input_metadata");
  force_arith_header("psa_ingress_input_metadata");
  force_arith_header("psa_ingress_output_metadata");
  force_arith_header("psa_egress_parser_input_metadata");
  force_arith_header("psa_egress_input_metadata");
  force_arith_header("psa_egress_output_metadata");
  force_arith_header("psa_egress_deparser_input_metadata");

  import_primitives();
  import_counters();
}

#define PACKET_LENGTH_REG_IDX 0

int
MtPsaSwitch::receive_(port_t port_num, const char *buffer, int len) {
  do_swap();

  // Allow up to 512 bytes of additional header data in packet.
  auto packet = new_packet_ptr(port_num, packet_id++, len,
                               bm::PacketBuffer(len + 512, buffer, len));

  BMELOG(packet_in, *packet);
  PHV *phv = packet->get_phv();
  phv->reset_metadata();
  phv->get_field("psa_ingress_parser_input_metadata.packet_path").set(PACKET_PATH_NORMAL);
  phv->get_field("psa_ingress_parser_input_metadata.ingress_port").set(port_num);

  // Store length in register 0
  packet->set_register(PACKET_LENGTH_REG_IDX, len);

  phv->get_field("psa_ingress_input_metadata.ingress_timestamp").set(get_ts().count());

  input_buffer.push_front(std::move(packet));
  return 0;
}

void
MtPsaSwitch::start_and_return_() {
  threads_.push_back(std::thread(&MtPsaSwitch::ingress_thread, this));
  for (size_t i = 0; i < nb_user_threads; i++)
  {
    threads_.push_back(std::thread(&MtPsaSwitch::user_thread, this, i));
  }
  threads_.push_back(std::thread(&MtPsaSwitch::transmit_thread, this));
}

MtPsaSwitch::~MtPsaSwitch() {
  input_buffer.push_front(nullptr);
  for (size_t i = 0; i < nb_user_threads; i++) {
    egress_buffers.push_front(i, nullptr);
  }
  output_buffer.push_front(nullptr);
  for (auto& thread_ : threads_) {
    thread_.join();
  }
}

void
MtPsaSwitch::reset_target_state_() {
  bm::Logger::get()->debug("Resetting mtpsa_switch target-specific state");
  get_component<McSimplePreLAG>()->reset_state();
}

int
MtPsaSwitch::set_egress_queue_depth(size_t port, const size_t depth_pkts) {
  egress_buffers.set_capacity(port, depth_pkts);
  return 0;
}

int
MtPsaSwitch::set_all_egress_queue_depths(const size_t depth_pkts) {
  egress_buffers.set_capacity_for_all(depth_pkts);
  return 0;
}

int
MtPsaSwitch::set_egress_queue_rate(size_t port, const uint64_t rate_pps) {
  egress_buffers.set_rate(port, rate_pps);
  return 0;
}

int
MtPsaSwitch::set_all_egress_queue_rates(const uint64_t rate_pps) {
  egress_buffers.set_rate_for_all(rate_pps);
  return 0;
}

uint64_t
MtPsaSwitch::get_time_elapsed_us() const {
  return get_ts().count();
}

uint64_t
MtPsaSwitch::get_time_since_epoch_us() const {
  auto tp = clock::now();
  return duration_cast<ts_res>(tp.time_since_epoch()).count();
}

void
MtPsaSwitch::set_transmit_fn(TransmitFn fn) 
{
  my_transmit_fn = std::move(fn);
}

void
MtPsaSwitch::transmit_thread() {
  while (1)
  {
    std::unique_ptr<Packet> packet;
    output_buffer.pop_back(&packet);

    if (packet == nullptr) break;
    BMELOG(packet_out, *packet);
    BMLOG_DEBUG_PKT(*packet, "Transmitting packet of size {} out of port {}",
                    packet->get_data_size(), packet->get_egress_port());

    my_transmit_fn(packet->get_egress_port(), packet->get_packet_id(),
                   packet->data(), packet->get_data_size());
  }
}

ts_res
MtPsaSwitch::get_ts() const {
  return duration_cast<ts_res>(clock::now() - start);
}

void
MtPsaSwitch::enqueue(port_t egress_port, std::unique_ptr<Packet> &&packet) {
  packet->set_egress_port(egress_port);
  egress_buffers.push_front(egress_port, std::move(packet));
}

void
MtPsaSwitch::ingress_thread() {
  PHV *phv;

  while (1)
  {
    std::unique_ptr<Packet> packet;
    input_buffer.pop_back(&packet);
    if (packet == nullptr)
      break;

    port_t ingress_port = packet->get_ingress_port();
    BMLOG_DEBUG_PKT(*packet, "Processing packet received on port {}", ingress_port);

    phv = packet->get_phv();

    const Packet::buffer_state_t packet_in_state = packet->save_buffer_state();

    Parser *parser = this->get_parser("ingress_parser");
    parser->parse(packet.get());

    phv->get_field("psa_ingress_input_metadata.ingress_port").set(ingress_port);
    phv->get_field("psa_ingress_input_metadata.packet_path")
      .set(phv->get_field("psa_ingress_parser_input_metadata.packet_path"));
    phv->get_field("psa_ingress_input_metadata.parser_error")
      .set(packet->get_error_code().get());

    phv->get_field("psa_ingress_output_metadata.class_of_service").set(0);
    phv->get_field("psa_ingress_output_metadata.clone").set(0);
    phv->get_field("psa_ingress_output_metadata.drop").set(1);
    phv->get_field("psa_ingress_output_metadata.resubmit").set(0);
    phv->get_field("psa_ingress_output_metadata.multicast_group").set(0);

    Pipeline *ingress_mau = this->get_pipeline("ingress");
    ingress_mau->apply(packet.get());
    packet->reset_exit();
    
    const auto &f_drop = phv->get_field("psa_ingress_output_metadata.drop");
    if (f_drop.get_int())
    {
      BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of ingress");
      continue;
    }

    const auto &f_resubmit = phv->get_field("psa_ingress_output_metadata.resubmit");
    if (f_resubmit.get_int())
    {
      BMLOG_DEBUG_PKT(*packet, "Resubmitting packet");

      packet->restore_buffer_state(packet_in_state);
      phv->reset_metadata();
      phv->get_field("psa_ingress_parser_input_metadata.packet_path").set(PACKET_PATH_RESUBMIT);

      input_buffer.push_front(std::move(packet));
      continue;
    }

    Deparser *deparser = this->get_deparser("ingress_deparser");
    deparser->deparse(packet.get());

    // handling multicast
    unsigned int mgid = 0u;
    const auto &f_mgid = phv->get_field("psa_ingress_output_metadata.multicast_group");
    mgid = f_mgid.get_uint();

    if (mgid != 0)
    {
      BMLOG_DEBUG_PKT(*packet, "Multicast requested for packet with multicast group {}", mgid);
      const auto pre_out = pre->replicate({mgid});
      auto packet_size = packet->get_register(PACKET_LENGTH_REG_IDX);
      for(const auto &out : pre_out){
        auto egress_port = out.egress_port;
        BMLOG_DEBUG_PKT(*packet, "Replicating packet on port {}", egress_port);
        std::unique_ptr<Packet> packet_copy = packet->clone_with_phv_ptr();
        packet_copy->set_register(PACKET_LENGTH_REG_IDX, packet_size);
        enqueue(egress_port, std::move(packet_copy));
      }
      continue;
    }

    const auto &f_egress_port = phv->get_field("psa_ingress_output_metadata.egress_port");
    port_t egress_port = f_egress_port.get_uint();
    BMLOG_DEBUG_PKT(*packet, "Egress port is {}", egress_port);

    enqueue(egress_port, std::move(packet));
  }
}

void MtPsaSwitch::user_thread(size_t user_id) {
  PHV *phv;

  while (1)
  {
    std::unique_ptr<Packet> packet;
    size_t port;

    egress_buffers.pop_back(user_id, &port, &packet);

    if (packet == nullptr)
      break;
    phv = packet->get_phv();
    phv->reset();
    phv->get_field("psa_egress_parser_input_metadata.egress_port").set(port);

    Parser *user_parser = this->get_parser("user_parser");
    user_parser->parse(packet.get());

    phv->get_field("psa_egress_input_metadata.egress_port")
      .set(phv->get_field("psa_egress_parser_input_metadata.egress_port"));
    phv->get_field("psa_egress_input_metadata.egress_timestamp").set(get_ts().count());
    phv->get_field("psa_egress_input_metadata.parser_error").set(packet->get_error_code().get());

    phv->get_field("psa_egress_output_metadata.drop").set(0);

    Pipeline *user_pipeline = this->get_pipeline("user_pipeline");
    user_pipeline->apply(packet.get());
    packet->reset_exit();

    Deparser *user_deparser = this->get_deparser("user_deparser");
    user_deparser->deparse(packet.get());

    output_buffer.push_front(std::move(packet));
  }
}

}  // namespace bm::mtpsa

}  // namespace bm
