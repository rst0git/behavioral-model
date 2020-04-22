#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/target_parser.h>

#include <iostream>

#include "bm/MtPsaSwitch.h"
#include "mtpsa_switch.h"

namespace {
  bm::mtpsa::MtPsaSwitch *mtpsa_switch;
  bm::TargetParserBasic *mtpsa_switch_parser;
}  // namespace

namespace mtpswitch_runtime {
  shared_ptr<MtPsaSwitchIf> get_handler(bm::mtpsa::MtPsaSwitch *sw);
}  // namespace mtpswitch_runtime

int main(int argc, char* argv[])
{
  mtpsa_switch = new bm::mtpsa::MtPsaSwitch();
  mtpsa_switch_parser = new bm::TargetParserBasic();
  mtpsa_switch_parser->add_string_option("user01", "User 1 config file");
  mtpsa_switch_parser->add_string_option("user02", "User 2 config file");
  mtpsa_switch_parser->add_string_option("user03", "User 3 config file");
  mtpsa_switch_parser->add_string_option("user04", "User 4 config file");

  int status = mtpsa_switch->init_from_command_line_options(argc, argv, mtpsa_switch_parser);
  if (status != 0)
    std::exit(status);

  for (int i=1; i<=4; i++) {
    std::string user_config;
    auto ret = mtpsa_switch_parser->get_string_option("user0" + std::to_string(i), &user_config);
    if (ret != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
    if (user_config.length() > 0)
      mtpsa_switch->load_user_config(i, user_config);
  }

  int thrift_port = mtpsa_switch->get_runtime_port();

  bm_runtime::start_server(mtpsa_switch, thrift_port);

  bm_runtime::add_service<
    mtpswitch_runtime::MtPsaSwitchIf,
    mtpswitch_runtime::MtPsaSwitchProcessor
  >(
    "mtpsa_switch",
    mtpswitch_runtime::get_handler(mtpsa_switch)
  );

  mtpsa_switch->start_and_return();

  while (true)
    std::this_thread::sleep_for(std::chrono::seconds(100));

  return 0;
}
