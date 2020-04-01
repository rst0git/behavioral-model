#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/target_parser.h>

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
  mtpsa_switch_parser->add_flag_option("enable-swap", "enable JSON swapping at runtime");

  int status = mtpsa_switch->init_from_command_line_options(argc, argv, mtpsa_switch_parser);
  if (status != 0)
    std::exit(status);

  {
    bool enable_swap_flag = false;
    auto ret = mtpsa_switch_parser->get_flag_option("enable-swap", &enable_swap_flag);
    if (ret != bm::TargetParserBasic::ReturnCode::SUCCESS)
      std::exit(1);
    if (enable_swap_flag)
      mtpsa_switch->enable_config_swap();
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
