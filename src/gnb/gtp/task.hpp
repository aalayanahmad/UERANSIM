//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "utils.hpp"

#include <memory>
#include <thread>
#include <unordered_map>
#include <vector>
#include <linux/types.h> 
#include <gnb/nts.hpp>
#include <lib/udp/server_task.hpp>
#include <utils/logger.hpp>
#include <utils/nts.hpp>


namespace nr::gnb
{

class GtpTask : public NtsTask
{
  private:
    TaskBase *m_base;
    std::unique_ptr<Logger> m_logger;

    udp::UdpServerTask *m_udpServer;
    std::unordered_map<int, std::unique_ptr<GtpUeContext>> m_ueContexts;
    std::unique_ptr<IRateLimiter> m_rateLimiter;
    std::unordered_map<uint64_t, std::unique_ptr<PduSessionResource>> m_pduSessions;
    PduSessionTree m_sessionTree;

    friend class GnbCmdHandler;

  public:
    explicit GtpTask(TaskBase *base);
    ~GtpTask() override = default;

  protected:
    void onStart() override;
    void onLoop() override;
    void onQuit() override;

  private:
    void handleUdpReceive(const udp::NwUdpServerReceive &msg);
    void handleUeContextUpdate(const GtpUeContextUpdate &msg);
    void handleSessionCreate(PduSessionResource *session);
    void handleSessionRelease(int ueId, int psi);
    void handleUeContextDelete(int ueId);
    void handleUplinkData(int ueId, int psi, OctetString &&data);

    void updateAmbrForUe(int ueId);
    void updateAmbrForSession(uint64_t pduSession);

   
    void extract_inner_ip_header(const uint8_t *data, __be32 *inner_src_ip, __be32 *inner_dst_ip);
    bool packets_to_be_monitored(const char *src_ip, const char *dst_ip);
    uint8_t set_qfi(const char *src_ip, const char *dst_ip);
    std::optional<uint32_t> extract_ul_delay(const uint8_t *data, int64_t data_length);
};

} // namespace nr::gnb
