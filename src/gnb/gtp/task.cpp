//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "task.hpp"

#include <gnb/gtp/proto.hpp>
#include <gnb/rls/task.hpp>
#include <utils/constants.hpp>
#include <utils/libc_error.hpp>
#include <iostream>
#include <arpa/inet.h> 
#include <linux/ip.h>  
#include <optional> 
#include <cstdint>
#include <linux/types.h>   
#include <netinet/tcp.h>
#include <asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h>

namespace nr::gnb
{

GtpTask::GtpTask(TaskBase *base)
    : m_base{base}, m_udpServer{}, m_ueContexts{}, m_rateLimiter(std::make_unique<RateLimiter>()), m_pduSessions{},
      m_sessionTree{}
{
    m_logger = m_base->logBase->makeUniqueLogger("gtp");
}

void GtpTask::onStart()
{
    try
    {
        m_udpServer = new udp::UdpServerTask(m_base->config->gtpIp, cons::GtpPort, this);
        m_udpServer->start();
    }
    catch (const LibError &e)
    {
        m_logger->err("GTP/UDP task could not be created. %s", e.what());
    }
}

void GtpTask::onQuit()
{
    m_udpServer->quit();
    delete m_udpServer;

    m_ueContexts.clear();
}

void GtpTask::onLoop()
{
    auto msg = take();
    if (!msg)
        return;

    switch (msg->msgType)
    {
    case NtsMessageType::GNB_NGAP_TO_GTP: {
        auto &w = dynamic_cast<NmGnbNgapToGtp &>(*msg);
        switch (w.present)
        {
        case NmGnbNgapToGtp::UE_CONTEXT_UPDATE: {
            handleUeContextUpdate(*w.update);
            break;
        }
        case NmGnbNgapToGtp::UE_CONTEXT_RELEASE: {
            handleUeContextDelete(w.ueId);
            break;
        }
        case NmGnbNgapToGtp::SESSION_CREATE: {
            handleSessionCreate(w.resource);
            break;
        }
        case NmGnbNgapToGtp::SESSION_RELEASE: {
            handleSessionRelease(w.ueId, w.psi);
            break;
        }
        }
        break;
    }
    case NtsMessageType::GNB_RLS_TO_GTP: {
        auto &w = dynamic_cast<NmGnbRlsToGtp &>(*msg);
        switch (w.present)
        {
        case NmGnbRlsToGtp::DATA_PDU_DELIVERY: {
            handleUplinkData(w.ueId, w.psi, std::move(w.pdu));
            break;
        }
        }
        break;
    }
    case NtsMessageType::UDP_SERVER_RECEIVE:
        handleUdpReceive(dynamic_cast<udp::NwUdpServerReceive &>(*msg));
        break;
    default:
        m_logger->unhandledNts(*msg);
        break;
    }
}

void GtpTask::handleUeContextUpdate(const GtpUeContextUpdate &msg)
{
    if (!m_ueContexts.count(msg.ueId))
        m_ueContexts[msg.ueId] = std::make_unique<GtpUeContext>(msg.ueId);

    auto &ue = m_ueContexts[msg.ueId];
    ue->ueAmbr = msg.ueAmbr;

    updateAmbrForUe(ue->ueId);
}

void GtpTask::handleSessionCreate(PduSessionResource *session)
{
    if (!m_ueContexts.count(session->ueId))
    {
        m_logger->err("PDU session resource could not be created, UE context with ID[%d] not found", session->ueId);
        return;
    }

    uint64_t sessionInd = MakeSessionResInd(session->ueId, session->psi);
    m_pduSessions[sessionInd] = std::unique_ptr<PduSessionResource>(session);

    m_sessionTree.insert(sessionInd, session->downTunnel.teid);

    updateAmbrForUe(session->ueId);
    updateAmbrForSession(sessionInd);
}

void GtpTask::handleSessionRelease(int ueId, int psi)
{
    if (!m_ueContexts.count(ueId))
    {
        m_logger->err("PDU session resource could not be released, UE context with ID[%d] not found", ueId);
        return;
    }

    uint64_t sessionInd = MakeSessionResInd(ueId, psi);

    // Remove all session information from rate limiter
    m_rateLimiter->updateSessionUplinkLimit(sessionInd, 0);
    m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

    // And remove from PDU session table
    if (m_pduSessions.count(sessionInd))
    {
        uint32_t teid = m_pduSessions[sessionInd]->downTunnel.teid;
        m_pduSessions.erase(sessionInd);

        // And remove from the tree
        m_sessionTree.remove(sessionInd, teid);
    }
}

void GtpTask::handleUeContextDelete(int ueId)
{
    // Find PDU sessions of the UE
    std::vector<uint64_t> sessions{};
    m_sessionTree.enumerateByUe(ueId, sessions);

    for (auto &session : sessions)
    {
        // Remove all session information from rate limiter
        m_rateLimiter->updateSessionUplinkLimit(session, 0);
        m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

        // And remove from PDU session table
        uint32_t teid = m_pduSessions[session]->downTunnel.teid;
        m_pduSessions.erase(session);

        // And remove from the tree
        m_sessionTree.remove(session, teid);
    }

    // Remove all user information from rate limiter
    m_rateLimiter->updateUeUplinkLimit(ueId, 0);
    m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

    // Remove UE context
    m_ueContexts.erase(ueId);
}

void GtpTask::extract_inner_ip_header(const uint8_t *data, __be32 *inner_src_ip, __be32 *inner_dst_ip) {
    const struct iphdr *inner_iph = reinterpret_cast<const struct iphdr *>(data);

    *inner_src_ip = inner_iph->saddr;
    *inner_dst_ip = inner_iph->daddr;
}

bool GtpTask::uplink(const char *ip) {
    return strncmp(ip, "10.60.0.", 8) == 0 || strncmp(ip, "10.61.0.", 8) == 0;
}

bool nr::gnb::GtpTask::	toBeMonitored(const char *src_ip, const char *dst_ip) {
    if ((uplink(src_ip) && strcmp(dst_ip, "10.100.200.2") == 0) || (uplink(src_ip) && strcmp(dst_ip, "10.100.200.3") == 0)) {
        return true;
    }
    return false;
}

uint8_t GtpTask::determine_qfi(const char *src_ip, const char *dst_ip) {
    if (uplink(src_ip) && strcmp(dst_ip, "10.100.200.2") == 0) {
        return 1;
    } else if (uplink(src_ip) && strcmp(dst_ip, "10.100.200.3") == 0){
        return 2;
    } else {
        return 0;
    }
}

std::optional<uint32_t> GtpTask::extractUlDelayResult(const uint8_t *data)
{
    const struct iphdr *ip_header = reinterpret_cast<const struct iphdr *>(data);
    size_t ip_header_len = ip_header->ihl * 4;

    const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr*>(data + ip_header_len);
    size_t tcp_header_len = tcp_header->doff * 4;

    const uint8_t *integer_location = data + ip_header_len + tcp_header_len;

    uint32_t appended_integer = *reinterpret_cast<const uint32_t*>(integer_location);
    return ntohl(appended_integer); 
}
void GtpTask::handleUplinkData(int ueId, int psi, OctetString &&pdu)
{
    uint32_t myInteger = 3;
    std::optional<uint32_t> optionalInteger = myInteger;
    const uint8_t *data = pdu.data();
    

    // ignore non IPv4 packets
    if ((data[0] >> 4 & 0xF) != 4)
        return;

    // Extract the source and destination IP addresses
    __be32 src_ip, dst_ip;
    extract_inner_ip_header(data, &src_ip, &dst_ip);

    char srcIpStr[INET_ADDRSTRLEN];
    char dstIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_ip, srcIpStr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_ip, dstIpStr, INET_ADDRSTRLEN);

    uint8_t qfi_to_mark = determine_qfi(srcIpStr, dstIpStr);


    uint64_t sessionInd = MakeSessionResInd(ueId, psi);

    if (!m_pduSessions.count(sessionInd))
    {
        m_logger->err("Uplink data failure, PDU session not found. UE[%d] PSI[%d]", ueId, psi);
        return;
    }
    auto &pduSession = m_pduSessions[sessionInd];

    if (m_rateLimiter->allowUplinkPacket(sessionInd, static_cast<int64_t>(pdu.length())))
    {
        gtp::GtpMessage gtp{};
        gtp.payload = std::move(pdu);
        gtp.msgType = gtp::GtpMessage::MT_G_PDU;
        gtp.teid = pduSession->upTunnel.teid;

        auto ul = std::make_unique<gtp::UlPduSessionInformation>();
        // TODO: currently using first QSI
        if (toBeMonitored(srcIpStr, dstIpStr)){
            ul->qmp = true;
            ul->qfi = qfi_to_mark;
            ul->ulDelayResult = myInteger;
            // auto aresult = extractUlDelayResult(data);
            // if (aresult.has_value()) {
            //     int appended_integer = aresult.value_or(0); 
            //     ul->ulDelayResult = appended_integer;
            // }
        }
        //ul->qfi = static_cast<int>(pduSession->qosFlows->list.array[0]->qosFlowIdentifier);

        auto cont = std::make_unique<gtp::PduSessionContainerExtHeader>();
        cont->pduSessionInformation = std::move(ul);
        gtp.extHeaders.push_back(std::move(cont));

        OctetString gtpPdu;
        if (!gtp::EncodeGtpMessage(gtp, gtpPdu))
            m_logger->err("Uplink data failure, GTP encoding failed");
        else
            m_udpServer->send(InetAddress(pduSession->upTunnel.address, cons::GtpPort), gtpPdu);
    }
}

void GtpTask::handleUdpReceive(const udp::NwUdpServerReceive &msg)
{
    OctetView buffer{msg.packet};
    auto gtp = gtp::DecodeGtpMessage(buffer);

    switch (gtp->msgType)
    {
    case gtp::GtpMessage::MT_G_PDU: {
        auto sessionInd = m_sessionTree.findByDownTeid(gtp->teid);
        if (sessionInd == 0)
        {
            m_logger->err("TEID %d not found on GTP-U Downlink", gtp->teid);
            return;
        }

        if (m_rateLimiter->allowDownlinkPacket(sessionInd, gtp->payload.length()))
        {
            auto w = std::make_unique<NmGnbGtpToRls>(NmGnbGtpToRls::DATA_PDU_DELIVERY);
            w->ueId = GetUeId(sessionInd);
            w->psi = GetPsi(sessionInd);
            w->pdu = std::move(gtp->payload);
            m_base->rlsTask->push(std::move(w));
        }
        return;
    }
    case gtp::GtpMessage::MT_ECHO_REQUEST: {
        gtp::GtpMessage gtpResponse{};
        gtpResponse.msgType = gtp::GtpMessage::MT_ECHO_RESPONSE;
        gtpResponse.seq = gtp->seq;
        gtpResponse.payload = OctetString::FromOctet2({14, 0});

        OctetString gtpPdu;
        if (gtp::EncodeGtpMessage(gtpResponse, gtpPdu))
            m_udpServer->send(msg.fromAddress, gtpPdu);
        else
            m_logger->err("Uplink data failure, GTP encoding failed");
        return;
    }
    default: {
        m_logger->err("Unhandled GTP-U message type: %d", gtp->msgType);
        return;
    }
    }
}

void GtpTask::updateAmbrForUe(int ueId)
{
    if (!m_ueContexts.count(ueId))
        return;

    auto &ue = m_ueContexts[ueId];
    m_rateLimiter->updateUeUplinkLimit(ueId, ue->ueAmbr.ulAmbr);
    m_rateLimiter->updateUeDownlinkLimit(ueId, ue->ueAmbr.dlAmbr);
}

void GtpTask::updateAmbrForSession(uint64_t pduSession)
{
    if (!m_pduSessions.count(pduSession))
        return;

    auto &sess = m_pduSessions[pduSession];
    m_rateLimiter->updateSessionUplinkLimit(pduSession, sess->sessionAmbr.ulAmbr);
    m_rateLimiter->updateSessionDownlinkLimit(pduSession, sess->sessionAmbr.dlAmbr);
}

} // namespace nr::gnb