#include "IpcCommandRouter.h"

#include "src/ipc/IpcProtocol.h"
#include "src/session/SessionState.h"

#include <cctype>
#include <cstdint>
#include <sstream>
#include <string>
#include <thread>

// -------------------- tiny json helpers --------------------

static std::string JsonUnescape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());

    for (size_t i = 0; i < s.size(); i++)
    {
        char c = s[i];
        if (c != '\\')
        {
            out.push_back(c);
            continue;
        }

        if (i + 1 >= s.size())
            break;

        char n = s[++i];
        switch (n)
        {
        case '\\': out.push_back('\\'); break;
        case '"':  out.push_back('"');  break;
        case 'n':  out.push_back('\n'); break;
        case 'r':  out.push_back('\r'); break;
        case 't':  out.push_back('\t'); break;
        default:   out.push_back(n);    break;
        }
    }

    return out;
}

static bool TryExtractJsonStringField(
    const std::string& json,
    const char* field,
    std::string& outValue)
{
    std::string key = std::string("\"") + field + "\"";
    auto p = json.find(key);
    if (p == std::string::npos) return false;

    p = json.find(':', p);
    if (p == std::string::npos) return false;

    p = json.find('"', p);
    if (p == std::string::npos) return false;

    auto e = p + 1;
    bool escaped = false;
    for (; e < json.size(); e++)
    {
        char c = json[e];
        if (escaped) { escaped = false; continue; }
        if (c == '\\') { escaped = true; continue; }
        if (c == '"') break;
    }
    if (e >= json.size()) return false;

    outValue = json.substr(p + 1, e - (p + 1));
    outValue = JsonUnescape(outValue);
    return true;
}

static bool TryExtractJsonBoolField(
    const std::string& json,
    const char* field,
    bool& outValue)
{
    std::string key = std::string("\"") + field + "\"";
    auto p = json.find(key);
    if (p == std::string::npos) return false;

    p = json.find(':', p);
    if (p == std::string::npos) return false;

    size_t i = p + 1;
    while (i < json.size() && std::isspace((unsigned char)json[i]))
        i++;

    if (json.compare(i, 4, "true") == 0)  { outValue = true;  return true; }
    if (json.compare(i, 5, "false") == 0) { outValue = false; return true; }

    return false;
}

static bool TryExtractJsonUInt16Field(
    const std::string& json,
    const char* field,
    uint16_t& outValue)
{
    std::string key = std::string("\"") + field + "\"";
    auto p = json.find(key);
    if (p == std::string::npos) return false;

    p = json.find(':', p);
    if (p == std::string::npos) return false;

    p++;
    while (p < json.size() && std::isspace((unsigned char)json[p]))
        p++;

    size_t e = p;
    while (e < json.size() && std::isdigit((unsigned char)json[e]))
        e++;

    if (e == p) return false;

    unsigned long v = std::stoul(json.substr(p, e - p));
    if (v > 65535) return false;

    outValue = static_cast<uint16_t>(v);
    return true;
}

// -------------------- status payload --------------------

static std::string BuildStatusPayload(const datagate::session::SessionState& st)
{
    std::ostringstream oss;
    oss << "{\"state\":\"" << datagate::session::ToString(st.phase) << "\"";
    if (!st.lastErrorCode.empty() || !st.lastErrorMessage.empty())
    {
        oss << ",\"error\":{\"code\":\"" << datagate::ipc::JsonEscape(st.lastErrorCode)
            << "\",\"message\":\"" << datagate::ipc::JsonEscape(st.lastErrorMessage) << "\"}";
    }
    oss << "}";
    return oss.str();
}

// -------------------- lifecycle payload --------------------

static std::string BuildLifecyclePayload(const char* phase, const char* reason, bool success)
{
    std::ostringstream oss;
    oss << "{"
        << "\"phase\":\"" << datagate::ipc::JsonEscape(phase) << "\","
        << "\"reason\":\"" << datagate::ipc::JsonEscape(reason) << "\","
        << "\"success\":" << (success ? "true" : "false")
        << "}";
    return oss.str();
}

// -------------------- ctor --------------------

IpcCommandRouter::IpcCommandRouter(datagate::ipc::IpcServer& ipc,
                                   datagate::session::SessionController& session,
                                   SessionOrchestrator& orchestrator,
                                   HANDLE stopEvent)
    : ipc_(ipc)
    , session_(session)
    , orchestrator_(orchestrator)
    , stopEvent_(stopEvent)
{
}

// -------------------- install --------------------

void IpcCommandRouter::Install()
{
    ipc_.SetCommandHandler([this](const datagate::ipc::Command& cmd)
    {
        switch (cmd.type)
        {
        case datagate::ipc::CommandType::StartSession:
        {
            datagate::session::StartOptions opt;

            // Required
            if (!TryExtractJsonStringField(cmd.payloadJson, "ovpnContent", opt.ovpnContentUtf8))
            {
                ipc_.ReplyError(cmd.id, "bad_payload", "Missing ovpnContent");
                return;
            }

            // Bridge fields (payload puts them at the root, not under bridge:{})
            TryExtractJsonStringField(cmd.payloadJson, "host", opt.bridge.host);
            TryExtractJsonStringField(cmd.payloadJson, "port", opt.bridge.port);
            TryExtractJsonStringField(cmd.payloadJson, "path", opt.bridge.path);
            TryExtractJsonStringField(cmd.payloadJson, "sni",  opt.bridge.sni);

            TryExtractJsonStringField(cmd.payloadJson, "listenIp", opt.bridge.listenIp);
            TryExtractJsonUInt16Field(cmd.payloadJson, "listenPort", opt.bridge.listenPort);

            TryExtractJsonBoolField(cmd.payloadJson, "verifyServerCert", opt.bridge.verifyServerCert);
            TryExtractJsonStringField(cmd.payloadJson, "authorizationHeader", opt.bridge.authorizationHeader);

            // Defaults (match SessionController defaults)
            if (opt.bridge.listenIp.empty())
                opt.bridge.listenIp = "127.0.0.1";
            if (opt.bridge.listenPort == 0)
                opt.bridge.listenPort = 18080;

            // Basic validation so we fail fast (no endless OpenVPN reconnect loop)
            if (opt.bridge.host.empty() || opt.bridge.port.empty() || opt.bridge.path.empty())
            {
                ipc_.ReplyError(cmd.id, "bad_payload", "Missing bridge fields: host/port/path");
                return;
            }

            // Kick off async start first, then reply.
            // This ensures UI gets immediate response but still receives events later.
            const bool accepted = orchestrator_.StartAsync(std::move(opt));
            if (!accepted)
            {
                ipc_.ReplyError(cmd.id, "start_in_progress", "StartSession rejected (start already in progress)");
                ipc_.SendEvent(
                    datagate::ipc::EventType::SessionLifecycle,
                    BuildLifecyclePayload("start_rejected", "start_in_progress", false)
                );
                return;
            }

            ipc_.ReplyOk(cmd.id, "{}");
            ipc_.SendEvent(
                datagate::ipc::EventType::SessionLifecycle,
                BuildLifecyclePayload("starting", "user_request", true)
            );

            return;
        }

        case datagate::ipc::CommandType::StopSession:
        {
            ipc_.SendEvent(
                datagate::ipc::EventType::SessionLifecycle,
                BuildLifecyclePayload("stopping", "user_request", true)
            );

            // IMPORTANT:
            // Reply must be sent from the same thread/context as the command handler.
            // Do NOT reply from detached threads unless IpcServer is explicitly designed for it.

            orchestrator_.StopSync();

            const bool stopped = orchestrator_.WaitForIdle(20000);
            if (!stopped)
            {
                ipc_.ReplyError(cmd.id, "stop_timeout", "StopSession timed out (did not reach idle)");
                ipc_.SendEvent(
                    datagate::ipc::EventType::SessionLifecycle,
                    BuildLifecyclePayload("stop_failed", "timeout", false)
                );
                return;
            }

            ipc_.ReplyOk(cmd.id, "{\"state\":\"idle\"}");
            ipc_.SendEvent(
                datagate::ipc::EventType::SessionLifecycle,
                BuildLifecyclePayload("stopped", "user_request", true)
            );

            return;
        }

        case datagate::ipc::CommandType::GetStatus:
        {
            ipc_.ReplyOk(cmd.id, BuildStatusPayload(session_.GetState()));
            return;
        }

        case datagate::ipc::CommandType::StopEngine:
        {
            ipc_.ReplyOk(cmd.id, "{}");

            ipc_.SendEvent(
                datagate::ipc::EventType::SessionLifecycle,
                BuildLifecyclePayload("engine_stopping", "stop_engine", true)
            );

            orchestrator_.ShutdownAsync(stopEvent_);
            return;
        }

        default:
            ipc_.ReplyError(cmd.id, "unknown_command", "Unknown command");
            return;
        }
    });
}
