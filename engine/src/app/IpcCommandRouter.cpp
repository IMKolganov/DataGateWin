#include "IpcCommandRouter.h"

#include "src/ipc/IpcProtocol.h"
#include "src/session/SessionState.h"

#include <cctype>
#include <cstdint>
#include <sstream>
#include <string>

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

    auto v = json.substr(p + 1);
    while (!v.empty() && std::isspace((unsigned char)v.front()))
        v.erase(v.begin());

    if (v.rfind("true", 0) == 0)  { outValue = true;  return true; }
    if (v.rfind("false", 0) == 0) { outValue = false; return true; }

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

void IpcCommandRouter::Install()
{
    ipc_.SetCommandHandler([this](const datagate::ipc::Command& cmd)
    {
        switch (cmd.type)
        {
        case datagate::ipc::CommandType::StartSession:
        {
            datagate::session::StartOptions opt;
            if (!TryExtractJsonStringField(cmd.payloadJson, "ovpnContent", opt.ovpnContentUtf8))
            {
                ipc_.ReplyError(cmd.id, "bad_payload", "Missing ovpnContent");
                return;
            }

            ipc_.ReplyOk(cmd.id, "{}");
            orchestrator_.StartAsync(std::move(opt));
            return;
        }

        case datagate::ipc::CommandType::StopSession:
        {
            ipc_.ReplyOk(cmd.id, "{}");
            orchestrator_.StopAsync();
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
            orchestrator_.ShutdownAsync(stopEvent_);
            return;
        }

        default:
            ipc_.ReplyError(cmd.id, "unknown_command", "Unknown command");
            return;
        }
    });
}
