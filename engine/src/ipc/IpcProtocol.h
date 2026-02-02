// IpcProtocol.h (your updated version with SessionLifecycle)
#pragma once

#include <cstdint>
#include <string>

namespace datagate::ipc
{
    enum class CommandType : uint8_t
    {
        Unknown = 0,
        StartSession,
        StopSession,
        GetStatus,
        StopEngine
    };

    enum class EventType : uint8_t
    {
        Unknown = 0,
        EngineReady,
        StateChanged,
        Log,
        Error,
        Connected,
        Disconnected,
        SessionLifecycle
    };

    struct PipeNames
    {
        std::string controlPipe;
        std::string eventsPipe;
    };

    inline PipeNames MakePipeNames(const std::string& sessionId)
    {
        PipeNames n;
        n.controlPipe = R"(\\.\pipe\datagate.engine.)" + sessionId + ".control";
        n.eventsPipe  = R"(\\.\pipe\datagate.engine.)" + sessionId + ".events";
        return n;
    }

    struct Command
    {
        std::string id;
        CommandType type = CommandType::Unknown;
        std::string payloadJson;
    };

    inline CommandType CommandTypeFromString(const std::string& s)
    {
        if (s == "StartSession") return CommandType::StartSession;
        if (s == "StopSession")  return CommandType::StopSession;
        if (s == "GetStatus")    return CommandType::GetStatus;
        if (s == "StopEngine")   return CommandType::StopEngine;
        return CommandType::Unknown;
    }

    inline std::string CommandTypeToString(CommandType t)
    {
        switch (t)
        {
        case CommandType::StartSession: return "StartSession";
        case CommandType::StopSession:  return "StopSession";
        case CommandType::GetStatus:    return "GetStatus";
        case CommandType::StopEngine:   return "StopEngine";
        default:                        return "Unknown";
        }
    }

    inline EventType EventTypeFromString(const std::string& s)
    {
        if (s == "EngineReady")      return EventType::EngineReady;
        if (s == "StateChanged")     return EventType::StateChanged;
        if (s == "Log")              return EventType::Log;
        if (s == "Error")            return EventType::Error;
        if (s == "Connected")        return EventType::Connected;
        if (s == "Disconnected")     return EventType::Disconnected;
        if (s == "SessionLifecycle") return EventType::SessionLifecycle;
        return EventType::Unknown;
    }

    inline std::string EventTypeToString(EventType t)
    {
        switch (t)
        {
        case EventType::EngineReady:      return "EngineReady";
        case EventType::StateChanged:     return "StateChanged";
        case EventType::Log:              return "Log";
        case EventType::Error:            return "Error";
        case EventType::Connected:        return "Connected";
        case EventType::Disconnected:     return "Disconnected";
        case EventType::SessionLifecycle: return "SessionLifecycle";
        default:                          return "Unknown";
        }
    }

    inline std::string JsonEscape(const std::string& s)
    {
        std::string out;
        out.reserve(s.size() + 8);
        for (char c : s)
        {
            switch (c)
            {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
            }
        }
        return out;
    }

    inline std::string MakeOkResponseLine(const std::string& id, const std::string& payloadJson = "{}")
    {
        return std::string("{\"id\":\"") + JsonEscape(id) + "\",\"ok\":true,\"error\":null,\"payload\":" + payloadJson + "}";
    }

    inline std::string MakeErrorResponseLine(const std::string& id, const std::string& code, const std::string& message)
    {
        return std::string("{\"id\":\"") + JsonEscape(id)
            + "\",\"ok\":false,\"error\":{\"code\":\"" + JsonEscape(code)
            + "\",\"message\":\"" + JsonEscape(message)
            + "\"},\"payload\":null}";
    }

    inline std::string MakeEventLine(EventType type, const std::string& payloadJson = "{}")
    {
        return std::string("{\"type\":\"") + EventTypeToString(type) + "\",\"payload\":" + payloadJson + "}";
    }
}
