#include "XrayRuntime.h"

#include <windows.h>

#include <json/json.h>

#include <memory>
#include <sstream>

namespace datagate::xray
{
    namespace
    {
        std::wstring Widen(const std::string& utf8)
        {
            if (utf8.empty())
                return {};
            const int n = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), nullptr, 0);
            std::wstring w(n, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), w.data(), n);
            return w;
        }

        std::string Narrow(const char* p)
        {
            return p ? std::string(p) : std::string();
        }

        std::string FindDllBesideEngine()
        {
            wchar_t path[MAX_PATH]{};
            GetModuleFileNameW(nullptr, path, MAX_PATH);
            std::wstring w(path);
            const auto slash = w.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
                w.resize(slash + 1);
            w += L"libXray.dll";
            char narrow[MAX_PATH * 4]{};
            WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, narrow, (int)sizeof(narrow), nullptr, nullptr);
            return std::string(narrow);
        }
    }

    XrayRuntime::~XrayRuntime()
    {
        std::lock_guard lock(_mx);
        if (_module)
        {
            FreeLibrary(static_cast<HMODULE>(_module));
            _module = nullptr;
        }
        _invoke = nullptr;
        _free = nullptr;
    }

    bool XrayRuntime::IsLoaded() const
    {
        std::lock_guard lock(_mx);
        return _module != nullptr && _invoke != nullptr && _free != nullptr;
    }

    bool XrayRuntime::EnsureLoaded(std::string& outError)
    {
        std::lock_guard lock(_mx);
        if (_module && _invoke && _free)
            return true;

        const auto pathUtf8 = FindDllBesideEngine();
        const auto pathW = Widen(pathUtf8);
        HMODULE mod = LoadLibraryW(pathW.c_str());
        if (!mod)
        {
            // Also try engine\libXray.dll relative cwd / third_party for local debug.
            mod = LoadLibraryW(L"libXray.dll");
        }
        if (!mod)
        {
            outError = "LoadLibrary(libXray.dll) failed; place libXray.dll next to engine.exe (see docs/BUILD_LIBXRAY_WINDOWS.md)";
            return false;
        }

        auto invoke = reinterpret_cast<CGoInvokeFn>(GetProcAddress(mod, "CGoInvoke"));
        auto freeFn = reinterpret_cast<CGoFreeFn>(GetProcAddress(mod, "CGoFree"));
        if (!invoke || !freeFn)
        {
            FreeLibrary(mod);
            outError = "libXray.dll missing CGoInvoke/CGoFree exports";
            return false;
        }

        _module = mod;
        _invoke = invoke;
        _free = freeFn;
        return true;
    }

    bool XrayRuntime::Invoke(const std::string& requestJson, std::string& outResponseJson, std::string& outError)
    {
        if (!EnsureLoaded(outError))
            return false;

        std::lock_guard lock(_mx);
        char* raw = _invoke(const_cast<char*>(requestJson.c_str()));
        if (!raw)
        {
            outError = "CGoInvoke returned null";
            return false;
        }
        outResponseJson = Narrow(raw);
        _free(raw);
        return true;
    }

    bool XrayRuntime::InvokeMethod(const char* method, const std::string& payloadJson,
                                   std::string& outDataJson, bool& outSuccess, std::string& outError)
    {
        outDataJson.clear();
        outSuccess = false;

        Json::Value req(Json::objectValue);
        req["apiVersion"] = 1;
        req["method"] = method;
        {
            Json::CharReaderBuilder b;
            Json::Value payload;
            std::string errs;
            std::unique_ptr<Json::CharReader> reader(b.newCharReader());
            if (!payloadJson.empty())
            {
                if (!reader->parse(payloadJson.data(), payloadJson.data() + payloadJson.size(), &payload, &errs))
                {
                    outError = "bad payload json: " + errs;
                    return false;
                }
            }
            else
            {
                payload = Json::Value(Json::objectValue);
            }
            req["payload"] = payload;
        }

        Json::StreamWriterBuilder wb;
        wb["indentation"] = "";
        const std::string request = Json::writeString(wb, req);

        std::string response;
        if (!Invoke(request, response, outError))
            return false;

        Json::CharReaderBuilder b;
        Json::Value resp;
        std::string errs;
        std::unique_ptr<Json::CharReader> reader(b.newCharReader());
        if (!reader->parse(response.data(), response.data() + response.size(), &resp, &errs))
        {
            outError = "bad response json: " + errs;
            return false;
        }

        outSuccess = resp.get("success", false).asBool();
        if (!outSuccess)
        {
            outError = resp.get("error", "libXray invoke failed").asString();
            return false;
        }

        const auto& data = resp["data"];
        if (data.isNull())
            outDataJson = "{}";
        else if (data.isString())
            outDataJson = data.asString();
        else
            outDataJson = Json::writeString(wb, data);

        return true;
    }

    bool XrayRuntime::ConvertShareLinksToXrayJson(const std::string& text, std::string& outDataJson, std::string& outError)
    {
        Json::Value payload(Json::objectValue);
        payload["text"] = text;
        Json::StreamWriterBuilder wb;
        wb["indentation"] = "";
        bool ok = false;
        return InvokeMethod("convertShareLinksToXrayJson", Json::writeString(wb, payload), outDataJson, ok, outError) && ok;
    }

    bool XrayRuntime::RunFromJson(const std::string& configJson, std::string& outError)
    {
        Json::Value payload(Json::objectValue);
        payload["configJSON"] = configJson;
        Json::StreamWriterBuilder wb;
        wb["indentation"] = "";
        std::string data;
        bool ok = false;
        return InvokeMethod("runXrayFromJson", Json::writeString(wb, payload), data, ok, outError) && ok;
    }

    bool XrayRuntime::Stop(std::string& outError)
    {
        if (!IsLoaded())
            return true;
        std::string data;
        bool ok = false;
        // stopXray should not hard-fail stop path
        if (!InvokeMethod("stopXray", "{}", data, ok, outError))
            return false;
        return true;
    }

    bool XrayRuntime::IsRunning(std::string& outError)
    {
        std::string data;
        bool ok = false;
        if (!InvokeMethod("getXrayState", "{}", data, ok, outError) || !ok)
            return false;
        Json::CharReaderBuilder b;
        Json::Value obj;
        std::string errs;
        std::unique_ptr<Json::CharReader> reader(b.newCharReader());
        if (!reader->parse(data.data(), data.data() + data.size(), &obj, &errs))
            return false;
        return obj.get("running", false).asBool();
    }

    std::string XrayRuntime::VersionOrEmpty()
    {
        std::string data;
        bool ok = false;
        std::string err;
        if (!InvokeMethod("xrayVersion", "{}", data, ok, err) || !ok)
            return {};
        Json::CharReaderBuilder b;
        Json::Value obj;
        std::string errs;
        std::unique_ptr<Json::CharReader> reader(b.newCharReader());
        if (!reader->parse(data.data(), data.data() + data.size(), &obj, &errs))
            return {};
        return obj.get("version", "").asString();
    }
}
