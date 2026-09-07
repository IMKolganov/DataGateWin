#pragma once

#include <mutex>
#include <string>

namespace datagate::xray
{
    /// Thin LoadLibrary wrapper around official libXray Windows DLL (`CGoInvoke` / `CGoFree`).
    class XrayRuntime
    {
    public:
        XrayRuntime() = default;
        ~XrayRuntime();

        XrayRuntime(const XrayRuntime&) = delete;
        XrayRuntime& operator=(const XrayRuntime&) = delete;

        bool EnsureLoaded(std::string& outError);
        bool IsLoaded() const;

        /// Full Invoke envelope response JSON.
        bool Invoke(const std::string& requestJson, std::string& outResponseJson, std::string& outError);

        bool ConvertShareLinksToXrayJson(const std::string& text, std::string& outDataJson, std::string& outError);
        bool RunFromJson(const std::string& configJson, std::string& outError);
        bool Stop(std::string& outError);
        bool IsRunning(std::string& outError);
        std::string VersionOrEmpty();

    private:
        using CGoInvokeFn = char* (__cdecl*)(char*);
        using CGoFreeFn = void (__cdecl*)(char*);

        bool InvokeMethod(const char* method, const std::string& payloadJson,
                          std::string& outDataJson, bool& outSuccess, std::string& outError);

        mutable std::mutex _mx;
        void* _module = nullptr; // HMODULE
        CGoInvokeFn _invoke = nullptr;
        CGoFreeFn _free = nullptr;
    };
}
