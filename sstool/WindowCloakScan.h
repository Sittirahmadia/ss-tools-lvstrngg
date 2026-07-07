#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>

#include "Console.h"
#include "Util.h"

// =====================================================================
// Window capture-cloaking scan.
//
// Windows 10 (2004+) and Windows 11 support SetWindowDisplayAffinity()
// with WDA_EXCLUDEFROMCAPTURE / WDA_MONITOR: a window can mark itself
// as invisible to any screen-capture API (OBS, Discord screenshare,
// Windows.Graphics.Capture, GDI BitBlt-based capture) while remaining
// perfectly visible to the person sitting at the PC.
//
// This is a real technique -- legitimate for things like DRM-protected
// video players or password managers hiding sensitive fields from
// capture -- but it is also exactly the technique a macro/overlay tool
// would use to stay invisible during a screenshare while the operator
// still sees it locally. A window that's visible+enabled but reports
// itself excluded from capture is a strong, hard-to-fake signal, since
// the affinity flag is queried directly from Windows rather than
// inferred from process/window name.
//
// Detection method: GetWindowDisplayAffinity() is a genuine read-only
// Win32 query -- it does not disable or bypass the cloaking, it only
// asks Windows to report the current affinity value for that window so
// the SS-er knows a cloaked window exists and can ask the player to
// close/show it.
// =====================================================================
namespace windowcloak {

    using Severity = util::Severity;
    using Finding  = util::Finding;

    #ifndef WDA_EXCLUDEFROMCAPTURE
    #define WDA_EXCLUDEFROMCAPTURE 0x00000011
    #endif
    #ifndef WDA_MONITOR
    #define WDA_MONITOR 0x00000001
    #endif

    struct CloakedWindow {
        HWND        hwnd;
        DWORD       pid;
        std::string title;
        std::string processName;
        DWORD       affinity;
    };

    static std::string affinityName(DWORD affinity) {
        switch (affinity) {
            case WDA_EXCLUDEFROMCAPTURE: return "WDA_EXCLUDEFROMCAPTURE";
            case WDA_MONITOR:            return "WDA_MONITOR";
            default:                     return "WDA_NONE";
        }
    }

    static std::string processNameForPid(DWORD pid) {
        HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!proc) return "(unknown)";
        wchar_t buf[MAX_PATH];
        DWORD len = MAX_PATH;
        std::string name = "(unknown)";
        if (QueryFullProcessImageNameW(proc, 0, buf, &len)) {
            std::wstring wpath(buf, len);
            std::string full = util::wideToUtf8(wpath);
            size_t slash = full.find_last_of("\\/");
            name = (slash != std::string::npos) ? full.substr(slash + 1) : full;
        }
        CloseHandle(proc);
        return name;
    }

    struct EnumCtx {
        std::vector<CloakedWindow>* results;
    };

    static BOOL CALLBACK enumWindowsProc(HWND hwnd, LPARAM lParam) {
        auto* ctx = reinterpret_cast<EnumCtx*>(lParam);

        if (!IsWindowVisible(hwnd)) return TRUE;

        DWORD affinity = 0;
        if (!GetWindowDisplayAffinity(hwnd, &affinity)) return TRUE;
        if (affinity == WDA_NONE) return TRUE; // normal window, not cloaked

        char titleBuf[512];
        int len = GetWindowTextA(hwnd, titleBuf, sizeof(titleBuf));
        std::string title = len > 0 ? std::string(titleBuf, len) : "(no title)";

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);

        CloakedWindow cw;
        cw.hwnd = hwnd;
        cw.pid = pid;
        cw.title = title;
        cw.processName = processNameForPid(pid);
        cw.affinity = affinity;
        ctx->results->push_back(cw);

        return TRUE;
    }

    // ---- main scan ------------------------------------------------------
    static std::vector<CloakedWindow> findCloakedWindows() {
        std::vector<CloakedWindow> results;
        EnumCtx ctx{ &results };
        EnumWindows(enumWindowsProc, reinterpret_cast<LPARAM>(&ctx));
        return results;
    }

    static std::vector<Finding> scan() {
        std::vector<Finding> out;
        auto cloaked = findCloakedWindows();

        if (cloaked.empty()) {
            out.push_back({ Severity::Info,
                "No windows are excluded from screen capture -- nothing hidden from the current screenshare." });
            return out;
        }

        for (const auto& cw : cloaked) {
            out.push_back({ Severity::Danger,
                cw.processName + " (PID " + std::to_string(cw.pid) + ") has a window "
                "hidden from screen capture [" + affinityName(cw.affinity) + "]: \"" + cw.title + "\"" });
        }
        out.push_back({ Severity::Warning,
            std::to_string(cloaked.size()) + " window(s) found that would be invisible in this "
            "or any other screen recording -- ask the player to close or show these windows." });

        return out;
    }

} // namespace windowcloak
