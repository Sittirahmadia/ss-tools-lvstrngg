#pragma once
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include "Util.h"

// ---- helpers -------------------------------------------------------------

using util::toLowerA;
using util::containsAny;

// kept as a thin alias so existing call sites (`toLower(...)`) don't all
// need renaming -- toLowerA is the canonical name shared with the other
// scan modules now.
static inline std::string toLower(std::string s) { return util::toLowerA(std::move(s)); }

struct MacroHit {
    std::string source;   // "process", "window", "installed"
    std::string name;     // what matched
    DWORD pid = 0;        // only for process/window hits
    HWND hwnd = nullptr;  // only for window hits -- used to bring to foreground
};

// ---- 1. running processes (covers 198M Macro / Zenith Macro running in background) ----
static std::vector<MacroHit> scanRunningProcesses(const std::vector<std::string>& keywordsLower) {
    std::vector<MacroHit> hits;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return hits;

    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snap, &entry)) {
        do {
            std::string exeName = entry.szExeFile;
            std::string lower = toLower(exeName);
            if (containsAny(lower, keywordsLower)) {
                hits.push_back({ "process", exeName, entry.th32ProcessID });
            }
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
    return hits;
}

// ---- 2. window titles (catches macro GUIs even if the exe itself is renamed) ----
struct EnumContext {
    const std::vector<std::string>* keywords;
    std::vector<MacroHit>* hits;
};

static BOOL CALLBACK enumWindowsProc(HWND hwnd, LPARAM lParam) {
    auto* ctx = reinterpret_cast<EnumContext*>(lParam);
    if (!IsWindowVisible(hwnd)) return TRUE;

    char title[256];
    int len = GetWindowTextA(hwnd, title, sizeof(title));
    if (len <= 0) return TRUE;

    std::string lower = toLower(std::string(title, len));
    if (containsAny(lower, *ctx->keywords)) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        ctx->hits->push_back({ "window", std::string(title, len), pid, hwnd });
    }
    return TRUE;
}

static std::vector<MacroHit> scanWindowTitles(const std::vector<std::string>& keywordsLower) {
    std::vector<MacroHit> hits;
    EnumContext ctx{ &keywordsLower, &hits };
    EnumWindows(enumWindowsProc, reinterpret_cast<LPARAM>(&ctx));
    return hits;
}

// ---- 3. installed programs via the Uninstall registry keys ----
// Catches macro software that is installed but not currently running.
static void scanUninstallKey(HKEY root, const std::wstring& subKey, const std::vector<std::string>& keywordsLower, std::vector<MacroHit>& hits) {
    HKEY hKey;
    if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    wchar_t nameBuf[256];
    DWORD index = 0;
    DWORD nameLen = 256;

    while (RegEnumKeyExW(hKey, index, nameBuf, &nameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        HKEY subHKey;
        if (RegOpenKeyExW(hKey, nameBuf, 0, KEY_READ, &subHKey) == ERROR_SUCCESS) {
            wchar_t displayName[512];
            DWORD size = sizeof(displayName);
            if (RegQueryValueExW(subHKey, L"DisplayName", nullptr, nullptr, reinterpret_cast<LPBYTE>(displayName), &size) == ERROR_SUCCESS) {
                int utf8Len = WideCharToMultiByte(CP_UTF8, 0, displayName, -1, nullptr, 0, nullptr, nullptr);
                std::string name(utf8Len, 0);
                WideCharToMultiByte(CP_UTF8, 0, displayName, -1, name.data(), utf8Len, nullptr, nullptr);

                std::string lower = toLower(name);
                if (containsAny(lower, keywordsLower)) {
                    hits.push_back({ "installed", name, 0 });
                }
            }
            RegCloseKey(subHKey);
        }
        index++;
        nameLen = 256;
    }
    RegCloseKey(hKey);
}

static std::vector<MacroHit> scanInstalledPrograms(const std::vector<std::string>& keywordsLower) {
    std::vector<MacroHit> hits;
    // 64-bit apps
    scanUninstallKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", keywordsLower, hits);
    // 32-bit apps on 64-bit Windows
    scanUninstallKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", keywordsLower, hits);
    // per-user installs
    scanUninstallKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", keywordsLower, hits);
    return hits;
}

// ---- window focus helpers ------------------------------------------
// When the scanner finds a macro tool already running, it calls
// bringMacroWindowToForeground() to surface that window so the
// SS-er can see it on screen without the suspect being able to
// hide/minimize it first.

// Helper: find the main visible window belonging to a given PID.
struct FindHwndCtx { DWORD pid; HWND result; };

static BOOL CALLBACK findMainWindowProc(HWND hwnd, LPARAM lParam) {
    auto* ctx = reinterpret_cast<FindHwndCtx*>(lParam);
    if (!IsWindowVisible(hwnd)) return TRUE;
    // Only want top-level windows that have a title
    char title[256];
    if (GetWindowTextA(hwnd, title, sizeof(title)) == 0) return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == ctx->pid) {
        ctx->result = hwnd;
        return FALSE; // stop enumeration -- found it
    }
    return TRUE;
}

static HWND findMainWindowForPid(DWORD pid) {
    FindHwndCtx ctx{ pid, nullptr };
    EnumWindows(findMainWindowProc, reinterpret_cast<LPARAM>(&ctx));
    return ctx.result;
}

// Bring the macro app window to the foreground so the SS-er can see it.
// Uses SetForegroundWindow + ShowWindow(SW_RESTORE) so it works even
// if the suspect minimized it to tray. Returns true if a window was found
// and brought up, false if the process has no visible window (e.g. it's
// a background service / tray-only app -- in that case the process is
// still flagged, just no window to show).
static bool bringMacroWindowToForeground(const MacroHit& hit) {
    HWND hwnd = hit.hwnd;

    // If we only have a process hit (not a window hit), search by PID
    if (!hwnd && hit.pid != 0) {
        hwnd = findMainWindowForPid(hit.pid);
    }
    if (!hwnd) return false;

    // Restore if minimized, then force to foreground
    if (IsIconic(hwnd)) ShowWindow(hwnd, SW_RESTORE);
    SetForegroundWindow(hwnd);
    BringWindowToTop(hwnd);

    // SetForegroundWindow can be blocked by Windows if the calling
    // process doesn't have focus itself. The SPI_SETFOREGROUNDLOCKTIMEOUT
    // workaround: briefly allow any process to steal focus.
    DWORD lockTimeout = 0;
    SystemParametersInfo(SPI_GETFOREGROUNDLOCKTIMEOUT, 0, &lockTimeout, 0);
    SystemParametersInfo(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, nullptr, 0);
    SetForegroundWindow(hwnd);
    SystemParametersInfo(SPI_SETFOREGROUNDLOCKTIMEOUT, lockTimeout, nullptr, 0);

    return true;
}

// ---- canonical keyword list -----------------------------------------
// The single source of truth for macro-tool keywords: used by
// scanRunningProcesses/scanWindowTitles/scanInstalledPrograms above, by
// main.cpp's runMacroSoftwareScan(), and by MacroSignature.h's on-disk
// signature sweep. Previously main.cpp also carried its own local copy
// of this same list, which is exactly the kind of drift-prone
// duplication that leads to the two scans quietly disagreeing over time.
static const std::vector<std::string> macroKeywords = {
    "198m macro",      // "198M Macros"
    "198macro",
    "zenith macro",    // "Zenith Macros"
};

// ---- User-confirmation macro app launcher ---------------------------
// When a macro tool is found installed but NOT currently running,
// the SS-er is offered the choice to open it. The user must explicitly
// confirm -- this never auto-launches without input.
struct MacroInstallInfo {
    std::string name;
    std::string exePath;   // full path to the .exe
    std::string installDir;
};

static std::vector<MacroInstallInfo> findInstalledMacroExes() {
    std::vector<MacroInstallInfo> found;

    // Check registry uninstall keys for install locations
    struct RegRoot { HKEY hive; const wchar_t* subkey; };
    static const RegRoot roots[] = {
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
    };

    for (const auto& root : roots) {
        HKEY hKey;
        if (RegOpenKeyExW(root.hive, root.subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;

        wchar_t subkeyName[512];
        DWORD index = 0;
        while (RegEnumKeyW(hKey, index++, subkeyName, 512) == ERROR_SUCCESS) {
            HKEY hSub;
            if (RegOpenKeyExW(hKey, subkeyName, 0, KEY_READ, &hSub) != ERROR_SUCCESS) continue;

            auto readStr = [&](const wchar_t* valueName) -> std::string {
                wchar_t buf[2048]; DWORD sz = sizeof(buf); DWORD type;
                if (RegQueryValueExW(hSub, valueName, nullptr, &type, (BYTE*)buf, &sz) == ERROR_SUCCESS
                    && (type == REG_SZ || type == REG_EXPAND_SZ))
                    return util::wideToUtf8(buf);
                return {};
            };

            std::string displayName = readStr(L"DisplayName");
            std::string installLoc  = readStr(L"InstallLocation");
            std::string exePath     = readStr(L"DisplayIcon");

            RegCloseKey(hSub);

            std::string nameLower = util::toLowerA(displayName);
            for (const auto& kw : macroKeywords) {
                if (nameLower.find(kw) != std::string::npos) {
                    // Try to find the actual .exe
                    std::string resolvedExe = exePath;
                    if (resolvedExe.empty() && !installLoc.empty()) {
                        // Scan install dir for .exe files
                        std::wstring wdir(installLoc.begin(), installLoc.end());
                        WIN32_FIND_DATAW fd;
                        std::wstring pattern = wdir + L"\\*.exe";
                        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
                        if (hFind != INVALID_HANDLE_VALUE) {
                            resolvedExe = installLoc + "\\" + util::wideToUtf8(fd.cFileName);
                            FindClose(hFind);
                        }
                    }
                    // Strip comma-separated icon index from DisplayIcon
                    size_t comma = resolvedExe.find(',');
                    if (comma != std::string::npos) resolvedExe = resolvedExe.substr(0, comma);

                    found.push_back({ displayName, resolvedExe, installLoc });
                    break;
                }
            }
        }
        RegCloseKey(hKey);
    }
    return found;
}

// Present the found macro install to the SS-er and ask if they want
// to open it. Returns true if the user chose to launch it.
static bool offerToLaunchMacroApp(const MacroInstallInfo& app) {
    std::cout << "\n";
    con::set(con::Color::Yellow);
    std::cout << "  +----------------------------------------------------------+\n";
    std::cout << "  |  MACRO APP DETECTED (not currently running)              |\n";
    std::cout << "  +----------------------------------------------------------+\n";
    con::reset();
    con::bad("Installed: " + app.name);
    if (!app.exePath.empty()) con::dim("Executable: " + app.exePath);
    if (!app.installDir.empty()) con::dim("Install dir: " + app.installDir);

    std::cout << "\n";
    con::set(con::Color::Yellow);
    std::cout << "  [?] Apakah kamu ingin membuka aplikasi ini untuk inspeksi?\n";
    con::reset();
    con::menuItem(1, "Ya, buka sekarang  (akan meminta konfirmasi UAC jika perlu)");
    con::menuItem(2, "Tidak, skip");
    con::prompt("Pilih (1 atau 2):");

    int choice = 0;
    std::string line;
    std::getline(std::cin, line);
    try { choice = std::stoi(line); } catch (...) {}

    if (choice != 1) {
        con::info("Skipped. Install path logged above as evidence.");
        return false;
    }

    if (app.exePath.empty()) {
        con::warn("No executable path found -- cannot launch. Open install folder manually.");
        if (!app.installDir.empty()) {
            std::string cmd = "explorer \"" + app.installDir + "\"";
            ShellExecuteA(nullptr, "open", "explorer.exe", app.installDir.c_str(), nullptr, SW_SHOWNORMAL);
        }
        return false;
    }

    // Launch with ShellExecuteA "runas" so Windows shows the UAC prompt
    // naturally -- the user sees exactly what's being run and can cancel.
    HINSTANCE result = ShellExecuteA(
        nullptr,
        "runas",                  // triggers UAC if needed
        app.exePath.c_str(),
        nullptr,
        nullptr,
        SW_SHOWNORMAL
    );

    if ((intptr_t)result > 32) {
        con::ok("Launched. The macro app window should appear shortly.");
        con::dim("Take a screenshot as evidence once the window is visible.");
        return true;
    } else {
        con::warn("Launch failed (user cancelled UAC, or executable not found).");
        return false;
    }
}
