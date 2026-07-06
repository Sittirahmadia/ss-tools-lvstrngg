#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <set>

#include "Console.h"
#include "Util.h"
#include "CheatStrings.h"

// =====================================================================
// Extended forensics -- OS + Minecraft-level artifact scanning.
//
// Covers:
//   1. .minecraft/logs  -- latest.log + old logs for cheat class names
//   2. crash-reports    -- crash signatures from known cheat injectors
//   3. configs          -- known cheat client config folders/files
//   4. %TEMP% + Downloads -- suspicious exe/jar files at rest
//   5. Windows clipboard history -- sometimes contains client URLs/keys
//   6. Recent files     -- MRU list for jars/exes opened recently
// =====================================================================
namespace forensicsext {

    namespace fs = std::filesystem;

    using Finding = util::Finding;
    using Severity = util::Severity;
    using util::toLowerA;

    // ---- known cheat config folder/file names -----------------------
    static const std::vector<std::string> knownConfigFragments = {
        "meteorclient", "meteor-client", "liquidbounce", "rusherhack",
        "aristois", "wurst", "impactclient", "vapeclient", "vape",
        "sigmaclient", "futureclient", "future-client", "kamiblue",
        "bleachhack", "inertia", "fdpclient", "novaclient", "nova",
        "doomsdayclient", "doomsday", "asteria", "xenon", "prestige",
        "gypsy", "phantom", "catlean", "argon", "skate", "walksy",
        "198macro", "198m", "zenithmacro", "zenith",
        "cheatbreaker", "cbclient",
    };

    // ---- log/crash keyword matchers ---------------------------------
    // Strings that appear in log output from known cheat clients
    static const std::vector<std::string> logCheatKeywords = {
        "meteordevelopment", "meteor-client", "liquidbounce",
        "rusherhack", "aristois", "wurst", "impactclient",
        "novaclient", "vapeclient", "SelfDestruct", "selfdestruct",
        "KillAura", "killaura", "AimAssist", "aimassist",
        "org/chainlibs/module", "imgui.binding",
        "JNativeHook", "GlobalScreen",
        "LicenseCheckMixin", "obfuscatedAuth",
        "TokenGrabber", "TokenLogger", "SessionStealer",
        "phantomclient", "phantom-refmap",
        "lvstrng", "dqrkis", "WalksyOptimizer",
        "macro_198", "198macro",
    };

    static fs::path expandEnv(const std::wstring& raw) {
        wchar_t buf[MAX_PATH * 2];
        DWORD n = ExpandEnvironmentStringsW(raw.c_str(), buf, MAX_PATH * 2);
        if (n == 0) return {};
        return fs::path(std::wstring(buf, n - 1));
    }

    static std::string readFileSample(const fs::path& p, size_t maxBytes = 512 * 1024) {
        std::ifstream f(p, std::ios::binary);
        if (!f.is_open()) return {};
        std::string s(maxBytes, '\0');
        f.read(s.data(), maxBytes);
        s.resize((size_t)f.gcount());
        return s;
    }

    static bool contentContainsAny(const std::string& content, const std::vector<std::string>& keywords) {
        std::string lower = toLowerA(content);
        for (const auto& kw : keywords) {
            if (lower.find(toLowerA(kw)) != std::string::npos) return true;
        }
        return false;
    }

    static std::string firstMatchedKeyword(const std::string& contentLower, const std::vector<std::string>& keywords) {
        for (const auto& kw : keywords) {
            if (contentLower.find(toLowerA(kw)) != std::string::npos) return kw;
        }
        return {};
    }

    // ---- 1. Minecraft log scan --------------------------------------
    static std::vector<Finding> scanMinecraftLogs(const fs::path& mcRoot) {
        std::vector<Finding> out;
        fs::path logsDir = mcRoot / "logs";
        std::error_code ec;
        if (!fs::exists(logsDir, ec)) {
            out.push_back({ Severity::Info, "No logs folder found at: " + logsDir.string() });
            return out;
        }

        std::vector<fs::path> logFiles;
        for (auto& e : fs::directory_iterator(logsDir, fs::directory_options::skip_permission_denied, ec)) {
            std::string ext = e.path().extension().string();
            if (ext == ".log" || ext == ".gz" || ext == ".txt")
                logFiles.push_back(e.path());
        }

        // Always scan latest.log first
        fs::path latest = logsDir / "latest.log";
        if (fs::exists(latest, ec)) {
            std::string content = readFileSample(latest);
            std::string lower = toLowerA(content);
            std::string matched = firstMatchedKeyword(lower, logCheatKeywords);
            if (!matched.empty()) {
                out.push_back({ Severity::Danger,
                    "latest.log contains cheat signature: \"" + matched + "\"" });
            } else {
                out.push_back({ Severity::Info, "latest.log: no cheat signatures found." });
            }
        }

        // Scan older logs
        int flaggedOld = 0;
        for (const auto& lf : logFiles) {
            if (lf == latest) continue;
            std::string content = readFileSample(lf, 128 * 1024); // shorter read for old logs
            std::string lower = toLowerA(content);
            std::string matched = firstMatchedKeyword(lower, logCheatKeywords);
            if (!matched.empty()) {
                flaggedOld++;
                out.push_back({ Severity::Warning,
                    "Old log " + lf.filename().string() + " contains: \"" + matched + "\"" });
            }
        }
        if (flaggedOld == 0 && !logFiles.empty())
            out.push_back({ Severity::Info,
                std::to_string(logFiles.size()) + " old log file(s) scanned -- no cheat signatures." });

        return out;
    }

    // ---- 2. Crash-reports scan --------------------------------------
    static std::vector<Finding> scanCrashReports(const fs::path& mcRoot) {
        std::vector<Finding> out;
        fs::path crashDir = mcRoot / "crash-reports";
        std::error_code ec;
        if (!fs::exists(crashDir, ec)) {
            out.push_back({ Severity::Info, "No crash-reports folder found." });
            return out;
        }

        int flagged = 0, total = 0;
        for (auto& e : fs::directory_iterator(crashDir, fs::directory_options::skip_permission_denied, ec)) {
            if (e.path().extension() != ".txt") continue;
            total++;
            std::string content = readFileSample(e.path(), 128 * 1024);
            std::string lower = toLowerA(content);
            std::string matched = firstMatchedKeyword(lower, logCheatKeywords);
            if (!matched.empty()) {
                flagged++;
                out.push_back({ Severity::Warning,
                    "Crash report contains cheat signature \"" + matched + "\": "
                    + e.path().filename().string() });
            }
        }
        if (flagged == 0)
            out.push_back({ Severity::Info,
                std::to_string(total) + " crash report(s) scanned -- no cheat signatures." });
        return out;
    }

    // ---- 3. Config folder scan --------------------------------------
    static std::vector<Finding> scanMinecraftConfigs(const fs::path& mcRoot) {
        std::vector<Finding> out;
        fs::path configDir = mcRoot / "config";
        std::error_code ec;
        if (!fs::exists(configDir, ec)) {
            out.push_back({ Severity::Info, "No config folder found." });
            return out;
        }

        bool anyHit = false;
        for (auto& e : fs::recursive_directory_iterator(configDir,
                fs::directory_options::skip_permission_denied, ec)) {
            std::string nameLower = toLowerA(e.path().filename().string());
            std::string pathLower = toLowerA(e.path().string());
            for (const auto& frag : knownConfigFragments) {
                if (nameLower.find(frag) != std::string::npos ||
                    pathLower.find(frag) != std::string::npos) {
                    anyHit = true;
                    out.push_back({ Severity::Danger,
                        "Known cheat client config found: " + e.path().filename().string() });
                    out.push_back({ util::Severity::Info, e.path().string() });
                    break;
                }
            }
        }
        if (!anyHit)
            out.push_back({ Severity::Info, "No known cheat config files/folders found." });
        return out;
    }

    // ---- 4. %TEMP% + Downloads scan ---------------------------------
    static std::vector<Finding> scanTempAndDownloads() {
        std::vector<Finding> out;
        std::vector<fs::path> scanDirs = {
            expandEnv(L"%TEMP%"),
            expandEnv(L"%USERPROFILE%\\Downloads"),
            expandEnv(L"%USERPROFILE%\\Desktop"),
        };

        static const std::vector<std::string> suspiciousExeNames = {
            "198macro", "198m", "zenith", "meteorclient", "liquidbounce",
            "wurst", "rusherhack", "vape", "impactclient", "novaclient",
            "cheat", "inject", "bypass", "hack", "aimbot", "killaura",
        };

        bool anyHit = false;
        std::error_code ec;
        for (const auto& dir : scanDirs) {
            if (!fs::exists(dir, ec)) continue;
            for (auto& e : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
                std::string nameLower = toLowerA(e.path().filename().string());
                std::string ext = toLowerA(e.path().extension().string());
                if (ext != ".exe" && ext != ".jar" && ext != ".zip") continue;

                for (const auto& frag : suspiciousExeNames) {
                    if (nameLower.find(frag) != std::string::npos) {
                        anyHit = true;
                        Severity sev = ext == ".exe" ? Severity::Danger : Severity::Warning;
                        out.push_back({ sev,
                            "Suspicious " + ext + " in " + dir.filename().string() + ": "
                            + e.path().filename().string() });
                        out.push_back({ Severity::Info, e.path().string() });
                        break;
                    }
                }
            }
        }
        if (!anyHit)
            out.push_back({ Severity::Info,
                "No suspicious files found in Temp/Downloads/Desktop." });
        return out;
    }

    // ---- 5. Clipboard history scan ----------------------------------
    // Reads the clipboard text content (one-time, non-destructive).
    // Cheat clients sometimes require pasting a license key or URL into
    // their auth panel during setup -- residual clipboard content can
    // confirm a client was used even after it's been deleted.
    static std::vector<Finding> scanClipboard() {
        std::vector<Finding> out;
        if (!OpenClipboard(nullptr)) {
            out.push_back({ Severity::Info, "Clipboard: could not open (in use or denied)." });
            return out;
        }

        HANDLE hData = GetClipboardData(CF_TEXT);
        if (!hData) {
            CloseClipboard();
            out.push_back({ Severity::Info, "Clipboard: empty or non-text content." });
            return out;
        }

        char* text = static_cast<char*>(GlobalLock(hData));
        std::string clipContent;
        if (text) {
            clipContent = std::string(text, strnlen(text, 4096));
            GlobalUnlock(hData);
        }
        CloseClipboard();

        if (clipContent.empty()) {
            out.push_back({ Severity::Info, "Clipboard: empty." });
            return out;
        }

        std::string lower = toLowerA(clipContent);
        static const std::vector<std::string> clipKeywords = {
            "novaclient", "liquidbounce", "meteorclient", "rusherhack",
            "vapeclient", "vape.gg", "impactclient", "aristois",
            "198macro", "zenithmacro", "dqrkis.xyz",
            "hwid", "license", "activation", "/hwidLogin",
        };

        bool anyHit = false;
        for (const auto& kw : clipKeywords) {
            if (lower.find(toLowerA(kw)) != std::string::npos) {
                anyHit = true;
                // Show only the first 80 chars to avoid leaking sensitive data
                std::string preview = clipContent.size() > 80
                    ? clipContent.substr(0, 80) + "..." : clipContent;
                out.push_back({ Severity::Warning,
                    "Clipboard contains cheat-related keyword \"" + kw + "\": " + preview });
            }
        }
        if (!anyHit)
            out.push_back({ Severity::Info, "Clipboard: no cheat-related content detected." });
        return out;
    }

    // ---- 6. Recent files (Windows MRU) ------------------------------
    static std::vector<Finding> scanRecentFiles() {
        std::vector<Finding> out;
        fs::path recentDir = expandEnv(L"%APPDATA%\\Microsoft\\Windows\\Recent");
        std::error_code ec;
        if (!fs::exists(recentDir, ec)) {
            out.push_back({ Severity::Info, "Recent Items folder not accessible." });
            return out;
        }

        static const std::vector<std::string> suspiciousRecent = {
            "198macro", "198m", "zenith", "meteorclient", "liquidbounce",
            "rusherhack", "vape", "wurst", "novaclient", "impactclient",
            "cheat", "inject", "bypass", "hack", "killaura", "aimbot",
        };

        bool anyHit = false;
        int total = 0;
        for (auto& e : fs::directory_iterator(recentDir, fs::directory_options::skip_permission_denied, ec)) {
            std::string nameLower = toLowerA(e.path().filename().string());
            std::string ext = e.path().extension().string();
            if (ext != ".lnk") continue;
            total++;
            for (const auto& frag : suspiciousRecent) {
                if (nameLower.find(frag) != std::string::npos) {
                    anyHit = true;
                    out.push_back({ Severity::Danger,
                        "Recently opened file matches cheat name: " + e.path().filename().string() });
                    break;
                }
            }
        }
        if (!anyHit)
            out.push_back({ Severity::Info,
                std::to_string(total) + " recent file(s) checked -- no cheat-related names." });
        return out;
    }

    // ---- Combined scan for one Minecraft root -----------------------
    static void runFullForensics(const fs::path& mcRoot) {
        struct Step { const char* title; std::vector<Finding>(*fn)(const fs::path&); bool needsMcRoot; };

        // Steps that need mcRoot
        auto runStep = [&](const char* title, std::vector<Finding> findings) {
            con::subheader(title);
            for (const auto& f : findings) con::finding(f.severity, f.text);
        };

        runStep("Minecraft Logs",    scanMinecraftLogs(mcRoot));
        runStep("Crash Reports",     scanCrashReports(mcRoot));
        runStep("Config Files",      scanMinecraftConfigs(mcRoot));
        runStep("Temp & Downloads",  scanTempAndDownloads());
        runStep("Clipboard",         scanClipboard());
        runStep("Recent Files",      scanRecentFiles());
    }

} // namespace forensicsext
