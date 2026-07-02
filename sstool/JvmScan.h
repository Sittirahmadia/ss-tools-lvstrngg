#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <cstdio>
#include <cctype>
#include <cwctype>
#include <sstream>

#include "Console.h"

// Some cheat-injection methods work by launching (or relaunching)
// Minecraft's JVM with extra command-line flags rather than modifying any
// jar on disk -- a -javaagent that bytecode-patches classes in memory at
// load time, or a debug/bootclasspath flag that bypasses the normal
// classloader. None of that shows up in a mods-folder scan or even a
// memory string scan if the agent is careful. This module reads the
// running java/javaw process's command line and flags known-suspicious
// patterns, the same signal the MeowModAnalyzer PowerShell tool's
// Invoke-JvmScan looks for.
//
// Win32 doesn't expose another process's command line directly, and
// reading it manually means walking the target's PEB via
// NtQueryInformationProcess -- undocumented, and needs matching bitness
// with the target. Shelling out to PowerShell's Get-CimInstance (WMI) is
// the same technique Task Manager's "Command line" column and the
// original tool both effectively use, so that's what this does.
namespace jvmscan {

    struct JavaProcessInfo {
        DWORD pid = 0;
        std::wstring exeName;
    };

    inline std::vector<JavaProcessInfo> findJavaProcesses() {
        std::vector<JavaProcessInfo> found;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return found;

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snap, &entry)) {
            do {
                std::wstring name = entry.szExeFile;
                std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                if (name == L"java.exe" || name == L"javaw.exe") {
                    found.push_back({ entry.th32ProcessID, entry.szExeFile });
                }
            } while (Process32NextW(snap, &entry));
        }
        CloseHandle(snap);
        return found;
    }

    inline std::string trim(std::string value) {
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
        size_t start = 0;
        while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) ++start;
        return start == 0 ? value : value.substr(start);
    }

    inline std::string wideToUtf8(const std::wstring& value) {
        if (value.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (len <= 1) return {};
        std::string out(static_cast<size_t>(len - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), len, nullptr, nullptr);
        return out;
    }

    inline std::string shellQuotePowerShell(const std::string& value) {
        std::string quoted = "'";
        for (char ch : value) {
            if (ch == '\'') quoted += "''";
            else quoted += ch;
        }
        quoted += "'";
        return quoted;
    }

    // Retrieves a process's full command line via WMI (through
    // PowerShell). Returns an empty string if it couldn't be read
    // (access denied, PowerShell missing, etc.) -- callers should treat
    // that as "unknown" rather than "clean".
    inline std::string getCommandLine(DWORD pid) {
        std::ostringstream ps;
        ps << "$ErrorActionPreference='SilentlyContinue';"
           << "$p=Get-CimInstance Win32_Process -Filter "
           << shellQuotePowerShell("ProcessId=" + std::to_string(pid)) << ";"
           << "if($null -ne $p -and $null -ne $p.CommandLine){[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8;$p.CommandLine}";

        std::string cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"" + ps.str() + "\"";

        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return {};

        std::string result;
        char buf[1024];
        while (fgets(buf, sizeof(buf), pipe) != nullptr) result += buf;
        int rc = _pclose(pipe);
        if (rc == -1) return trim(result);
        return trim(result);
    }

    struct JvmFinding {
        con::Color severity;
        std::string text;
    };

    inline std::vector<JvmFinding> analyzeCommandLine(const std::string& cmdLine) {
        std::vector<JvmFinding> findings;
        if (cmdLine.empty()) return findings;

        static const std::vector<std::string> legitAgentMarkers = {
            "jmxremote", "yjp", "jrebel", "newrelic", "jacoco", "theseus"
        };

        try {
            std::regex agentRe(R"agent(-javaagent:(?:"([^"]+)"|([^\s"]+)))agent", std::regex_constants::icase);
            auto begin = std::sregex_iterator(cmdLine.begin(), cmdLine.end(), agentRe);
            for (auto it = begin; it != std::sregex_iterator(); ++it) {
                std::string agentPath = (*it)[1].matched ? (*it)[1].str() : (*it)[2].str();
                std::string lowerPath = agentPath;
                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

                bool isLegit = std::any_of(legitAgentMarkers.begin(), legitAgentMarkers.end(),
                    [&](const std::string& m) { return lowerPath.find(m) != std::string::npos; });

                if (!isLegit) {
                    findings.push_back({ con::Color::Red, "JVM agent injected -- -javaagent:" + agentPath });
                }
            }
        } catch (const std::regex_error&) { /* malformed cmdline text, skip agent parsing */ }

        struct FlagCheck { const char* flag; const char* desc; };
        static const FlagCheck suspiciousFlags[] = {
            { "-Xbootclasspath/p:", "prepends to bootstrap classpath, overrides core Java classes" },
            { "-Xbootclasspath/a:", "appends to bootstrap classpath, injects below the classloader" },
            { "-agentlib:jdwp",     "JDWP debug agent -- remote debugging enabled" },
            { "-agentpath:",        "native agent loaded -- bypasses the Java sandbox" },
        };
        std::string cmdLower = cmdLine;
        std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        for (const auto& sf : suspiciousFlags) {
            if (cmdLower.find(sf.flag) != std::string::npos) {
                findings.push_back({ con::Color::Yellow, std::string("Suspicious JVM flag -- ") + sf.flag + " (" + sf.desc + ")" });
            }
        }
        return findings;
    }

    inline void runJvmScan() {
        auto procs = findJavaProcesses();
        if (procs.empty()) {
            con::line("No running java/javaw process found. Is Minecraft open?", con::Color::Yellow);
            return;
        }

        con::header("JVM Flag / Injected Agent Scan");
        bool anyFinding = false;

        for (const auto& p : procs) {
            std::string cmdLine = getCommandLine(p.pid);
            std::string exeNameA = wideToUtf8(p.exeName);
            std::cout << "PID " << p.pid << " (" << exeNameA << "):\n";

            if (cmdLine.empty()) {
                con::line("  Couldn't read command line (access denied, or PowerShell/WMI unavailable).", con::Color::Gray);
                continue;
            }

            auto findings = analyzeCommandLine(cmdLine);
            if (findings.empty()) {
                con::line("  No suspicious JVM flags or unrecognized agents found.", con::Color::Green);
            } else {
                anyFinding = true;
                for (const auto& f : findings) con::line("  [!] " + f.text, f.severity);
            }
        }

        if (anyFinding) {
            con::line("\nSuspicious JVM flags found -- an agent-based injection method may be in use.", con::Color::Red);
        }
    }

} // namespace jvmscan
