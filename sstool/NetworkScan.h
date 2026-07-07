#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>

#include "Console.h"
#include "Util.h"

// =====================================================================
// Network connection scan.
//
// Enumerates active TCP connections for the whole system via
// GetExtendedTcpTable (the same API `netstat -ano` uses -- read-only,
// no packet capture, no interception) and flags:
//   - Connections to known cheat-client license/auth/webhook endpoints
//   - Active connections from java/javaw or unrecognized executables
//
// This complements MacroSignature.h's "/hwidLogin" static-string check:
// that finds the string baked into the exe; this shows whether it's
// actually being *used* right now (an active connection, not just a
// dormant capability).
// =====================================================================
namespace networkscan {

    using Severity = util::Severity;
    using Finding  = util::Finding;
    using util::toLowerA;

    // ---- known cheat-client network indicators ------------------------
    // Hostname fragments resolved from known cheat-client auth/webhook
    // infrastructure. Matched against reverse-DNS of the remote IP.
    static const std::vector<std::string> knownCheatHosts = {
        "novaclient.lol", "vape.gg", "rusherhack.org", "aristois.net",
        "dqrkis.xyz", "prestigeclient.vip", "sigmaclient",
        "liquidbounce.net", "meteorclient.com",
    };

    struct TcpConnInfo {
        DWORD       pid;
        std::string localAddr;
        std::string remoteAddr;
        std::string state;
        std::string processName;
    };

    static std::string ipToString(DWORD ip) {
        IN_ADDR addr;
        addr.S_un.S_addr = ip;
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return std::string(buf);
    }

    static const char* tcpStateName(DWORD state) {
        switch (state) {
            case MIB_TCP_STATE_CLOSED:     return "CLOSED";
            case MIB_TCP_STATE_LISTEN:     return "LISTEN";
            case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
            case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
            case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
            case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
            case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
            case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
            case MIB_TCP_STATE_CLOSING:    return "CLOSING";
            case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
            case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
            case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
            default:                       return "UNKNOWN";
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

    // Reverse-resolve an IP to a hostname (best-effort; only called for
    // already-established connections from java/unknown processes, so
    // the small number of lookups keeps this fast).
    static std::string reverseResolve(const std::string& ip) {
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

        char host[NI_MAXHOST];
        int result = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
            host, sizeof(host), nullptr, 0, NI_NAMEREQD);
        if (result != 0) return {};
        return std::string(host);
    }

    // ---- enumerate all TCP connections --------------------------------
    static std::vector<TcpConnInfo> enumerateTcpConnections() {
        std::vector<TcpConnInfo> out;

        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0) return out;

        std::vector<uint8_t> buffer(size);
        if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET,
                TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
            return out;
        }

        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];
            if (row.dwState != MIB_TCP_STATE_ESTAB) continue; // only active connections matter here

            TcpConnInfo info;
            info.pid = row.dwOwningPid;
            info.localAddr  = ipToString(row.dwLocalAddr)  + ":" + std::to_string(ntohs((u_short)row.dwLocalPort));
            info.remoteAddr = ipToString(row.dwRemoteAddr) + ":" + std::to_string(ntohs((u_short)row.dwRemotePort));
            info.state = tcpStateName(row.dwState);
            info.processName = processNameForPid(info.pid);
            out.push_back(info);
        }
        return out;
    }

    // ---- main scan ------------------------------------------------------
    static std::vector<Finding> scanConnections() {
        std::vector<Finding> out;

        WSADATA wsaData;
        bool wsaInit = (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);

        auto connections = enumerateTcpConnections();
        if (connections.empty()) {
            out.push_back({ Severity::Info, "No active TCP connections found (or access denied)." });
            if (wsaInit) WSACleanup();
            return out;
        }

        // Only reverse-resolve connections from java/javaw or unknown exe
        // names -- resolving every single browser/system connection would
        // be slow and isn't relevant to cheat detection.
        int checked = 0, flagged = 0;
        for (const auto& conn : connections) {
            std::string procLower = toLowerA(conn.processName);
            bool relevant = procLower.find("java") != std::string::npos ||
                            procLower.find("minecraft") != std::string::npos ||
                            procLower == "(unknown)";
            if (!relevant) continue;
            checked++;

            std::string host = reverseResolve(conn.remoteAddr.substr(0, conn.remoteAddr.find(':')));
            std::string hostLower = toLowerA(host);

            bool matched = false;
            for (const auto& knownHost : knownCheatHosts) {
                if (!host.empty() && hostLower.find(knownHost) != std::string::npos) {
                    matched = true;
                    flagged++;
                    out.push_back({ Severity::Danger,
                        conn.processName + " (PID " + std::to_string(conn.pid) +
                        ") has an active connection to known cheat-client host: " + host +
                        "  (" + conn.remoteAddr + ")" });
                    break;
                }
            }
            if (!matched && !host.empty()) {
                out.push_back({ Severity::Info,
                    conn.processName + " -> " + host + "  (" + conn.remoteAddr + ")" });
            }
        }

        if (flagged == 0) {
            out.push_back({ Severity::Info,
                "Checked " + std::to_string(checked) + " java/unknown connection(s) -- "
                "no known cheat-client hosts found." });
        }

        if (wsaInit) WSACleanup();
        return out;
    }

} // namespace networkscan
