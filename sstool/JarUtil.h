#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <optional>
#include <random>
#include <algorithm>
#include <cctype>
#include <cwchar>

// A .jar is just a ZIP file, but the project intentionally avoids pulling in
// a zip/inflate library (miniz, zlib, ...) as a dependency. Windows 10
// 1803+ and Windows 11 both ship tar.exe (bsdtar) in System32, which reads
// the ZIP format out of the box, so we just shell out to it. This keeps the
// tool a single .exe with no extra DLLs to distribute.
namespace jarutil {

    namespace fs = std::filesystem;

    // Builds a unique-ish temp directory under %TEMP%\sstool_scan\ for
    // extracting one jar (and its nested jars) into.
    inline fs::path makeTempDir(const std::wstring& label) {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);

        std::mt19937 rng(std::random_device{}());
        wchar_t buf[16];
        swprintf_s(buf, 16, L"%08x", rng());

        fs::path dir = fs::path(tempPath) / L"sstool_scan" / (label + L"_" + buf);
        std::error_code ec;
        fs::create_directories(dir, ec);
        return dir;
    }

    // Extracts a zip/jar archive into destDir using tar.exe. Returns false
    // if extraction failed (corrupt archive, tar.exe missing, etc.) -- the
    // caller should treat that as "couldn't fully inspect this jar" rather
    // than a hard error.
    inline bool extractArchive(const fs::path& archivePath, const fs::path& destDir) {
        std::error_code ec;
        fs::create_directories(destDir, ec);

        std::wstring cmd = L"tar.exe -xf \"" + archivePath.wstring() + L"\" -C \"" + destDir.wstring() + L"\"";

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};

        std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
        mutableCmd.push_back(L'\0');

        BOOL ok = CreateProcessW(
            nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi
        );
        if (!ok) return false;

        WaitForSingleObject(pi.hProcess, 15000); // 15s ceiling per archive
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode == 0;
    }

    inline void removeDirBestEffort(const fs::path& dir) {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    // Reads a whole file into a string (binary-safe; used for ASCII/UTF-8
    // substring scanning, not for text parsing).
    inline std::string readFileBytes(const fs::path& p, size_t capBytes = 4 * 1024 * 1024) {
        std::ifstream f(p, std::ios::binary);
        if (!f) return {};
        f.seekg(0, std::ios::end);
        std::streamoff size = f.tellg();
        if (size <= 0) return {};
        f.seekg(0, std::ios::beg);
        size_t toRead = static_cast<size_t>(std::min<std::streamoff>(size, static_cast<std::streamoff>(capBytes)));
        std::string data(toRead, '\0');
        f.read(data.data(), toRead);
        return data;
    }

    // Reads the NTFS "Zone.Identifier" alternate data stream Windows
    // attaches to files downloaded from the internet (via a browser or
    // Discord). On Windows 10 1709+ this often includes a HostUrl field
    // showing exactly where the file came from -- useful during a
    // screenshare because a mod claiming to be legitimate but downloaded
    // from a raw MediaFire/Discord CDN link is itself a signal.
    inline std::optional<std::string> readDownloadHostUrl(const fs::path& filePath) {
        fs::path adsPath = filePath;
        adsPath += L":Zone.Identifier";

        std::ifstream f(adsPath, std::ios::binary);
        if (!f) return std::nullopt;

        std::stringstream ss;
        ss << f.rdbuf();
        std::string content = ss.str();

        size_t pos = content.find("HostUrl=");
        if (pos == std::string::npos) return std::nullopt;
        pos += 8;
        size_t end = content.find_first_of("\r\n", pos);
        std::string url = (end == std::string::npos) ? content.substr(pos) : content.substr(pos, end - pos);
        if (url.empty()) return std::nullopt;
        return url;
    }

    // Maps a download URL to a friendly source name, same idea as the
    // PowerShell tool's Get-DownloadSource.
    inline std::string classifyDownloadSource(const std::string& url) {
        struct Entry { const char* needle; const char* name; };
        static const Entry table[] = {
            { "mediafire.com", "MediaFire" },
            { "discordapp.com", "Discord" },
            { "discord.com", "Discord" },
            { "dropbox.com", "Dropbox" },
            { "drive.google.com", "Google Drive" },
            { "mega.nz", "MEGA" },
            { "mega.co.nz", "MEGA" },
            { "github.com", "GitHub" },
            { "modrinth.com", "Modrinth" },
            { "curseforge.com", "CurseForge" },
        };
        std::string lower = url;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        for (const auto& e : table) {
            if (lower.find(e.needle) != std::string::npos) return e.name;
        }
        // fall back to bare host
        size_t schemeEnd = lower.find("://");
        size_t hostStart = (schemeEnd == std::string::npos) ? 0 : schemeEnd + 3;
        size_t hostEnd = lower.find('/', hostStart);
        return url.substr(hostStart, hostEnd == std::string::npos ? std::string::npos : hostEnd - hostStart);
    }

    // ---- Missing functions for EnhancedJarScan.h ----

    // List all files in the jar by extracting it to a temp directory first.
    inline std::vector<std::string> listEntries(const std::string& jarPath) {
        fs::path jar(jarPath);
        fs::path temp = makeTempDir(jar.stem().wstring());
        if (!extractArchive(jar, temp)) {
            removeDirBestEffort(temp);
            return {};
        }

        std::vector<std::string> entries;
        std::error_code ec;
        for (auto& p : fs::recursive_directory_iterator(temp, ec)) {
            if (p.is_regular_file()) {
                std::string rel = fs::relative(p.path(), temp).string();
                // Normalize slashes for jar entry style
                std::replace(rel.begin(), rel.end(), '\\', '/');
                entries.push_back(rel);
            }
        }
        removeDirBestEffort(temp);
        return entries;
    }

    // Read the whole jar as a single string (useful for grep-like scanning).
    inline std::string readAllText(const std::string& jarPath) {
        fs::path jar(jarPath);
        fs::path temp = makeTempDir(jar.stem().wstring() + L"_text");
        if (!extractArchive(jar, temp)) {
            removeDirBestEffort(temp);
            return {};
        }

        std::string combined;
        std::error_code ec;
        for (auto& p : fs::recursive_directory_iterator(temp, ec)) {
            if (p.is_regular_file()) {
                combined += readFileBytes(p.path());
            }
        }
        removeDirBestEffort(temp);
        return combined;
    }

    // Read a specific entry from the jar.
    inline std::string readEntry(const std::string& jarPath, const std::string& entryName) {
        fs::path jar(jarPath);
        fs::path temp = makeTempDir(jar.stem().wstring() + L"_entry");
        if (!extractArchive(jar, temp)) {
            removeDirBestEffort(temp);
            return {};
        }

        fs::path entryPath = temp / entryName;
        std::string content;
        if (fs::exists(entryPath)) {
            content = readFileBytes(entryPath);
        }
        removeDirBestEffort(temp);
        return content;
    }

} // namespace jarutil
