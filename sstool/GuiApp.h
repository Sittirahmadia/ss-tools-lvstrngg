#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <d3d11.h>
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <chrono>
#include <cstdio>

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "imgui/backends/imgui_impl_win32.h"
#include "imgui/backends/imgui_impl_dx11.h"

// =====================================================================
// GuiApp.h  --  Dear ImGui application shell for SS Tool
//
// Layout:
//   +--sidebar--+--------main panel----------+
//   |  [logo]   |  [tab bar]                 |
//   |  nav list |  [scan output / log]       |
//   |           |  [status bar]              |
//   +-----------+----------------------------+
//
// All scan functions are run on a background thread so the UI stays
// responsive. Output is captured into GuiLog (thread-safe ring buffer)
// and rendered as a scrollable, colour-coded log in the main panel.
// =====================================================================
namespace guiapp {

// ---- Log entry -------------------------------------------------------
enum class LogLevel { Info, Ok, Warn, Danger, Dim, Header };

struct LogEntry {
    LogLevel level;
    std::string text;
};

// ---- Shared state (accessed from both UI thread and scan thread) -----
struct AppState {
    // Log buffer
    std::deque<LogEntry>  log;
    std::mutex            logMutex;
    bool                  logScrollToBottom = false;

    // Scan control
    std::atomic<bool>     scanning{false};
    std::atomic<bool>     scanDone{false};
    std::string           currentScanName;

    // Sidebar selection
    int                   selectedNav = 0;

    // Progress
    std::atomic<int>      progressPct{0};
    std::string           progressLabel;
    std::mutex            progressMutex;

    // Results summary
    int                   lastHitCount  = 0;
    bool                  lastWasClean  = true;
    std::string           lastScanSummary;

    void addLog(LogLevel lvl, const std::string& text) {
        std::lock_guard<std::mutex> lk(logMutex);
        log.push_back({ lvl, text });
        if (log.size() > 4096) log.pop_front();
        logScrollToBottom = true;
    }

    void clearLog() {
        std::lock_guard<std::mutex> lk(logMutex);
        log.clear();
    }

    void setProgress(int pct, const std::string& label) {
        progressPct = pct;
        std::lock_guard<std::mutex> lk(progressMutex);
        progressLabel = label;
    }
};

static AppState g_state;

// ---- Log helper (replaces Console.h for GUI output) -----------------
// All scan modules call con:: functions; those are re-routed here when
// running inside the GUI by setting a global "gui mode" flag.
inline void logInfo   (const std::string& s) { g_state.addLog(LogLevel::Info,   s); }
inline void logOk     (const std::string& s) { g_state.addLog(LogLevel::Ok,     s); }
inline void logWarn   (const std::string& s) { g_state.addLog(LogLevel::Warn,   s); }
inline void logDanger (const std::string& s) { g_state.addLog(LogLevel::Danger, s); }
inline void logDim    (const std::string& s) { g_state.addLog(LogLevel::Dim,    s); }
inline void logHeader (const std::string& s) { g_state.addLog(LogLevel::Header, s); }

// ---- DX11 globals -------------------------------------------------------
static ID3D11Device*           g_pd3dDevice           = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext     = nullptr;
static IDXGISwapChain*         g_pSwapChain            = nullptr;
static bool                    g_SwapChainOccluded     = false;
static UINT                    g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView  = nullptr;

static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void CreateRenderTarget();
static void CleanupRenderTarget();
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED) return 0;
            g_ResizeWidth  = (UINT)LOWORD(lParam);
            g_ResizeHeight = (UINT)HIWORD(lParam);
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ---- Cyberpunk / dark theme -----------------------------------------
static void applyTheme() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding    = 6.0f;
    s.ChildRounding     = 4.0f;
    s.FrameRounding     = 4.0f;
    s.GrabRounding      = 4.0f;
    s.TabRounding       = 4.0f;
    s.ScrollbarRounding = 6.0f;
    s.PopupRounding     = 4.0f;
    s.WindowPadding     = { 12, 12 };
    s.FramePadding      = {  8,  5 };
    s.ItemSpacing       = {  8,  6 };
    s.IndentSpacing     = 18.0f;
    s.ScrollbarSize     = 12.0f;
    s.WindowBorderSize  = 1.0f;
    s.FrameBorderSize   = 0.0f;
    s.TabBorderSize     = 0.0f;

    // Deep dark cyberpunk palette
    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg]             = ImVec4(0.07f, 0.08f, 0.10f, 1.00f);
    c[ImGuiCol_ChildBg]              = ImVec4(0.05f, 0.06f, 0.08f, 1.00f);
    c[ImGuiCol_PopupBg]              = ImVec4(0.08f, 0.09f, 0.12f, 0.97f);
    c[ImGuiCol_Border]               = ImVec4(0.18f, 0.22f, 0.30f, 1.00f);
    c[ImGuiCol_BorderShadow]         = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    c[ImGuiCol_FrameBg]              = ImVec4(0.11f, 0.13f, 0.17f, 1.00f);
    c[ImGuiCol_FrameBgHovered]       = ImVec4(0.16f, 0.20f, 0.28f, 1.00f);
    c[ImGuiCol_FrameBgActive]        = ImVec4(0.20f, 0.26f, 0.36f, 1.00f);
    c[ImGuiCol_TitleBg]              = ImVec4(0.05f, 0.06f, 0.08f, 1.00f);
    c[ImGuiCol_TitleBgActive]        = ImVec4(0.08f, 0.12f, 0.20f, 1.00f);
    c[ImGuiCol_TitleBgCollapsed]     = ImVec4(0.05f, 0.06f, 0.08f, 0.80f);
    c[ImGuiCol_MenuBarBg]            = ImVec4(0.05f, 0.06f, 0.08f, 1.00f);
    c[ImGuiCol_ScrollbarBg]          = ImVec4(0.04f, 0.05f, 0.06f, 0.60f);
    c[ImGuiCol_ScrollbarGrab]        = ImVec4(0.20f, 0.30f, 0.50f, 0.80f);
    c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.28f, 0.42f, 0.68f, 0.90f);
    c[ImGuiCol_ScrollbarGrabActive]  = ImVec4(0.35f, 0.55f, 0.85f, 1.00f);
    c[ImGuiCol_CheckMark]            = ImVec4(0.26f, 0.78f, 1.00f, 1.00f);
    c[ImGuiCol_SliderGrab]           = ImVec4(0.26f, 0.78f, 1.00f, 0.80f);
    c[ImGuiCol_SliderGrabActive]     = ImVec4(0.36f, 0.88f, 1.00f, 1.00f);
    c[ImGuiCol_Button]               = ImVec4(0.14f, 0.20f, 0.32f, 1.00f);
    c[ImGuiCol_ButtonHovered]        = ImVec4(0.20f, 0.42f, 0.72f, 1.00f);
    c[ImGuiCol_ButtonActive]         = ImVec4(0.26f, 0.55f, 0.92f, 1.00f);
    c[ImGuiCol_Header]               = ImVec4(0.14f, 0.24f, 0.40f, 1.00f);
    c[ImGuiCol_HeaderHovered]        = ImVec4(0.20f, 0.38f, 0.62f, 1.00f);
    c[ImGuiCol_HeaderActive]         = ImVec4(0.26f, 0.50f, 0.80f, 1.00f);
    c[ImGuiCol_Separator]            = ImVec4(0.18f, 0.22f, 0.30f, 1.00f);
    c[ImGuiCol_SeparatorHovered]     = ImVec4(0.26f, 0.55f, 0.88f, 0.80f);
    c[ImGuiCol_SeparatorActive]      = ImVec4(0.26f, 0.68f, 1.00f, 1.00f);
    c[ImGuiCol_ResizeGrip]           = ImVec4(0.26f, 0.78f, 1.00f, 0.20f);
    c[ImGuiCol_ResizeGripHovered]    = ImVec4(0.26f, 0.78f, 1.00f, 0.60f);
    c[ImGuiCol_ResizeGripActive]     = ImVec4(0.26f, 0.78f, 1.00f, 0.90f);
    c[ImGuiCol_Tab]                  = ImVec4(0.10f, 0.14f, 0.22f, 1.00f);
    c[ImGuiCol_TabHovered]           = ImVec4(0.20f, 0.42f, 0.72f, 1.00f);
    c[ImGuiCol_TabSelected]          = ImVec4(0.16f, 0.36f, 0.64f, 1.00f);
    c[ImGuiCol_TabSelectedOverline]  = ImVec4(0.26f, 0.78f, 1.00f, 1.00f);
    c[ImGuiCol_TabDimmed]            = ImVec4(0.07f, 0.10f, 0.16f, 1.00f);
    c[ImGuiCol_TabDimmedSelected]    = ImVec4(0.12f, 0.24f, 0.42f, 1.00f);
    c[ImGuiCol_PlotLines]            = ImVec4(0.26f, 0.78f, 1.00f, 1.00f);
    c[ImGuiCol_PlotHistogram]        = ImVec4(0.26f, 0.68f, 0.90f, 1.00f);
    c[ImGuiCol_TableHeaderBg]        = ImVec4(0.10f, 0.14f, 0.22f, 1.00f);
    c[ImGuiCol_TableBorderStrong]    = ImVec4(0.18f, 0.26f, 0.40f, 1.00f);
    c[ImGuiCol_TableBorderLight]     = ImVec4(0.12f, 0.18f, 0.28f, 1.00f);
    c[ImGuiCol_TextSelectedBg]       = ImVec4(0.26f, 0.55f, 0.88f, 0.35f);
    c[ImGuiCol_NavCursor]            = ImVec4(0.26f, 0.78f, 1.00f, 1.00f);
    c[ImGuiCol_Text]                 = ImVec4(0.90f, 0.92f, 0.96f, 1.00f);
    c[ImGuiCol_TextDisabled]         = ImVec4(0.40f, 0.46f, 0.56f, 1.00f);
    c[ImGuiCol_DragDropTarget]       = ImVec4(0.26f, 0.78f, 1.00f, 0.90f);
    c[ImGuiCol_ModalWindowDimBg]     = ImVec4(0.00f, 0.00f, 0.00f, 0.60f);
}

// ---- Log entry colour map -------------------------------------------
static ImVec4 logColor(LogLevel lvl) {
    switch (lvl) {
        case LogLevel::Ok:     return { 0.30f, 1.00f, 0.55f, 1.0f }; // bright green
        case LogLevel::Warn:   return { 1.00f, 0.80f, 0.10f, 1.0f }; // amber
        case LogLevel::Danger: return { 1.00f, 0.28f, 0.28f, 1.0f }; // red
        case LogLevel::Dim:    return { 0.45f, 0.50f, 0.58f, 1.0f }; // grey
        case LogLevel::Header: return { 0.26f, 0.78f, 1.00f, 1.0f }; // cyan
        default:               return { 0.80f, 0.84f, 0.92f, 1.0f }; // near-white
    }
}

static const char* logPrefix(LogLevel lvl) {
    switch (lvl) {
        case LogLevel::Ok:     return "  [+] ";
        case LogLevel::Warn:   return "  [!] ";
        case LogLevel::Danger: return "  [x] ";
        case LogLevel::Dim:    return "      ";
        case LogLevel::Header: return " ==== ";
        default:               return "  [*] ";
    }
}

// ---- Navigation items -----------------------------------------------
struct NavItem {
    const char* icon;
    const char* label;
    const char* desc;
};

static const NavItem kNavItems[] = {
    { ">>", "Smart Auto-Scan",   "Auto-detect launcher + full analysis" },
    { "**", "Memory Scan v2",    "Multi-threaded, XOR, confidence scores" },
    { "JV", "JVM Flags",         "Detect agent injection + suspicious flags" },
    { "DL", "Module Scan",       "Injected DLL detection in java process" },
    { "JR", "Enhanced JAR",      "Bytecode, obfuscation, mixin, whitelist" },
    { "MO", "Mods Folder",       "Classic static JAR analysis" },
    { "MC", "Macro Scan",        "198M/Zenith: process, window, registry, exe" },
    { "FS", "Extended Forensics","Logs, configs, temp, clipboard" },
    { "SY", "System Forensics",  "Prefetch, autorun, tasks, hosts file" },
    { "NW", "Network Scan",      "Active connections to known cheat auth servers" },
    { "WC", "Window Cloak Scan", "Windows hidden from screen capture" },
};
static const int kNavCount = (int)(sizeof(kNavItems) / sizeof(kNavItems[0]));

// ---- Main render function -------------------------------------------
// Call this every frame from the message loop. Takes scan callbacks
// indexed to match kNavItems.
static void RenderFrame(
    const std::function<void(int)>& launchScan,
    bool& appRunning)
{
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 display = io.DisplaySize;

    // Full-screen invisible host window
    ImGui::SetNextWindowPos({ 0, 0 });
    ImGui::SetNextWindowSize(display);
    ImGui::Begin("##host", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNav);

    const float sidebarW  = 210.0f;
    const float statusBarH = 28.0f;
    const float mainW     = display.x - sidebarW;
    const float mainH     = display.y - statusBarH;

    // ---- Sidebar ---------------------------------------------------
    ImGui::SetNextWindowPos({ 0, 0 });
    ImGui::SetNextWindowSize({ sidebarW, mainH });
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.05f, 0.06f, 0.09f, 1.0f));
    ImGui::BeginChild("##sidebar", { sidebarW, mainH }, ImGuiChildFlags_Borders);

    // Logo
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.26f, 0.78f, 1.00f, 1.0f));
    ImGui::SetCursorPosX(12.0f);
    ImGui::SetCursorPosY(14.0f);
    ImGui::Text("SS TOOL  v2.0");
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.40f, 0.46f, 0.56f, 1.0f));
    ImGui::SetCursorPosX(14.0f);
    ImGui::Text("by lvstrng");
    ImGui::PopStyleColor();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.40f, 0.50f, 0.60f, 1.0f));
    ImGui::Text("  SCAN MODULES");
    ImGui::PopStyleColor();
    ImGui::Spacing();

    for (int i = 0; i < kNavCount; i++) {
        const auto& nav = kNavItems[i];
        bool selected = (g_state.selectedNav == i);

        // Highlight row
        if (selected) {
            ImGui::PushStyleColor(ImGuiCol_Header,        ImVec4(0.14f, 0.28f, 0.50f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0.18f, 0.34f, 0.58f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_HeaderActive,  ImVec4(0.22f, 0.40f, 0.66f, 1.0f));
        }

        ImGui::PushID(i);
        bool clicked = ImGui::Selectable(
            ("  " + std::string(nav.label)).c_str(),
            selected,
            ImGuiSelectableFlags_None,
            { sidebarW - 10.0f, 28.0f }
        );
        ImGui::PopID();

        if (selected)
            ImGui::PopStyleColor(3);

        if (clicked) g_state.selectedNav = i;
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Elevation badge
    bool elevated = util::isRunningElevated();
    if (elevated) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.30f, 1.00f, 0.55f, 1.0f));
        ImGui::Text("  [+] Administrator");
        ImGui::PopStyleColor();
    } else {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.00f, 0.80f, 0.10f, 1.0f));
        ImGui::Text("  [!] Standard User");
        ImGui::PopStyleColor();
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.40f, 0.46f, 0.56f, 1.0f));
        ImGui::Text("  Re-run as Admin");
        ImGui::Text("  for best results");
        ImGui::PopStyleColor();
    }

    ImGui::EndChild();
    ImGui::PopStyleColor(); // ChildBg

    // ---- Main panel ------------------------------------------------
    ImGui::SetCursorPos({ sidebarW, 0 });
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.07f, 0.08f, 0.10f, 1.0f));
    ImGui::BeginChild("##main", { mainW, mainH }, ImGuiChildFlags_None);

    // Header bar
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.09f, 0.11f, 0.16f, 1.0f));
    ImGui::BeginChild("##header", { mainW, 52.0f }, ImGuiChildFlags_Borders);

    int nav = g_state.selectedNav;
    ImGui::SetCursorPos({ 14.0f, 8.0f });
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.90f, 0.92f, 0.96f, 1.0f));
    ImGui::Text("%s", kNavItems[nav].label);
    ImGui::PopStyleColor();

    ImGui::SetCursorPos({ 14.0f, 28.0f });
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.40f, 0.50f, 0.60f, 1.0f));
    ImGui::Text("%s", kNavItems[nav].desc);
    ImGui::PopStyleColor();

    // Run button (top-right of header)
    bool isScanning = g_state.scanning.load();
    float btnW = 110.0f;
    ImGui::SetCursorPos({ mainW - btnW - 12.0f, 12.0f });
    if (isScanning) {
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.30f, 0.14f, 0.14f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.40f, 0.18f, 0.18f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.50f, 0.22f, 0.22f, 1.0f));
        ImGui::Button("  Scanning...  ", { btnW, 28.0f });
        ImGui::PopStyleColor(3);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.14f, 0.28f, 0.50f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.42f, 0.72f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.26f, 0.55f, 0.92f, 1.0f));
        if (ImGui::Button("  Run Scan  ", { btnW, 28.0f })) {
            if (!isScanning) {
                g_state.clearLog();
                g_state.scanDone = false;
                g_state.lastScanSummary.clear();
                launchScan(g_state.selectedNav);
            }
        }
        ImGui::PopStyleColor(3);
    }

    // Clear log button
    ImGui::SetCursorPos({ mainW - btnW * 2 - 18.0f, 12.0f });
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.12f, 0.14f, 0.20f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.16f, 0.20f, 0.30f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.20f, 0.26f, 0.40f, 1.0f));
    if (ImGui::Button("  Clear  ", { 80.0f, 28.0f })) g_state.clearLog();
    ImGui::PopStyleColor(3);

    ImGui::EndChild();
    ImGui::PopStyleColor();

    // Progress bar (only visible during scan)
    if (isScanning) {
        float pct = g_state.progressPct.load() / 100.0f;
        std::string plabel;
        { std::lock_guard<std::mutex> lk(g_state.progressMutex); plabel = g_state.progressLabel; }
        ImGui::SetCursorPos({ 0, 52.0f });
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.20f, 0.58f, 1.00f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg,       ImVec4(0.10f, 0.12f, 0.18f, 1.0f));
        ImGui::ProgressBar(pct, { mainW, 18.0f }, plabel.c_str());
        ImGui::PopStyleColor(2);
    }

    float logOffsetY = isScanning ? 70.0f : 52.0f;
    float logH = mainH - logOffsetY;

    // Result summary banner (shown after scan completes)
    if (g_state.scanDone.load() && !g_state.lastScanSummary.empty()) {
        ImVec4 bannerColor = g_state.lastWasClean
            ? ImVec4(0.08f, 0.18f, 0.10f, 1.0f)
            : ImVec4(0.22f, 0.08f, 0.08f, 1.0f);
        ImVec4 textColor = g_state.lastWasClean
            ? ImVec4(0.30f, 1.00f, 0.55f, 1.0f)
            : ImVec4(1.00f, 0.30f, 0.30f, 1.0f);

        ImGui::SetCursorPos({ 0, logOffsetY });
        ImGui::PushStyleColor(ImGuiCol_ChildBg, bannerColor);
        ImGui::BeginChild("##banner", { mainW, 30.0f }, ImGuiChildFlags_None);
        ImGui::SetCursorPos({ 12.0f, 6.0f });
        ImGui::PushStyleColor(ImGuiCol_Text, textColor);
        ImGui::Text("%s", g_state.lastScanSummary.c_str());
        ImGui::PopStyleColor();
        ImGui::EndChild();
        ImGui::PopStyleColor();

        logOffsetY += 30.0f;
        logH -= 30.0f;
    }

    // ---- Scrollable log panel -------------------------------------
    ImGui::SetCursorPos({ 0, logOffsetY });
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.05f, 0.06f, 0.08f, 1.0f));
    ImGui::BeginChild("##log", { mainW, logH }, ImGuiChildFlags_None,
        ImGuiWindowFlags_HorizontalScrollbar);

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, { 4.0f, 2.0f });
    {
        std::lock_guard<std::mutex> lk(g_state.logMutex);
        for (const auto& entry : g_state.log) {
            ImVec4 col = logColor(entry.level);

            if (entry.level == LogLevel::Header) {
                ImGui::Spacing();
                ImGui::PushStyleColor(ImGuiCol_Text, col);
                ImGui::Separator();
                ImGui::Text("  %s", entry.text.c_str());
                ImGui::Separator();
                ImGui::PopStyleColor();
                ImGui::Spacing();
            } else {
                ImGui::PushStyleColor(ImGuiCol_Text, col);
                ImGui::TextUnformatted((logPrefix(entry.level) + entry.text).c_str());
                ImGui::PopStyleColor();
            }
        }

        if (g_state.logScrollToBottom) {
            ImGui::SetScrollHereY(1.0f);
            g_state.logScrollToBottom = false;
        }
    }
    ImGui::PopStyleVar();
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::EndChild(); // main
    ImGui::PopStyleColor();

    // ---- Status bar -----------------------------------------------
    ImGui::SetCursorPos({ 0, mainH });
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.05f, 0.07f, 0.12f, 1.0f));
    ImGui::BeginChild("##statusbar", { display.x, statusBarH }, ImGuiChildFlags_Borders);
    ImGui::SetCursorPos({ 12.0f, 6.0f });

    if (isScanning) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.26f, 0.78f, 1.00f, 1.0f));
        // Animated dots
        static int dotTick = 0;
        dotTick++;
        std::string dots = std::string(1 + (dotTick / 15) % 3, '.');
        std::string slbl;
        { std::lock_guard<std::mutex> lk(g_state.progressMutex); slbl = g_state.progressLabel; }
        ImGui::Text("Scanning %s  %s  %d%%",
            g_state.currentScanName.c_str(), dots.c_str(), g_state.progressPct.load());
        ImGui::PopStyleColor();
    } else {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.40f, 0.50f, 0.60f, 1.0f));
        ImGui::Text("Ready  |  SS Tool v2.0  |  Read-only scans");
        ImGui::PopStyleColor();
    }

    // Framerate (right side)
    ImGui::SameLine(display.x - 110.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.28f, 0.35f, 0.45f, 1.0f));
    ImGui::Text("%.0f fps", io.Framerate);
    ImGui::PopStyleColor();

    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::End(); // host
}

// ---- DX11 helpers ---------------------------------------------------
static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[] = {
        D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
        featureLevelArray, 2, D3D11_SDK_VERSION,
        &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED)
        res = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags,
            featureLevelArray, 2, D3D11_SDK_VERSION,
            &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK) return false;
    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain)         { g_pSwapChain->Release();         g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext)  { g_pd3dDeviceContext->Release();  g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)         { g_pd3dDevice->Release();         g_pd3dDevice = nullptr; }
}

static void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

static void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

// ---- Entry point ----------------------------------------------------
// Call this from WinMain / main after setting up the scan callbacks.
static int Run(const std::function<void(int)>& launchScan) {
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SSTool";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(
        0, wc.lpszClassName, L"SS Tool v2.0  --  Minecraft Screenshare Detection",
        WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800,
        nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    // Disable .ini so the layout stays consistent across runs
    io.IniFilename = nullptr;

    applyTheme();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    bool appRunning = true;
    ImVec4 clearColor = { 0.07f, 0.08f, 0.10f, 1.0f };

    // Welcome message
    g_state.addLog(LogLevel::Header, "SS Tool v2.0  --  Ready");
    g_state.addLog(LogLevel::Info,   "Select a scan module from the sidebar, then click Run Scan.");
    g_state.addLog(LogLevel::Dim,    "All scans are read-only -- nothing is modified on this PC.");

    while (appRunning) {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) appRunning = false;
        }
        if (!appRunning) break;

        if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED) {
            Sleep(10); continue;
        }
        g_SwapChainOccluded = false;

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        RenderFrame(launchScan, appRunning);

        ImGui::Render();
        const float cc[4] = { clearColor.x, clearColor.y, clearColor.z, clearColor.w };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, cc);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        HRESULT hr = g_pSwapChain->Present(1, 0);
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

} // namespace guiapp
