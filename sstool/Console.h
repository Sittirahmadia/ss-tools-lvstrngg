#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

// =====================================================================
//  Console.h  --  Output layer
//
//  Two modes, selected by whether GUI_MODE is defined before this file
//  is included:
//    - Console mode (default): ANSI-colored stdout, spinners, progress
//      bars drawn with \r carriage returns.
//    - GUI mode (GUI_MODE defined, set by main.cpp before including
//      GuiApp.h/Console.h): every call routes to guiapp::g_state's log
//      buffer instead, so the same scan code renders inside the Dear
//      ImGui window without any changes to the scan modules themselves.
//
//  Every helper below has exactly ONE definition with an #ifdef/#else
//  inside it -- never two separate function bodies -- to avoid the kind
//  of duplicate-definition drift that broke this file previously.
// =====================================================================

#ifdef GUI_MODE
namespace guiapp {
    struct AppState;
    extern AppState g_state;
    void logInfo   (const std::string& s);
    void logOk     (const std::string& s);
    void logWarn   (const std::string& s);
    void logDanger (const std::string& s);
    void logDim    (const std::string& s);
    void logHeader (const std::string& s);
}
#endif

namespace con {

    enum class Color {
        Default  = -1,
        Gray     = FOREGROUND_INTENSITY,
        DarkGray = 8,
        Red      = FOREGROUND_RED | FOREGROUND_INTENSITY,
        Green    = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        Yellow   = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        Cyan     = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        Magenta  = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        Blue     = FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        White    = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    };

    inline HANDLE hStdOut() {
        static HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        return h;
    }

    inline void set(Color c) {
#ifndef GUI_MODE
        if (hStdOut() == INVALID_HANDLE_VALUE || c == Color::Default) return;
        SetConsoleTextAttribute(hStdOut(), static_cast<WORD>(c));
#else
        (void)c;
#endif
    }

    inline void reset() { set(Color::White); }

    // ---- basic line printers ------------------------------------------
    inline void ok(const std::string& text) {
#ifdef GUI_MODE
        guiapp::logOk(text);
#else
        set(Color::Green); std::cout << "  [+] "; reset(); std::cout << text << "\n";
#endif
    }

    inline void warn(const std::string& text) {
#ifdef GUI_MODE
        guiapp::logWarn(text);
#else
        set(Color::Yellow); std::cout << "  [!] "; reset(); std::cout << text << "\n";
#endif
    }

    inline void bad(const std::string& text) {
#ifdef GUI_MODE
        guiapp::logDanger(text);
#else
        set(Color::Red); std::cout << "  [x] "; reset(); std::cout << text << "\n";
#endif
    }

    inline void info(const std::string& text) {
#ifdef GUI_MODE
        guiapp::logInfo(text);
#else
        set(Color::Cyan); std::cout << "  [*] "; reset(); std::cout << text << "\n";
#endif
    }

    inline void dim(const std::string& text) {
#ifdef GUI_MODE
        guiapp::logDim(text);
#else
        set(Color::Gray); std::cout << "      " << text; reset(); std::cout << "\n";
#endif
    }

    // Unified finding renderer: every scan module shares util::Severity,
    // so results render through one call instead of hand-rolled chains.
    template <typename SeverityT>
    inline void finding(SeverityT severity, const std::string& text) {
        switch (static_cast<int>(severity)) {
            case 2: bad(text);  break; // Danger
            case 1: warn(text); break; // Warning
            default: info(text); break; // Info
        }
    }

    template <typename SeverityT>
    inline std::string badge(SeverityT severity) {
        switch (static_cast<int>(severity)) {
            case 2: return "[DANGER]";
            case 1: return "[WARN]";
            default: return "[INFO]";
        }
    }

    // ---- structural printers -------------------------------------------
    inline void divider(char ch = '-', int width = 60, Color c = Color::DarkGray) {
#ifndef GUI_MODE
        set(c); std::cout << std::string(width, ch) << "\n"; reset();
#else
        (void)ch; (void)width; (void)c;
#endif
    }

    inline void header(const std::string& text, Color c = Color::Cyan) {
#ifdef GUI_MODE
        (void)c;
        guiapp::logHeader(text);
#else
        std::cout << "\n";
        divider('=', 60, c);
        set(c);
        int pad = (58 - (int)text.size()) / 2; if (pad < 0) pad = 0;
        std::cout << "  " << std::string(pad, ' ') << text << "\n";
        divider('=', 60, c);
        reset();
#endif
    }

    inline void subheader(const std::string& text, Color c = Color::Cyan) {
#ifdef GUI_MODE
        (void)c;
        guiapp::logInfo(">> " + text);
#else
        std::cout << "\n";
        set(c); std::cout << "  >> " << text << "\n";
        divider('-', 60, c);
        reset();
#endif
    }

    inline void step(int current, int total, const std::string& desc) {
#ifdef GUI_MODE
        guiapp::logHeader("Step " + std::to_string(current) + "/" + std::to_string(total) + "  " + desc);
        if (total > 0) guiapp::g_state.setProgress((current - 1) * 100 / total, desc);
#else
        std::cout << "\n";
        divider('-', 60, Color::DarkGray);
        set(Color::Cyan);  std::cout << "  Step " << current << "/" << total << "  ";
        set(Color::White); std::cout << desc << "\n";
        divider('-', 60, Color::DarkGray);
        reset();
#endif
    }

    inline void menuItem(int n, const std::string& text, Color c = Color::White) {
#ifdef GUI_MODE
        (void)n; (void)c;
        guiapp::logInfo(std::to_string(n) + ". " + text);
#else
        set(Color::Cyan); std::cout << "    [" << n << "] ";
        set(c); std::cout << text << "\n";
        reset();
#endif
    }

    inline void prompt(const std::string& text) {
#ifdef GUI_MODE
        guiapp::logInfo("> " + text);
#else
        set(Color::Yellow); std::cout << "\n  > " << text; reset(); std::cout << " ";
#endif
    }

    // ---- progress / spinner --------------------------------------------
    inline void spinnerTick(const std::string& msg) {
#ifdef GUI_MODE
        guiapp::g_state.setProgress(guiapp::g_state.progressPct.load(), msg);
#else
        static int frame = 0;
        static const char* frames[] = { "|", "/", "-", "\\" };
        set(Color::Cyan);
        std::cout << "\r  " << frames[frame++ % 4] << "  ";
        reset();
        std::cout << msg << "   " << std::flush;
#endif
    }

    inline void spinnerClear() {
#ifndef GUI_MODE
        std::cout << "\r" << std::string(70, ' ') << "\r" << std::flush;
#endif
    }

    inline void progressBar(int done, int total, int width = 40) {
#ifdef GUI_MODE
        if (total > 0)
            guiapp::g_state.setProgress(done * 100 / total,
                std::to_string(done) + "/" + std::to_string(total));
#else
        if (total == 0) return;
        int filled = (done * width) / total;
        int pct = (done * 100) / total;
        set(Color::Cyan); std::cout << "\r  [";
        set(Color::Green); std::cout << std::string(filled, '=');
        if (filled < width) {
            std::cout << ">";
            set(Color::DarkGray);
            std::cout << std::string(width - filled - 1, ' ');
        }
        set(Color::Cyan); std::cout << "] ";
        set(Color::White); std::cout << std::setw(3) << pct << "% (" << done << "/" << total << ")   " << std::flush;
        reset();
#endif
    }

    // ---- summary / banner ----------------------------------------------
    inline void resultSummary(bool clean, int hits, const std::string& context) {
#ifdef GUI_MODE
        guiapp::g_state.lastWasClean = clean;
        guiapp::g_state.lastHitCount = hits;
        guiapp::g_state.lastScanSummary = clean
            ? "CLEAN -- No " + context + " found."
            : "FLAGGED -- " + std::to_string(hits) + " " + context + " detected.";
        guiapp::g_state.setProgress(100, "Done");
        guiapp::g_state.scanDone = true;
        guiapp::g_state.scanning = false;
#else
        std::cout << "\n";
        if (clean) {
            divider('=', 60, Color::Green);
            set(Color::Green);
            std::cout << "  RESULT:  CLEAN -- No " << context << " found.\n";
            divider('=', 60, Color::Green);
        } else {
            divider('=', 60, Color::Red);
            set(Color::Red);
            std::cout << "  RESULT:  FLAGGED -- " << hits << " " << context << " detected.\n";
            divider('=', 60, Color::Red);
        }
        reset();
#endif
    }

    // Bordered box of centered lines -- startup banner, exit banner, etc.
    inline void box(const std::vector<std::string>& lines, int width = 60, Color c = Color::Cyan) {
#ifdef GUI_MODE
        (void)width; (void)c;
        for (const auto& l : lines) if (!l.empty()) guiapp::logHeader(l);
#else
        std::cout << "\n";
        set(c);
        std::cout << "  +" << std::string(width - 2, '-') << "+\n";
        for (const auto& l : lines) {
            int pad = (width - 2 - (int)l.size());
            int left = pad / 2;
            int right = pad - left;
            if (left < 0) left = 0;
            if (right < 0) right = 0;
            std::cout << "  |" << std::string(left, ' ') << l << std::string(right, ' ') << "|\n";
        }
        std::cout << "  +" << std::string(width - 2, '-') << "+\n";
        reset();
#endif
    }

    // Single labeled callout, e.g. "[ Note ] some text"
    inline void box(const std::string& label, const std::string& text, Color c = Color::Yellow) {
#ifdef GUI_MODE
        (void)c;
        guiapp::logInfo("[" + label + "] " + text);
#else
        set(c); std::cout << "  [ " << label << " ] "; reset();
        std::cout << text << "\n";
#endif
    }

    // "  Key ......... value" -- aligned status line for banners.
    inline void statusLine(const std::string& key, const std::string& value,
                           Color valueColor = Color::White, int keyWidth = 18) {
#ifdef GUI_MODE
        (void)valueColor; (void)keyWidth;
        guiapp::logDim(key + ": " + value);
#else
        set(Color::Gray);
        std::cout << "    " << key;
        int pad = keyWidth - (int)key.size();
        if (pad > 0) std::cout << std::string(pad, '.');
        std::cout << " ";
        set(valueColor);
        std::cout << value << "\n";
        reset();
#endif
    }

} // namespace con
