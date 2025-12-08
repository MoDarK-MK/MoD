# 🚀 MoD v4.0.0 - Release Notes

**Release Date:** December 8, 2025

## 📋 Overview

Major UI/UX improvements and accessibility enhancements. Version 4 introduces comprehensive sizing optimization, dynamic UI scaling, improved theme system, and better layout organization.

---

## ✨ Major Features

### 🎨 **Theme System Enhancements**

- Comprehensive audit and fixes for all 14 themes
- Improved color contrast for better accessibility
- Enhanced primary, secondary, and accent colors across all themes
- Theme validation and testing suite

### 📏 **UI Size Selector**

- New **Settings → Display Settings** option
- Three sizing modes: **Small** (85%), **Medium** (100%), **Large** (115%)
- Dynamic scaling of all UI elements:
  - Font sizes (9-16pt range)
  - Button and input heights (32-40px)
  - Padding and spacing (4-12px)
  - Tab bar sizing

### 🎯 **Vulnerability Scanner Layout Optimization**

- Restructured scanner checklist from vertical to **2-column grid layout**
- Improved space efficiency on screen
- Better visual organization of 14 vulnerability scanners:
  - XSS Injection
  - SQL Injection
  - Remote Code Execution
  - Command Injection
  - SSRF
  - CSRF
  - XXE
  - File Upload
  - API Security
  - WebSocket Security
  - GraphQL Testing
  - SSTI
  - LDAP Injection
  - OAuth2/SAML

### 📐 **Comprehensive Size Optimization**

Applied consistent sizing pattern across all GUI tabs:

| Element            | Before             | After             |
| ------------------ | ------------------ | ----------------- |
| **Main Margins**   | 30px / 20px        | 15px              |
| **Spacing**        | 20px / 15px        | 12px / 10px / 8px |
| **Button Heights** | 50px / 45px / 40px | 36px              |
| **Label Heights**  | 40px / 36px        | 32px              |
| **Input Heights**  | 40px / 36px        | 36px / 32px       |
| **Progress Bars**  | 30px               | 22px              |
| **Font Sizes**     | 16pt               | 14pt              |

### 🔧 **Optimized Tabs**

- ✅ Scan Tab
- ✅ Results Tab
- ✅ CORS Tester Tab
- ✅ CVE Scanner Tab
- ✅ GraphQL Tab
- ✅ Help & Documentation Tab
- ✅ Authentication Tab
- ✅ Request Monitor Tab
- ✅ Advanced Settings Tab
- ✅ WebSocket Tab
- ✅ Subdomain Tab
- ✅ Wayback Tab
- ✅ WAF Bypass Tab
- ✅ Main Window & Dialogs

### 📚 **Help Tab Redesign**

- Fixed readability issues with dark theme
- Improved background color (#1e1e1e)
- Enhanced text colors (#e0e0e0)
- Professional CSS styling for:
  - Headers and sections
  - Code blocks (pre/code)
  - Links and emphasis
  - Lists and formatting
- Better line height and spacing

### 🎯 **GUI Settings Tab Expansion**

- Settings tab now contains:
  - **General Settings**: Theme selection, display options
  - **AI Integration**: Provider, model, API key configuration
  - **Scanner Config**: Verification settings, timeouts, retries, worker threads
  - **Advanced Options**: SSL verification, redirect following

---

## 🔄 Technical Improvements

### Settings Management

- Added `ui_size_changed` signal in SettingsTab
- New `on_ui_size_changed()` handler
- Settings dictionary now includes `ui_size` field
- Persistent UI size preference storage

### Layout System

- Converted ScanTab vulnerability scanner to GridLayout
- Consistent QGridLayout usage across scanner selections
- Improved responsive design with proper spacing

### Theme Application

- New `apply_ui_size()` method in MainWindow
- Dynamic font and spacing calculation based on size mode
- Real-time UI updates without restart
- Stylesheet combination for theme + size scaling

### Accessibility

- Reduced overall visual clutter
- Improved element spacing for clarity
- Better touch target sizes (minimum 36px for buttons)
- Consistent spacing ratios for professional appearance

---

## 🐛 Bug Fixes

### Help Tab

- Fixed white background rendering issue
- Corrected text color visibility
- Improved HTML content styling
- Enhanced readability across all sections

### UI Consistency

- Fixed inconsistent button heights across tabs
- Standardized input field sizing
- Unified margin and padding conventions
- Proper label height consistency

---

## 📦 What's Changed

### Files Modified (15+ tabs optimized)

```
gui/
  ├── settings_tab.py (UI Size selector added)
  ├── scan_tab.py (Grid layout for scanners)
  ├── results_tab.py (Size optimization)
  ├── cors_tab.py (Full optimization)
  ├── cve_scanner_tab.py (Button/input sizing)
  ├── graphql_tab.py (Compact layout)
  ├── help_tab.py (Dark theme, CSS styling)
  ├── auth_tab.py (Margin reduction)
  ├── request_monitor_tab.py (Layout optimization)
  ├── advanced_settings_tab.py (Size reduction)
  ├── main_window.py (UI size handler)
  ├── websocket_tab.py (Previously optimized)
  ├── subdomain_tab.py (Previously optimized)
  ├── wayback_tab.py (Previously optimized)
  └── waf_bypass_tab.py (Previously optimized)
```

### Core Changes

- 36+ individual file edits
- Consistent sizing patterns applied throughout
- New signal-slot connections for UI scaling
- Enhanced CSS styling system

---

## 🎯 Performance Notes

- ✅ No performance degradation
- ✅ Faster UI rendering with optimized layouts
- ✅ Reduced memory footprint from streamlined design
- ✅ Theme switching remains instantaneous

---

## 📖 How to Use New Features

### Changing UI Size

1. Navigate to **Settings Tab**
2. Go to **Display Settings** section
3. Select desired size: **Small**, **Medium**, or **Large**
4. Changes apply immediately
5. Size preference is saved

### Viewing Vulnerability Scanners

1. Go to **Scan Tab**
2. Scanner Selection now shows checklist in **2-column layout**
3. Easy to select/deselect all scanners
4. Cleaner interface with better space utilization

---

## 🔮 Future Roadmap

- Persistent UI size storage in configuration
- Custom size multiplier settings
- Per-tab size preferences
- Touch-optimized mode detection
- Dark/Light mode auto-detection

---

## 📞 Support

For issues or feature requests, visit: https://github.com/MoDarK-MK/MoD

---

## 📝 Version History

| Version   | Date        | Notes                                         |
| --------- | ----------- | --------------------------------------------- |
| **4.0.0** | Dec 8, 2025 | Major UI/UX improvements, sizing optimization |
| 3.0.0     | -           | Previous version                              |
| 2.0.0     | -           | Previous version                              |
| 1.0.0     | -           | Initial release                               |

---

**Built with ❤️ by MoDarK-MK**
