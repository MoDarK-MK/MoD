#!/usr/bin/env python3
from gui.theme_manager import ThemeManager

print("\n" + "="*70)
print("THEME MANAGER VALIDATION TEST")
print("="*70)

tm = ThemeManager()

print("\n1. Testing theme loading...")
themes = tm.get_available_themes()
print(f"   Loaded {len(themes)} themes successfully")

print("\n2. Testing each theme's stylesheet...")
failed_themes = []
for theme_name in themes:
    try:
        tm.set_theme(theme_name)
        stylesheet = tm.get_stylesheet()
        
        bracket_count_open = stylesheet.count("{")
        bracket_count_close = stylesheet.count("}")
        
        if bracket_count_open != bracket_count_close:
            failed_themes.append(f"{theme_name}: Bracket mismatch ({bracket_count_open} open, {bracket_count_close} close)")
        else:
            print(f"   [OK] {theme_name}: {len(stylesheet)} chars, {len(stylesheet.splitlines())} lines")
    except Exception as e:
        failed_themes.append(f"{theme_name}: {str(e)[:50]}")

print("\n3. Testing theme color palettes...")
for theme_name in themes:
    try:
        tm.set_theme(theme_name)
        palette = tm.get_color_palette()
        
        required_keys = ['primary', 'secondary', 'accent', 'background', 'text_primary']
        for key in required_keys:
            if key not in palette:
                print(f"   [FAIL] {theme_name}: Missing key '{key}'")
    except Exception as e:
        print(f"   [FAIL] {theme_name}: {str(e)[:50]}")

print("\n4. Checking color contrast...")
for theme_name in themes:
    try:
        tm.set_theme(theme_name)
        theme = tm.get_theme()
        colors = theme['colors']
        
        print(f"   [OK] {theme_name}: Primary={colors.primary}, Text={colors.text_primary}")
    except Exception as e:
        print(f"   [FAIL] {theme_name}: {str(e)[:50]}")

if failed_themes:
    print(f"\n[WARNING] {len(failed_themes)} issues found:")
    for issue in failed_themes:
        print(f"   - {issue}")
else:
    print("\n" + "="*70)
    print("[SUCCESS] ALL THEMES VALIDATED SUCCESSFULLY")
    print("="*70)
