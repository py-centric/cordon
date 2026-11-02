import 'package:flutter/material.dart';

/// The three constitutional theme modes that must stay at parity.
enum CordonThemePreset {
  light,
  dark,
  highContrast;
}

/// Builds the [ThemeData] for the given [preset].
///
/// All three presets enforce the constitutional 48x48dp minimum touch target
/// and Material 3 semantics; High Contrast targets >= 7:1 contrast with a pure
/// black scaffold and yellow primary.
ThemeData buildCordonTheme(CordonThemePreset preset) {
  const minButtonSize = Size(48, 48);
  final buttonThemes = (
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(minimumSize: minButtonSize),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(minimumSize: minButtonSize),
    ),
  );

  if (preset == CordonThemePreset.highContrast) {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: Colors.black,
      colorScheme: const ColorScheme.highContrastDark(
        primary: Color(0xFFFFFF00),
        onPrimary: Colors.black,
        surface: Colors.black,
        onSurface: Colors.white,
      ),
      elevatedButtonTheme: buttonThemes.elevatedButtonTheme,
      outlinedButtonTheme: buttonThemes.outlinedButtonTheme,
    );
  }

  final isDark = preset == CordonThemePreset.dark;
  return ThemeData(
    useMaterial3: true,
    colorSchemeSeed: const Color(0xFF2563EB),
    brightness: isDark ? Brightness.dark : Brightness.light,
    elevatedButtonTheme: buttonThemes.elevatedButtonTheme,
    outlinedButtonTheme: buttonThemes.outlinedButtonTheme,
  );
}
