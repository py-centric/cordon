import 'package:flutter/material.dart';

import 'app_tokens.g.dart';

/// The three constitutional theme modes that must stay at parity.
enum CordonThemePreset {
  light,
  dark,
  highContrast;
}

/// Builds the [ThemeData] for the given [preset].
///
/// All three presets enforce the constitutional 48x48dp minimum touch target
/// and Material 3 semantics; High Contrast targets >= 7:1 contrast using
/// [CordonDesignTokens] high-contrast semantic tokens.
ThemeData buildCordonTheme(CordonThemePreset preset) {
  const minButtonSize = CordonDesignTokens.touchTargetMin;
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
      scaffoldBackgroundColor: CordonDesignTokens.highContrastScaffold,
      colorScheme: const ColorScheme.highContrastDark(
        primary: CordonDesignTokens.highContrastPrimary,
        onPrimary: CordonDesignTokens.highContrastOnPrimary,
        surface: CordonDesignTokens.highContrastSurface,
        onSurface: CordonDesignTokens.highContrastOnSurface,
      ),
      elevatedButtonTheme: buttonThemes.elevatedButtonTheme,
      outlinedButtonTheme: buttonThemes.outlinedButtonTheme,
    );
  }

  final isDark = preset == CordonThemePreset.dark;
  return ThemeData(
    useMaterial3: true,
    colorSchemeSeed: CordonDesignTokens.brandSeed,
    brightness: isDark ? Brightness.dark : Brightness.light,
    elevatedButtonTheme: buttonThemes.elevatedButtonTheme,
    outlinedButtonTheme: buttonThemes.outlinedButtonTheme,
  );
}
