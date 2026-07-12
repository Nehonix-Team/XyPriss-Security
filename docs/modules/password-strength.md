# Documentation: PasswordManager.strength()

The `strength()` method of the `PasswordManager` class is an advanced password analysis feature. It allows you to evaluate password security, calculate its entropy, estimate cracking time, and provide dynamic recommendations based on developer-defined security criteria.

## Configuration (Constructor Options)

Security rules for the `strength()` method are configured when instantiating `PasswordManager` via the `strength` property.

> [!TIP]
> By default, `PasswordManager` includes strict rules (e.g., minimum 8 characters, dictionary check, etc.). Any option you provide will override its corresponding default value.

```typescript
import { PasswordManager } from "xypriss-security";

const pwd = new PasswordManager({
  strength: {
    minLength: 12,              // Minimum length (default: 8)
    maxLength: 64,              // Optional maximum length
    requireUppercase: true,     // Require an uppercase letter (default: true)
    requireLowercase: true,     // Require a lowercase letter (default: true)
    requireNumbers: true,       // Require a number (default: true)
    requireSymbols: true,       // Require a special character (default: true)
    preventRepeats: true,       // Prevent repeated characters like "aaa" (default: true)
    preventSequences: true,     // Prevent common sequences like "123", "abc" (default: true)
    checkDictionary: true,      // Check if the password contains common dictionary words (default: true)
  }
});
```

## Usage

Call the method with the plaintext password to get a detailed analysis.

```typescript
const result = pwd.strength("myPassword123!");
console.log(result);
```

## Result Structure (`PasswordStrengthResult`)

The returned object contains the following information:

| Property | Type | Description |
|-----------|------|-------------|
| `isValid` | `boolean` | `true` if the password meets **all** the rules configured in `strengthOptions`. |
| `score` | `number` | A score from 0 to 100 estimating overall strength (based on length, variety, and penalties). |
| `label` | `string` | Human-readable classification: `"very-weak"`, `"weak"`, `"fair"`, `"strong"`, `"very-strong"`. |
| `suggestions` | `string[]` | **Dynamic suggestions**. Only appears for configured rules that are not met. |
| `analysis` | `object` | Raw analysis data (see below). |

### The `analysis` Object

The `analysis` object is very useful for displaying visual security indicators (progress bars, colors) to the user:

*   `length` (number): The length of the tested password.
*   `hasUppercase` (boolean): Presence of uppercase letters.
*   `hasLowercase` (boolean): Presence of lowercase letters.
*   `hasNumbers` (boolean): Presence of numbers.
*   `hasSymbols` (boolean): Presence of symbols.
*   `hasRepeats` (boolean): `true` if there are more than 2 identical characters in a row (e.g., "aaa").
*   `hasSequences` (boolean): `true` if there is an obvious sequence (e.g., "123", "abc").
*   `entropy` (number): The calculated theoretical entropy in bits.
*   `crackTimeSeconds` (number): **Estimated cracking time** in seconds (offline attack scenario at 1 billion guesses/sec).
*   `crackTimeDisplay` (string): **Human-readable version** of the cracking time (e.g., `"Instantly"`, `"37 minutes"`, `"2 months"`, `"Centuries"`).

## Advanced Features

### 1. Dictionary Check (Anti-Dictionary Attack)
If `checkDictionary: true` is enabled, the method silently loads an optimized dictionary of common words into memory (only once for better performance). 
If the password contains a dictionary word longer than 3 letters, a severe penalty (-20 points) is applied, and `isValid` becomes `false`.

### 2. Smart Dynamic Suggestions
The suggestions returned in the `suggestions` array adapt **strictly** to your configuration.
If you configure `minLength: 8` and the user enters `12345678`, the method will not ask them to increase the size (since 8 is valid according to your rule). It will only suggest what is actually missing based on your config (e.g., "Add uppercase letters (A-Z).").

> [!IMPORTANT]
> The generated suggestions are in English by default. You can rely on the booleans inside the `analysis` object to manage your own translated error messages on your frontend.
