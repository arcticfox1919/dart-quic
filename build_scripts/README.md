# Build Scripts

Cross-platform build tool for dart-quic native library.

## Setup

```bash
cd build_scripts
dart pub get
```

## Usage

```bash
dart run builder.dart [options] [platform]
```

## Examples

### Single Platform
```bash
# Build for Windows x64
dart run builder.dart windowsX64

# Build for iOS ARM64 in debug mode
dart run builder.dart iosArm64 -d

# Build with verbose output
dart run builder.dart linuxX64 -v
```

### Multiple Platforms
```bash
# Build all platforms
dart run builder.dart -p all

# Build mobile platforms
dart run builder.dart -p mobile

# Build desktop platforms  
dart run builder.dart -p desktop
```

### Options
| Option | Description |
|--------|-------------|
| `-p` | Platform list or preset |
| `-d` | Debug mode |
| `-v` | Verbose output |
| `-s` | Skip existing builds |
| `-o` | Output directory |
| `-l` | List platforms |
| `-h` | Help |

### Platform Presets
- `all` - All platforms
- `mobile` - Android + iOS
- `desktop` - Windows + macOS + Linux
- `android` - Android platforms
- `ios` - iOS platforms

## Output

Libraries are copied to:
- `dart-quic/lib/src/native/` - For Dart FFI
- `dist/` - Distribution directory
- `dart-quic/include/` - Header file