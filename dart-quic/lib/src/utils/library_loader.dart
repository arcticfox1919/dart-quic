import 'dart:ffi' as ffi;
import 'dart:io';

class LibraryLoader {
  static ffi.DynamicLibrary Function()? _customLibraryLoader;

  static void setCustomLoader(ffi.DynamicLibrary Function()? loader) {
    _customLibraryLoader = loader;
  }

  static ffi.DynamicLibrary load() =>
      _customLibraryLoader?.call() ?? loadLibrary();

  static ffi.DynamicLibrary loadLibrary() {
    ffi.DynamicLibrary library;
    if (Platform.isAndroid) {
      // On Android, the library should be packaged with the app in jniLibs
      library = LibraryLoader.loadAndroidLibrary();
    } else if (Platform.isIOS) {
      // On iOS, the library is statically linked into the app
      library = ffi.DynamicLibrary.process();
    } else if (Platform.isWindows) {
      // On Windows, load from plugin's native directory
      library = LibraryLoader.loadWindowsLibrary();
    } else if (Platform.isMacOS) {
      // On macOS, load from plugin's native directory
      library = LibraryLoader.loadMacOSLibrary();
    } else if (Platform.isLinux) {
      // On Linux, load from plugin's native directory
      library = LibraryLoader.loadLinuxLibrary();
    } else {
      throw UnsupportedError(
        'Platform ${Platform.operatingSystem} is not supported',
      );
    }
    return library;
  }

  static ffi.DynamicLibrary loadAndroidLibrary() =>
      ffi.DynamicLibrary.open('libdart_quic_ffi.so');

  static ffi.DynamicLibrary loadWindowsLibrary() {
    // For Windows desktop, try multiple strategies:
    // 1. Adjacent to executable
    // 2. In PATH environment variable
    // 3. System directories
    final paths = [
      'dart_quic_ffi.dll', // Same directory as executable
      'lib/dart_quic_ffi.dll', // In lib subdirectory
    ];

    for (final path in paths) {
      try {
        return ffi.DynamicLibrary.open(path);
      } catch (e) {
        // Continue trying other paths
      }
    }

    throw StateError(
      'Could not load dart_quic_ffi.dll. For Windows desktop applications:\n'
      '1. Place dart_quic_ffi.dll next to your application executable\n'
      '2. Or add the library location to your PATH environment variable\n'
      '3. Or install the library in a system directory',
    );
  }

  static ffi.DynamicLibrary loadMacOSLibrary() {
    // For macOS desktop, try multiple strategies:
    // 1. App bundle (for packaged apps)
    // 2. Adjacent to executable
    // 3. System library paths
    final paths = [
      'libdart_quic_ffi.dylib', // Same directory as executable
      '@executable_path/libdart_quic_ffi.dylib', // Relative to executable
      '@loader_path/libdart_quic_ffi.dylib', // Relative to loading binary
      '/usr/local/lib/libdart_quic_ffi.dylib', // Homebrew location
      '/opt/homebrew/lib/libdart_quic_ffi.dylib', // Apple Silicon Homebrew
    ];

    for (final path in paths) {
      try {
        return ffi.DynamicLibrary.open(path);
      } catch (e) {
        // Continue trying other paths
      }
    }

    throw StateError(
      'Could not load libdart_quic_ffi.dylib. For macOS desktop applications:\n'
      '1. Place libdart_quic_ffi.dylib next to your application executable\n'
      '2. Or install via Homebrew: brew install <your-formula>\n'
      '3. Or set DYLD_LIBRARY_PATH environment variable',
    );
  }

  static ffi.DynamicLibrary loadLinuxLibrary() {
    // For Linux desktop, try multiple strategies:
    // 1. Adjacent to executable
    // 2. LD_LIBRARY_PATH
    // 3. System library directories
    final paths = [
      'libdart_quic_ffi.so', // Same directory as executable
      './libdart_quic_ffi.so', // Current directory
      '/usr/local/lib/libdart_quic_ffi.so', // Common install location
      '/usr/lib/libdart_quic_ffi.so', // System library directory
      '/usr/lib/x86_64-linux-gnu/libdart_quic_ffi.so', // Debian/Ubuntu
    ];

    for (final path in paths) {
      try {
        return ffi.DynamicLibrary.open(path);
      } catch (e) {
        // Continue trying other paths
      }
    }

    throw StateError(
      'Could not load libdart_quic_ffi.so. For Linux desktop applications:\n'
      '1. Place libdart_quic_ffi.so next to your application executable\n'
      '2. Or install to /usr/local/lib/ and run ldconfig\n'
      '3. Or set LD_LIBRARY_PATH environment variable\n'
      '4. Or install via package manager',
    );
  }
}
