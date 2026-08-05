// dart:ffi bindings for the zcash_signer Rust library.
//
// Every native call returns a JSON envelope: {"ok": ...} or {"error": "..."}.
// Byte inputs are passed as (pointer, length); returned strings are freed
// with zsig_free_string.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

typedef _FingerprintNative = Pointer<Utf8> Function(Pointer<Uint8>, UintPtr);
typedef _FingerprintDart = Pointer<Utf8> Function(Pointer<Uint8>, int);

typedef _SeedFnNative = Pointer<Utf8> Function(Pointer<Uint8>, UintPtr, Uint32, Uint32);
typedef _SeedFnDart = Pointer<Utf8> Function(Pointer<Uint8>, int, int, int);

typedef _PcztFnNative = Pointer<Utf8> Function(
  Pointer<Uint8>,
  UintPtr,
  Pointer<Uint8>,
  UintPtr,
  Uint32,
  Uint32,
);
typedef _PcztFnDart = Pointer<Utf8> Function(
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  int,
  int,
);

typedef _FreeNative = Void Function(Pointer<Utf8>);
typedef _FreeDart = void Function(Pointer<Utf8>);

class ZcashSignerException implements Exception {
  ZcashSignerException(this.message);
  final String message;

  @override
  String toString() => "ZcashSignerException: $message";
}

class ZcashSignerFfi {
  factory ZcashSignerFfi() => _instance ??= ZcashSignerFfi._open();
  ZcashSignerFfi._open() : _lib = _openLibrary() {
    _fingerprint = _lib
        .lookupFunction<_FingerprintNative, _FingerprintDart>("zsig_seed_fingerprint");
    _getUfvk = _lib.lookupFunction<_SeedFnNative, _SeedFnDart>("zsig_get_ufvk");
    _getAddress = _lib.lookupFunction<_SeedFnNative, _SeedFnDart>("zsig_get_address");
    _checkPczt = _lib.lookupFunction<_PcztFnNative, _PcztFnDart>("zsig_check_pczt");
    _signPczt = _lib.lookupFunction<_PcztFnNative, _PcztFnDart>("zsig_sign_pczt");
    _freeString = _lib.lookupFunction<_FreeNative, _FreeDart>("zsig_free_string");
  }

  static ZcashSignerFfi? _instance;

  final DynamicLibrary _lib;
  late final _FingerprintDart _fingerprint;
  late final _SeedFnDart _getUfvk;
  late final _SeedFnDart _getAddress;
  late final _PcztFnDart _checkPczt;
  late final _PcztFnDart _signPczt;
  late final _FreeDart _freeString;

  static DynamicLibrary _openLibrary() {
    if (Platform.isAndroid) {
      return DynamicLibrary.open("libzcash_signer.so");
    }
    if (Platform.isIOS) {
      return DynamicLibrary.process();
    }
    if (Platform.isMacOS) {
      // Development convenience: prefer the locally built dylib.
      const local = "zcash_signer/target/release/libzcash_signer.dylib";
      if (File(local).existsSync()) {
        return DynamicLibrary.open(local);
      }
      return DynamicLibrary.open("libzcash_signer.dylib");
    }
    if (Platform.isLinux) {
      return DynamicLibrary.open("libzcash_signer.so");
    }
    throw UnsupportedError("zcash_signer is not built for this platform");
  }

  /// Decodes the JSON envelope, frees the native string, throws on error.
  dynamic _envelope(final Pointer<Utf8> ptr) {
    if (ptr == nullptr) {
      throw ZcashSignerException("null response from native library");
    }
    final raw = ptr.toDartString();
    _freeString(ptr);
    final decoded = jsonDecode(raw);
    if (decoded is Map<String, dynamic> && decoded.containsKey("error")) {
      throw ZcashSignerException(decoded["error"] as String);
    }
    return (decoded as Map<String, dynamic>)["ok"];
  }

  T _withBytes<T>(final Uint8List data, final T Function(Pointer<Uint8>, int) f) {
    final ptr = calloc<Uint8>(data.length);
    try {
      ptr.asTypedList(data.length).setAll(0, data);
      return f(ptr, data.length);
    } finally {
      // Zero seed material before releasing.
      ptr.asTypedList(data.length).fillRange(0, data.length, 0);
      calloc.free(ptr);
    }
  }

  /// ZIP-32 seed fingerprint, hex-encoded.
  String seedFingerprint(final Uint8List seed) => _withBytes(
        seed,
        (final ptr, final len) =>
            _envelope(_fingerprint(ptr, len))["fingerprint"] as String,
      );

  /// ZIP-316 encoded UFVK for the account.
  String getUfvk(final Uint8List seed, final int account, final int network) => _withBytes(
        seed,
        (final ptr, final len) =>
            _envelope(_getUfvk(ptr, len, account, network))["ufvk"] as String,
      );

  /// Default unified address for the account.
  String getAddress(final Uint8List seed, final int account, final int network) => _withBytes(
        seed,
        (final ptr, final len) =>
            _envelope(_getAddress(ptr, len, account, network))["address"] as String,
      );

  /// Fully checks the PCZT; returns the verified display summary.
  Map<String, dynamic> checkPczt(
    final Uint8List pczt,
    final Uint8List seed,
    final int account,
    final int network,
  ) =>
      _withBytes(
        pczt,
        (final pcztPtr, final pcztLen) => _withBytes(
          seed,
          (final seedPtr, final seedLen) => _envelope(
            _checkPczt(pcztPtr, pcztLen, seedPtr, seedLen, account, network),
          ) as Map<String, dynamic>,
        ),
      );

  /// Re-checks and signs the PCZT; returns the signed PCZT bytes.
  Uint8List signPczt(
    final Uint8List pczt,
    final Uint8List seed,
    final int account,
    final int network,
  ) {
    final hexPczt = _withBytes(
      pczt,
      (final pcztPtr, final pcztLen) => _withBytes(
        seed,
        (final seedPtr, final seedLen) => _envelope(
          _signPczt(pcztPtr, pcztLen, seedPtr, seedLen, account, network),
        )["pczt"] as String,
      ),
    );
    final out = Uint8List(hexPczt.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(hexPczt.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }
}
