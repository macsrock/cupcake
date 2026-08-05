// Keystone-compatible UR envelopes for Zcash, per keystone-sdk-rust:
//
//   zcash-accounts (tag 49201):
//     {1: bstr seed_fingerprint, 2: [+ #6.49203(zcash-unified-full-viewing-key)]}
//   zcash-unified-full-viewing-key (tag 49203):
//     {1: text ufvk, 2: uint index, ?3: text name}
//   zcash-pczt (tag 49204):
//     {1: bstr data}
//
// The payloads are small integer-keyed CBOR maps, so this file carries a
// purpose-built encoder/decoder instead of pulling in a CBOR dependency.

import 'dart:convert';
import 'dart:typed_data';

import 'package:ur/ur.dart';
import 'package:ur/ur_decoder.dart';
import 'package:ur/ur_encoder.dart';

const String zcashAccountsUrType = "zcash-accounts";
const String zcashPcztUrType = "zcash-pczt";
const int zcashUfvkCborTag = 49203;

class _CborWriter {
  final BytesBuilder _out = BytesBuilder();

  Uint8List take() => _out.takeBytes();

  void _head(final int major, final int value) {
    assert(value >= 0);
    if (value < 24) {
      _out.addByte((major << 5) | value);
    } else if (value <= 0xff) {
      _out.addByte((major << 5) | 24);
      _out.addByte(value);
    } else if (value <= 0xffff) {
      _out.addByte((major << 5) | 25);
      _out.add([(value >> 8) & 0xff, value & 0xff]);
    } else {
      _out.addByte((major << 5) | 26);
      _out.add([
        (value >> 24) & 0xff,
        (value >> 16) & 0xff,
        (value >> 8) & 0xff,
        value & 0xff,
      ]);
    }
  }

  void uint(final int value) => _head(0, value);
  void bytes(final Uint8List value) {
    _head(2, value.length);
    _out.add(value);
  }

  void text(final String value) {
    final encoded = utf8.encode(value);
    _head(3, encoded.length);
    _out.add(encoded);
  }

  void array(final int length) => _head(4, length);
  void map(final int length) => _head(5, length);
  void tag(final int value) => _head(6, value);
}

class _CborReader {
  _CborReader(this._data);
  final Uint8List _data;
  int _pos = 0;

  (int major, int value) _head() {
    final initial = _data[_pos++];
    final major = initial >> 5;
    final additional = initial & 0x1f;
    if (additional < 24) return (major, additional);
    if (additional == 24) return (major, _data[_pos++]);
    if (additional == 25) {
      final v = (_data[_pos] << 8) | _data[_pos + 1];
      _pos += 2;
      return (major, v);
    }
    if (additional == 26) {
      final v = (_data[_pos] << 24) |
          (_data[_pos + 1] << 16) |
          (_data[_pos + 2] << 8) |
          _data[_pos + 3];
      _pos += 4;
      return (major, v);
    }
    throw Exception("unsupported CBOR additional info $additional");
  }

  int mapHeader() {
    final (major, value) = _head();
    if (major != 5) throw Exception("expected CBOR map, got major $major");
    return value;
  }

  int uint() {
    final (major, value) = _head();
    if (major != 0) throw Exception("expected CBOR uint, got major $major");
    return value;
  }

  Uint8List bytes() {
    final (major, value) = _head();
    if (major != 2) throw Exception("expected CBOR bytes, got major $major");
    final out = Uint8List.sublistView(_data, _pos, _pos + value);
    _pos += value;
    return out;
  }

  /// Skips one data item of any supported type.
  void skip() {
    final (major, value) = _head();
    switch (major) {
      case 0 || 1:
        return;
      case 2 || 3:
        _pos += value;
      case 4:
        for (var i = 0; i < value; i++) {
          skip();
        }
      case 5:
        for (var i = 0; i < 2 * value; i++) {
          skip();
        }
      case 6:
        skip();
      default:
        throw Exception("unsupported CBOR major type $major");
    }
  }
}

/// Encodes the `zcash-accounts` payload used to pair with a hot wallet.
Uint8List encodeZcashAccounts({
  required final Uint8List seedFingerprint,
  required final String ufvk,
  final int accountIndex = 0,
  final String? name,
}) {
  final w = _CborWriter();
  w.map(2);
  w.uint(1);
  w.bytes(seedFingerprint);
  w.uint(2);
  w.array(1);
  w.tag(zcashUfvkCborTag);
  w.map(name == null ? 2 : 3);
  w.uint(1);
  w.text(ufvk);
  w.uint(2);
  w.uint(accountIndex);
  if (name != null) {
    w.uint(3);
    w.text(name);
  }
  return w.take();
}

/// Encodes the `zcash-pczt` payload (a signed or unsigned PCZT).
Uint8List encodeZcashPczt(final Uint8List pczt) {
  final w = _CborWriter();
  w.map(1);
  w.uint(1);
  w.bytes(pczt);
  return w.take();
}

/// Extracts the raw PCZT bytes from a fully received `zcash-pczt` UR.
Uint8List decodeZcashPczt(final List<String> urParts) {
  final decoder = URDecoder();
  for (final part in urParts) {
    decoder.receivePart(part);
  }
  if (!decoder.isComplete()) {
    throw Exception("incomplete zcash-pczt UR");
  }
  final ur = decoder.result as UR;
  final reader = _CborReader(ur.cbor);
  final entries = reader.mapHeader();
  Uint8List? pczt;
  for (var i = 0; i < entries; i++) {
    final key = reader.uint();
    if (key == 1) {
      pczt = reader.bytes();
    } else {
      reader.skip();
    }
  }
  if (pczt == null) {
    throw Exception("zcash-pczt UR has no data field");
  }
  return pczt;
}

/// Renders a UR payload into animated QR frames.
List<String> urFrames(
  final String type,
  final Uint8List cbor, {
  final int maxFragmentLength = 130,
}) {
  final encoder = UREncoder(UR(type, cbor), maxFragmentLength);
  final List<String> frames = [];
  while (!encoder.isComplete) {
    frames.add(encoder.nextPart());
  }
  return frames;
}
