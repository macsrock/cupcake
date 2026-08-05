import 'dart:io';
import 'dart:typed_data';

import 'package:cupcake/coins/zcash/ffi.dart';
import 'package:cupcake/coins/zcash/ur.dart';
import 'package:cupcake/utils/urqr.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List _fromHex(final String hex) {
  final clean = hex.trim();
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

void main() {
  final seed = Uint8List.fromList(List.filled(64, 0xab));

  group("UR envelope codec", () {
    test("zcash-pczt round-trips through animated UR frames", () {
      final payload = Uint8List.fromList(List.generate(3000, (final i) => i % 256));
      final frames = urFrames(zcashPcztUrType, encodeZcashPczt(payload));
      expect(frames.length, greaterThan(1));
      expect(frames.first.startsWith("ur:zcash-pczt/"), isTrue);

      // The scanner's progress parser must recognize the frames too.
      final parsed = URQRData.parse(frames);
      expect(parsed.tag, "zcash-pczt");
      expect(parsed.progress, 1.0);

      final decoded = decodeZcashPczt(frames);
      expect(decoded, payload);
    });

    test("zcash-accounts encodes fingerprint and tagged UFVK", () {
      final fp = Uint8List.fromList(List.generate(32, (final i) => i));
      final cbor = encodeZcashAccounts(
        seedFingerprint: fp,
        ufvk: "uview1testvalue",
        accountIndex: 0,
        name: "cupcake",
      );
      // {1: bstr(32), 2: [tag(49203){...}], ...}: spot-check the head bytes.
      expect(cbor[0], 0xa2); // map(2)
      expect(cbor[1], 0x01); // key 1
      expect(cbor[2], 0x58); // bytes, 1-byte length
      expect(cbor[3], 32);
      // Frames must be valid URs.
      final frames = urFrames(zcashAccountsUrType, cbor);
      expect(frames.first.startsWith("ur:zcash-accounts/"), isTrue);
    });
  });

  group("zcash_signer FFI", () {
    final dylib = File("zcash_signer/target/release/libzcash_signer.dylib");

    test("derives UFVK, address, fingerprint; checks and signs the vector",
        () {
      if (!dylib.existsSync() && !Platform.isLinux) {
        markTestSkipped("libzcash_signer not built; run cargo build --release");
        return;
      }
      final ffi = ZcashSignerFfi();

      final ufvk = ffi.getUfvk(seed, 0, 1);
      expect(ufvk.startsWith("uview"), isTrue);
      final address = ffi.getAddress(seed, 0, 1);
      expect(address.startsWith("u"), isTrue);
      final fp = ffi.seedFingerprint(seed);
      expect(fp.length, 64);

      final pczt = _fromHex(File("test/data/ironwood_pczt.hex").readAsStringSync());

      // The vector spends 100k zats: 60k external, 30k change, 10k fee.
      final summary = ffi.checkPczt(pczt, seed, 0, 1);
      expect(summary["fee"], 10000);
      expect(summary["total_out"], 60000);
      expect(summary["total_change"], 30000);
      final outputs = summary["outputs"] as List<dynamic>;
      final external = outputs.where((final o) => o["is_change"] != true).toList();
      expect(external.length, 1);
      expect((external.first["address"] as String).startsWith("utest"), isTrue);

      final signed = ffi.signPczt(pczt, seed, 0, 1);
      expect(signed.length, greaterThan(0));
      expect(signed, isNot(pczt));

      // A foreign seed must be rejected by the check layer.
      final otherSeed = Uint8List.fromList(List.filled(64, 0xcd));
      expect(
        () => ffi.checkPczt(pczt, otherSeed, 0, 1),
        throwsA(isA<ZcashSignerException>()),
      );
    });
  });
}
