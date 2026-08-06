// Prints UR fixtures produced by Cupcake's encoder, so the hot-wallet side
// can assert byte-compatibility against them.
//
//   flutter test test/gen_ur_fixture.dart --plain-name fixtures

import 'dart:typed_data';

import 'package:cupcake/coins/zcash/ur.dart';
import 'package:flutter_test/flutter_test.dart';

String _hex(final Uint8List b) =>
    b.map((final x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  test("fixtures", () {
    final fp = Uint8List.fromList(List.generate(32, (final i) => i));
    final accounts = encodeZcashAccounts(
      seedFingerprint: fp,
      ufvk: "uview1cupcaketestufvk",
      accountIndex: 0,
      name: "cupcake",
    );
    print("ZCASH_ACCOUNTS_CBOR=${_hex(accounts)}");

    final pczt = Uint8List.fromList(List.generate(64, (final i) => i * 3 % 256));
    print("ZCASH_PCZT_CBOR=${_hex(encodeZcashPczt(pczt))}");
    print("ZCASH_PCZT_PAYLOAD=${_hex(pczt)}");
    print("ZCASH_PCZT_FRAMES=${urFrames(zcashPcztUrType, encodeZcashPczt(pczt)).join(' ')}");
  });
}
