import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;
import 'package:cupcake/coins/abstract/address.dart' as abstract_address;
import 'package:cupcake/coins/abstract/coin.dart';
import 'package:cupcake/coins/abstract/wallet.dart';
import 'package:cupcake/coins/abstract/wallet_info.dart';
import 'package:cupcake/coins/abstract/wallet_seed_detail.dart';
import 'package:cupcake/coins/zcash/address.dart';
import 'package:cupcake/coins/zcash/amount.dart';
import 'package:cupcake/coins/zcash/coin.dart';
import 'package:cupcake/coins/zcash/ffi.dart';
import 'package:cupcake/coins/zcash/ur.dart' as zcash_ur;
import 'package:cupcake/coins/zcash/wallet_info.dart';
import 'package:cupcake/utils/config.dart';
import 'package:cupcake/utils/types.dart';
import 'package:cupcake/utils/urqr.dart';
import 'package:cupcake/views/animated_qr_page.dart';
import 'package:cupcake/views/unconfirmed_transaction.dart';
import 'package:flutter/cupertino.dart';
import 'package:path/path.dart' as p;

/// Zcash mainnet, ZIP-32 account 0 (matching the Keystone/Zashi flow).
const int _network = 0;
const int _account = 0;

class ZcashWallet implements CoinWallet {
  ZcashWallet({
    required this.seed,
    required this.passphrase,
    required final String walletName,
  }) : _walletName = walletName {
    _seedBytes = bip39.mnemonicToSeed(seed, passphrase: passphrase);
    final ffi = ZcashSignerFfi();
    _ufvk = ffi.getUfvk(_seedBytes, _account, _network);
    _address = ffi.getAddress(_seedBytes, _account, _network);
    _seedFingerprintHex = ffi.seedFingerprint(_seedBytes);
  }

  @override
  final String seed;

  @override
  final String passphrase;

  final String _walletName;

  late final Uint8List _seedBytes;
  late final String _ufvk;
  late final String _address;
  late final String _seedFingerprintHex;

  Uint8List get _seedFingerprint {
    final out = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      out[i] =
          int.parse(_seedFingerprintHex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }

  @override
  Coin get coin => Zcash();

  /// Pairing payload: the Keystone-compatible `ur:zcash-accounts` frames that
  /// Zashi (and, later, Cake Wallet) scan to create a watch-only account.
  @override
  List<String> get connectCakeWalletQRCode => zcash_ur.urFrames(
        zcash_ur.zcashAccountsUrType,
        zcash_ur.encodeZcashAccounts(
          seedFingerprint: _seedFingerprint,
          ufvk: _ufvk,
          accountIndex: _account,
          name: walletName,
        ),
        maxFragmentLength: CupcakeConfig.instance.maxFragmentLength,
      );

  @override
  Future<void> handleUR(final BuildContext context, final URQRData ur) async {
    switch (ur.tag) {
      case "zcash-pczt":
        final pczt = zcash_ur.decodeZcashPczt(ur.inputs);
        final ffi = ZcashSignerFfi();
        // The check layer verifies everything shown below against the PCZT's
        // cryptographic commitments and this wallet's keys.
        final summary = ffi.checkPczt(pczt, _seedBytes, _account, _network);

        final Map<abstract_address.Address, ZcashAmount> destMap = {};
        for (final output in (summary["outputs"] as List<dynamic>)) {
          final map = output as Map<String, dynamic>;
          if (map["is_change"] == true) continue;
          destMap[ZcashAddress(
            UnifiedAddressLabel(),
            map["address"] as String,
          )] = ZcashAmount(map["value"] as int);
        }
        final fee = ZcashAmount(summary["fee"] as int);

        if (!context.mounted) return;
        await UnconfirmedTransactionView(
          wallet: this,
          destMap: destMap,
          fee: fee,
          confirmCallback: (final BuildContext context) async {
            final signed = ffi.signPczt(pczt, _seedBytes, _account, _network);
            final frames = zcash_ur.urFrames(
              zcash_ur.zcashPcztUrType,
              zcash_ur.encodeZcashPczt(signed),
              maxFragmentLength: CupcakeConfig.instance.maxFragmentLength,
            );
            if (!context.mounted) return;
            await AnimatedURPage(
              urqrList: {"signedTx": frames},
              currentWallet: this,
            ).pushReplacement(context);
          },
          cancelCallback: (final BuildContext context) => Navigator.of(context).pop(),
        ).pushReplacement(context);
      default:
        throw Exception("Unable to handle '${ur.tag}' UR tag");
    }
  }

  @override
  bool get hasAccountSupport => false;

  @override
  bool get hasAddressesSupport => true;

  @override
  List<ZcashAddress> get address => [
        ZcashAddress(UnifiedAddressLabel(), _address),
      ];

  @override
  int get addressIndex => 0;

  @override
  Future<void> close() async {}

  @override
  int getAccountId() => 0;

  @override
  String get getAccountLabel => "Primary Address";

  @override
  int getAccountsCount() => 1;

  @override
  int getBalance() => -1;

  @override
  String getBalanceString() => (getBalance() / 1e8).toStringAsFixed(8);

  @override
  Future<List<WalletSeedDetail>> seedDetails() async {
    return [
      WalletSeedDetail(
        type: WalletSeedDetailType.text,
        name: Coin.L.seed,
        value: seed,
      ),
      if (passphrase.isNotEmpty)
        WalletSeedDetail(
          type: WalletSeedDetailType.text,
          name: Coin.L.wallet_passphrase,
          value: passphrase,
        ),
      WalletSeedDetail(
        type: WalletSeedDetailType.text,
        name: "UFVK",
        value: _ufvk,
      ),
    ];
  }

  @override
  void setAccount(final int newAccountIndex) {}

  @override
  String get walletName => p.basename(_walletName);

  @override
  CoinWalletInfo get walletInfo => ZcashWalletInfo(walletName);
}
