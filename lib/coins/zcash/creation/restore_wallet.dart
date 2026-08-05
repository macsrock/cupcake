import 'dart:io';

import 'package:bip39/bip39.dart' as bip39;
import 'package:cupcake/coins/abstract/wallet_creation.dart';
import 'package:cupcake/coins/zcash/coin.dart';
import 'package:cupcake/coins/zcash/wallet.dart';
import 'package:cupcake/l10n/app_localizations.dart';
import 'package:cupcake/utils/encryption/default.dart';
import 'package:cupcake/utils/types.dart';
import 'package:path/path.dart' as p;

class RestoreZcashWalletCreationMethod extends CreationMethod {
  RestoreZcashWalletCreationMethod(
    this.L, {
    required this.walletPath,
    required this.walletPassword,
    required this.seed,
    required this.passphrase,
  });
  final coin = Zcash();
  final AppLocalizations L;

  final String walletPath;
  final String walletPassword;
  final String seed;
  final String passphrase;

  @override
  Future<CreationOutcome> create() async {
    final mnemonic = seed.trim().replaceAll(RegExp(r"\s+"), " ");
    if (!bip39.validateMnemonic(mnemonic)) {
      return CreationOutcome(
        method: CreateMethod.restore,
        success: false,
        message: L.warning_seed_incorrect_length,
      );
    }

    final keys = "${Zcash().getPathForWallet(p.basename(walletPath))}.keys";
    final data = passphrase.isEmpty ? mnemonic : "$mnemonic;$passphrase";
    final keysEncrypted = DefaultEncryption().encryptString(data, walletPassword);
    File(keys).writeAsBytesSync(keysEncrypted);

    return CreationOutcome(
      method: CreateMethod.restore,
      success: true,
      wallet: ZcashWallet(
        seed: mnemonic,
        passphrase: passphrase,
        walletName: p.basename(walletPath),
      ),
    );
  }
}
