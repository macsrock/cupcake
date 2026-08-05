import 'dart:io';

import 'package:bip39/bip39.dart' as bip39;
import 'package:cupcake/coins/abstract/wallet_creation.dart';
import 'package:cupcake/coins/zcash/coin.dart';
import 'package:cupcake/coins/zcash/wallet.dart';
import 'package:cupcake/l10n/app_localizations.dart';
import 'package:cupcake/utils/encryption/default.dart';
import 'package:cupcake/utils/types.dart';
import 'package:path/path.dart' as p;

class CreateZcashWalletCreationMethod extends CreationMethod {
  CreateZcashWalletCreationMethod(
    this.L, {
    required this.walletPath,
    required this.walletPassword,
    required this.passphrase,
  });
  final coin = Zcash();
  final AppLocalizations L;

  final String walletPath;
  final String walletPassword;
  final String passphrase;

  @override
  Future<CreationOutcome> create() async {
    // 24 words, the norm for Zcash wallets (Zashi restores 24-word seeds).
    final mnemonic = bip39.generateMnemonic(strength: 256);

    final keys = "${Zcash().getPathForWallet(p.basename(walletPath))}.keys";
    final data = passphrase.isEmpty ? mnemonic : "$mnemonic;$passphrase";
    final keysEncrypted = DefaultEncryption().encryptString(data, walletPassword);
    File(keys).writeAsBytesSync(keysEncrypted);

    return CreationOutcome(
      method: CreateMethod.create,
      success: true,
      wallet: ZcashWallet(
        seed: mnemonic,
        passphrase: passphrase,
        walletName: p.basename(walletPath),
      ),
    );
  }
}
