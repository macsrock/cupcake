import 'package:cupcake/coins/abstract/coin.dart';
import 'package:cupcake/coins/abstract/wallet_creation.dart';
import 'package:cupcake/coins/zcash/coin.dart';
import 'package:cupcake/coins/zcash/creation/new_wallet.dart';
import 'package:cupcake/coins/zcash/creation/restore_wallet.dart';
import 'package:cupcake/l10n/app_localizations.dart';
import 'package:cupcake/utils/form/abstract_form_element.dart';
import 'package:cupcake/utils/form/string_form_element.dart';
import 'package:cupcake/utils/form/validators.dart';
import 'package:cupcake/utils/types.dart';

class ZcashWalletCreation extends WalletCreation {
  factory ZcashWalletCreation(final AppLocalizations L) {
    _instance ??= ZcashWalletCreation._internal(L);
    return _instance!;
  }
  ZcashWalletCreation._internal(this.L);
  static ZcashWalletCreation? _instance;

  final AppLocalizations L;

  Future<void> errorHandler(final Object error) async {
    print("error: $error");
    return;
  }

  late StringFormElement seed = StringFormElement(
    L.wallet_seed,
    password: false,
    validator: nonEmptyValidator(
      L,
      extra: (final input) =>
          !(Zcash().isSeedSomewhatLegit(input)) ? L.warning_seed_incorrect_length : null,
    ),
    errorHandler: errorHandler,
    canPaste: true,
  );

  late StringFormElement passphrase = StringFormElement(
    L.wallet_passphrase,
    password: false,
    validator: nonEmptyValidator(
      L,
      extra: (final input) => null,
    ),
    errorHandler: errorHandler,
    canPaste: true,
    isExtra: true,
  );

  late StringFormElement passphraseConfirm = StringFormElement(
    L.wallet_passphrase,
    password: false,
    validator: nonEmptyValidator(
      L,
      extra: (final input) => input != passphrase.ctrl.text ? L.seed_passphrase_mismatch : null,
    ),
    errorHandler: errorHandler,
    canPaste: true,
    isExtra: true,
  );

  late List<FormElement> createForm = [passphrase, passphraseConfirm];
  late List<FormElement> restoreForm = [seed, passphrase];

  @override
  Future<CreationOutcome?> create(
    final CreateMethod createMethod,
    final String walletName,
    final String walletPassword,
  ) async {
    if (createMethod == CreateMethod.create) {
      if (await passphrase.value != await passphraseConfirm.value) {
        throw Exception(L.seed_passphrase_mismatch);
      }
    }
    return switch (createMethod) {
      CreateMethod.create => CreateZcashWalletCreationMethod(
          L,
          walletPath: coin.getPathForWallet(walletName),
          walletPassword: walletPassword,
          passphrase: await passphrase.value,
        ).create(),
      CreateMethod.restore => RestoreZcashWalletCreationMethod(
          L,
          walletPath: coin.getPathForWallet(walletName),
          walletPassword: walletPassword,
          seed: await seed.value,
          passphrase: await passphrase.value,
        ).create(),
    };
  }

  @override
  Future<void> wipe() async {
    await Future.delayed(Duration.zero); // do not call on build();
    seed.ctrl.clear();
    passphrase.ctrl.clear();
    passphraseConfirm.ctrl.clear();
  }

  @override
  Map<String, WalletCreationForm> createMethods(
    final CreateMethod createMethod,
  ) =>
      {
        if ([CreateMethod.create].contains(createMethod))
          L.option_create_new_wallet: WalletCreationForm(
            method: CreateMethod.create,
            form: createForm,
          ),
        if ([CreateMethod.restore].contains(createMethod)) ...{
          L.option_create_seed: WalletCreationForm(method: CreateMethod.restore, form: restoreForm),
        },
      };

  @override
  Coin get coin => Zcash();
}
