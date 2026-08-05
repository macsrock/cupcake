import 'package:cupcake/coins/abstract/amount.dart';

class ZcashAmount implements Amount {
  ZcashAmount(this.amount);
  @override
  final int amount; // zatoshis

  @override
  String toString() => (amount / 1e8).toStringAsFixed(8);
}
