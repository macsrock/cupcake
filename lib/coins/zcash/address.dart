import 'package:cupcake/coins/abstract/address.dart';
import 'package:flutter/material.dart';

class ZcashAddress extends Address {
  ZcashAddress(super.label, super.address);
}

class UnifiedAddressLabel implements AddressLabel {
  @override
  Widget icon(final Color color) => Icon(
        Icons.shield_outlined,
        color: color,
      );

  @override
  String get extra => "";

  @override
  String get label => "Unified";
}
