import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart' as pc;
import '../constants.dart';

/// A class representing a scalar value in the elliptic curve field
class Scalar {
  final BigInt value;
  final BigInt order;

  Scalar(this.value, this.order);

  /// Create a Scalar from bytes
  static Scalar fromBytes(Uint8List bytes, [BigInt? order]) {
    order ??= pc.ECDomainParameters(defaultCurve).n;
    return Scalar(
        BigInt.parse(
            bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
            radix: 16),
        order);
  }

  /// Convert Scalar to bytes
  Uint8List toBytes() {
    var hex = value.toRadixString(16);
    // Pad to 64 hex chars (32 bytes)
    hex = hex.padLeft(64, '0');
    if (hex.length % 2 != 0) hex = '0$hex';
    return Uint8List.fromList(List<int>.generate(hex.length ~/ 2,
        (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16)));
  }

  /// Add two scalars
  Scalar add(Scalar other) {
    return Scalar((value + other.value) % order, order);
  }

  /// Multiply two scalars
  Scalar mul(Scalar other) {
    return Scalar((value * other.value) % order, order);
  }

  /// Get multiplicative inverse
  Scalar inv() {
    return Scalar(value.modInverse(order), order);
  }
}
