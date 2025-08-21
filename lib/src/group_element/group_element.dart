import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart' as pc;
import '../constants.dart';
import '../scalar/scalar.dart';

/// A class representing a point on the elliptic curve
class GroupElement {
  final pc.ECPoint? point;
  final pc.ECDomainParameters params;

  GroupElement(this.point, this.params);

  /// Create a GroupElement from bytes
  static GroupElement fromBytes(Uint8List bytes,
      [pc.ECDomainParameters? params]) {
    params ??= pc.ECDomainParameters(DEFAULT_CURVE);
    if (bytes.length < 65) {
      throw ArgumentError(
          'Invalid input length: ${bytes.length} bytes. Expected 65 bytes for an uncompressed EC point.');
    }
    if (bytes[0] != 0x04) {
      throw ArgumentError(
          'Invalid point format: ${bytes[0]}. Expected 0x04 for an uncompressed point.');
    }

    var curve = params.curve;
    var x = BigInt.parse(
        bytes
            .sublist(1, 33)
            .map((b) => b.toRadixString(16).padLeft(2, '0'))
            .join(),
        radix: 16);
    var y = BigInt.parse(
        bytes
            .sublist(33, 65)
            .map((b) => b.toRadixString(16).padLeft(2, '0'))
            .join(),
        radix: 16);
    final point = curve.createPoint(x, y);
    return GroupElement(point, params);
  }

  /// Convert GroupElement to bytes
  Uint8List toBytes() {
    if (point == null) throw StateError('ECPoint is null');
    final xVal = point!.x?.toBigInteger();
    final yVal = point!.y?.toBigInteger();
    if (xVal == null || yVal == null) {
      throw StateError('ECPoint x or y is null');
    }

    // Get raw bytes from x and y coordinates
    var xBytes = _bigIntToBytes(xVal);
    var yBytes = _bigIntToBytes(yVal);

    // Ensure x and y are 32 bytes each
    if (xBytes.length > 32 || yBytes.length > 32) {
      throw StateError('ECPoint coordinates too large');
    }

    // Pad with zeros if needed
    var paddedX = Uint8List(32)..setAll(32 - xBytes.length, xBytes);
    var paddedY = Uint8List(32)..setAll(32 - yBytes.length, yBytes);

    // Prepend 0x04 (uncompressed point) and concatenate x and y
    return Uint8List.fromList([0x04] + paddedX + paddedY);
  }

  /// Convert a BigInt to a byte array in big-endian format
  Uint8List _bigIntToBytes(BigInt value) {
    var hex = value.toRadixString(16);
    if (hex.length % 2 != 0) hex = '0$hex';
    var bytes = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < hex.length; i += 2) {
      bytes[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
    }
    return bytes;
  }

  /// Add two group elements
  GroupElement add(GroupElement other) {
    if (point == null || other.point == null)
      throw StateError('ECPoint is null');
    return GroupElement(point! + other.point!, params);
  }

  /// Multiply a group element by a scalar
  GroupElement mul(Scalar scalar) {
    if (point == null) throw StateError('ECPoint is null');
    return GroupElement(point! * scalar.value, params);
  }
}
