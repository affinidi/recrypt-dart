import 'dart:convert';
import 'package:pointycastle/pointycastle.dart' as pc;
import '../constants.dart';
import '../group_element/group_element.dart';
import '../scalar/scalar.dart';

/// A class representing a re-encryption key
class ReEncryptionKey {
  final Scalar scalar;
  final GroupElement point;
  final pc.ECDomainParameters params;

  ReEncryptionKey(this.scalar, this.point, this.params);

  /// Create a ReEncryptionKey from base64 string
  static ReEncryptionKey fromBase64(String base64,
      [pc.ECDomainParameters? params]) {
    params ??= pc.ECDomainParameters(DEFAULT_CURVE);
    var bytes = base64Decode(base64);
    var scalar = Scalar.fromBytes(bytes.sublist(0, 32), params.n);
    var point = GroupElement.fromBytes(bytes.sublist(32), params);
    return ReEncryptionKey(scalar, point, params);
  }

  /// Convert ReEncryptionKey to base64 string
  String toBase64() {
    return base64Encode(scalar.toBytes() + point.toBytes());
  }
}
