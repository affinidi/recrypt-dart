import 'dart:convert';
import 'package:pointycastle/pointycastle.dart' as pc;
import '../constants.dart';
import '../group_element/group_element.dart';

/// A class representing a public key
class PublicKey {
  final GroupElement point;
  final pc.ECDomainParameters params;

  PublicKey(this.point, this.params);

  /// Create a PublicKey from base64 string
  static PublicKey fromBase64(String base64, [pc.ECDomainParameters? params]) {
    params ??= pc.ECDomainParameters(defaultCurve);
    var bytes = base64Decode(base64);
    return PublicKey(GroupElement.fromBytes(bytes, params), params);
  }

  /// Convert PublicKey to base64 string
  String toBase64() {
    return base64Encode(point.toBytes());
  }
}
