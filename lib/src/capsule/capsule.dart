import 'dart:convert';
import 'package:pointycastle/pointycastle.dart' as pc;
import '../constants.dart';
import '../group_element/group_element.dart';
import '../scalar/scalar.dart';

/// A class representing an encryption capsule
class Capsule {
  final GroupElement E;
  final GroupElement V;
  final Scalar S;
  final GroupElement? XG;
  final pc.ECDomainParameters params;

  Capsule(this.E, this.V, this.S, this.XG, this.params);

  bool get isReEncrypted => XG != null;

  /// Create a Capsule from base64 string
  static Capsule fromBase64(String base64, [pc.ECDomainParameters? params]) {
    params ??= pc.ECDomainParameters(DEFAULT_CURVE);
    var bytes = base64Decode(base64);
    if (bytes.length < 162) {
      throw ArgumentError(
          'Invalid capsule length: ${bytes.length} bytes. Expected at least 162 bytes.');
    }
    var E = GroupElement.fromBytes(bytes.sublist(0, 65), params);
    var V = GroupElement.fromBytes(bytes.sublist(65, 130), params);
    var S = Scalar.fromBytes(bytes.sublist(130, 162), params.n);

    // Parse XG if present
    GroupElement? XG;
    if (bytes.length >= 227) {
      // 162 + 65
      XG = GroupElement.fromBytes(bytes.sublist(162, 227), params);
    }

    return Capsule(E, V, S, XG, params);
  }

  /// Convert Capsule to base64 string
  String toBase64() {
    var bytes = E.toBytes() + V.toBytes() + S.toBytes();
    if (XG != null) {
      bytes += XG!.toBytes();
    }
    return base64Encode(bytes);
  }
}
