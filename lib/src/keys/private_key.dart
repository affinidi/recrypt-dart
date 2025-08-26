import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart' as pc;

import '../constants.dart';
import '../group_element/group_element.dart';
import '../scalar/scalar.dart';
import 'public_key.dart';

/// A class representing a private key
class PrivateKey {
  final Scalar scalar;
  final pc.ECDomainParameters params;

  PrivateKey(this.scalar, this.params);

  /// Generate a new private key
  static PrivateKey generate([pc.ECDomainParameters? params]) {
    params ??= pc.ECDomainParameters(defaultCurve);
    var random = Random.secure();
    var bytes = Uint8List(32);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = random.nextInt(256);
    }
    var scalar = Scalar.fromBytes(bytes, params.n);
    return PrivateKey(scalar, params);
  }

  /// Create a PrivateKey from bytes
  static PrivateKey fromBytes(Uint8List bytes, pc.ECDomainParameters params) {
    return PrivateKey(Scalar.fromBytes(bytes, params.n), params);
  }

  /// Convert PrivateKey to bytes
  Uint8List toBytes() {
    return scalar.toBytes();
  }

  /// Create a PrivateKey from base64 string
  static PrivateKey fromBase64(String base64, [pc.ECDomainParameters? params]) {
    params ??= pc.ECDomainParameters(defaultCurve);
    var bytes = base64Decode(base64);
    return fromBytes(bytes, params);
  }

  /// Convert PrivateKey to base64 string
  String toBase64() {
    return base64Encode(scalar.toBytes());
  }

  /// Get the corresponding public key
  PublicKey getPublicKey() {
    return PublicKey(GroupElement(params.G * scalar.value, params), params);
  }
}
