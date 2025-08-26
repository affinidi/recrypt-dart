import 'dart:convert';
import 'package:pointycastle/pointycastle.dart' as pc;
import '../constants.dart';
import '../group_element/group_element.dart';
import '../scalar/scalar.dart';
import 'private_key.dart';
import 'public_key.dart';

/// A class representing a key pair
class KeyPair {
  final PrivateKey privateKey;
  final PublicKey publicKey;

  KeyPair(this.privateKey, this.publicKey);

  /// Convert KeyPair to JSON string
  Map<String, String> toJson() {
    return {
      'privateKey': privateKey.toBase64(),
      'publicKey': publicKey.toBase64(),
    };
  }

  /// Create a KeyPair from JSON string
  static KeyPair fromJson(String json, [pc.ECDomainParameters? params]) {
    params ??= pc.ECDomainParameters(defaultCurve);
    var map = jsonDecode(json) as Map<String, dynamic>;
    var privateKey = PrivateKey.fromBase64(map['privateKey'] as String, params);
    var publicKey = PublicKey.fromBase64(map['publicKey'] as String, params);
    return KeyPair(privateKey, publicKey);
  }

  /// Convert KeyPair to base64 string (includes both private and public keys)
  String toBase64() {
    return base64Encode(privateKey.toBytes() + publicKey.point.toBytes());
  }

  /// Create a KeyPair from base64 string
  static KeyPair fromBase64(String base64, [pc.ECDomainParameters? params]) {
    params ??= pc.ECDomainParameters(defaultCurve);
    var bytes = base64Decode(base64);
    if (bytes.length != 97) {
      // 32 bytes private key + 65 bytes public key
      throw ArgumentError(
          'Invalid key pair length: ${bytes.length} bytes. Expected 97 bytes.');
    }
    var privateKey = PrivateKey.fromBytes(bytes.sublist(0, 32), params);
    var publicKey =
        PublicKey(GroupElement.fromBytes(bytes.sublist(32), params), params);
    return KeyPair(privateKey, publicKey);
  }

  /// Convert only the public key to base64 string
  String publicKeyToBase64() {
    return publicKey.toBase64();
  }

  /// Create a KeyPair with only the public key from base64 string
  static KeyPair fromPublicKeyBase64(String base64,
      [pc.ECDomainParameters? params]) {
    params ??= pc.ECDomainParameters(defaultCurve);
    var publicKey = PublicKey.fromBase64(base64, params);
    // Create a dummy private key since we don't have the actual private key
    var privateKey = PrivateKey(Scalar(BigInt.zero, params.n), params);
    return KeyPair(privateKey, publicKey);
  }
}
