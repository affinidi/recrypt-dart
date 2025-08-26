import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/pointycastle.dart' as pc;

import '../capsule/capsule.dart';
import '../constants.dart';
import '../group_element/group_element.dart';
import '../keys/key_pair.dart';
import '../keys/private_key.dart';
import '../keys/public_key.dart';
import '../keys/re_encryption_key.dart';
import '../scalar/scalar.dart';

/// Main class for proxy re-encryption operations
class Recrypt {
  final pc.ECDomainParameters params;

  Recrypt([pc.ECDomainParameters? params])
      : params = params ?? pc.ECDomainParameters(defaultCurve);

  /// Generate a new key pair
  KeyPair generateKeyPair() {
    var privateKey = PrivateKey.generate(params);
    return KeyPair(privateKey, privateKey.getPublicKey());
  }

  static String generateSecureRandomMessage() {
    var message = List<int>.generate(32, (_) => Random.secure().nextInt(256));
    return message.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Encapsulate a symmetric key for a public key
  Map<String, dynamic> encapsulate(PublicKey publicKey) {
    var kp1 = generateKeyPair();
    var kp2 = generateKeyPair();

    var sk1 = kp1.privateKey.scalar;
    var sk2 = kp2.privateKey.scalar;
    var pk1 = kp1.publicKey.point;
    var pk2 = kp2.publicKey.point;

    var hash = _hashToScalar([pk1, pk2]);
    var S = sk1.add(sk2.mul(hash));

    var symmetricPoint = publicKey.point.mul(sk1.add(sk2));
    var symmetricKey = _sha256(symmetricPoint.toBytes());

    var capsule = Capsule(pk1, pk2, S, null, params);

    return {'capsule': capsule, 'symmetricKey': symmetricKey};
  }

  /// Decapsulate a capsule with a private key
  Uint8List decapsulate(Capsule capsule, PrivateKey privateKey) {
    if (capsule.isReEncrypted) {
      return _decapsulateReEncrypted(capsule, privateKey);
    }
    return _decapsulateOriginal(capsule, privateKey);
  }

  /// Generate a re-encryption key
  ReEncryptionKey generateReEncryptionKey(PrivateKey fromKey, PublicKey toKey) {
    var kp = generateKeyPair();
    var tmpSk = kp.privateKey.scalar;
    var tmpPk = kp.publicKey.point;

    var points = [tmpPk, toKey.point, toKey.point.mul(tmpSk)];
    var hash = _hashToScalar(points);
    var rk = fromKey.scalar.mul(hash.inv());

    return ReEncryptionKey(rk, tmpPk, params);
  }

  /// Re-encrypt a capsule
  Capsule reEncrypt(Capsule capsule, ReEncryptionKey rk) {
    var primeE = capsule.E.mul(rk.scalar);
    var primeV = capsule.V.mul(rk.scalar);
    // Use only the current re-encryption key's point
    return Capsule(primeE, primeV, capsule.S, rk.point, params);
  }

  Uint8List _decapsulateOriginal(Capsule capsule, PrivateKey privateKey) {
    var s = capsule.E.add(capsule.V);
    var symmetricPoint = s.mul(privateKey.scalar);
    return _sha256(symmetricPoint.toBytes());
  }

  Uint8List _decapsulateReEncrypted(Capsule capsule, PrivateKey privateKey) {
    var recipientPubKey = privateKey.getPublicKey().point;
    // ignore: non_constant_identifier_names
    var XG = capsule.XG!; // We know it's re-encrypted, so XG must exist

    // Hash input: [XG, recipientPubKey, XG * privateKey] - matching JavaScript implementation
    var points = [XG, recipientPubKey, XG.mul(privateKey.scalar)];
    var hash = _hashToScalar(points);
    var tmpKdfPoint = capsule.E.add(capsule.V).mul(hash);

    return _sha256(tmpKdfPoint.toBytes());
  }

  Scalar _hashToScalar(List<GroupElement> points) {
    var hash = sha256.convert(points.expand((p) => p.toBytes()).toList());
    var hashValue = BigInt.parse(hash.toString(), radix: 16);
    return Scalar(hashValue + BigInt.one, params.n);
  }

  Uint8List _sha256(Uint8List data) {
    var hash = sha256.convert(data);
    return Uint8List.fromList(hash.bytes);
  }
}
