import 'dart:convert';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart' as encrypt_pkg;
import '../../proxy_recrypt.dart';

/// A class representing a shared key that can be used for encryption and decryption.
///
/// This class encapsulates:
/// - A capsule for proxy re-encryption
/// - A symmetric key for AES-256-GCM encryption
/// - An initialization vector (IV) for the encryption
///
/// The shared key can be:
/// - Generated for a specific public key
/// - Serialized to base64 for storage or transmission
/// - Deserialized from base64
/// - Used for encryption and decryption of messages
class SharedEncryptor {
  final Capsule capsule;
  final List<int> key;
  final encrypt_pkg.IV iv;

  /// Creates a new shared key with the given components.
  ///
  /// This constructor is typically used when deserializing a shared key
  /// or when creating a shared key from a re-encrypted capsule.
  SharedEncryptor(this.capsule, this.key, this.iv);

  /// Generates a new shared key using the given public key.
  ///
  /// This is the primary way to create a new shared key for encryption.
  /// The generated key can be stored and reused, or transmitted to a proxy
  /// for re-encryption.
  static SharedEncryptor createSharableEncryptor(PublicKey publicKey) {
    var recrypt = Recrypt();
    var result = recrypt.encapsulate(publicKey);
    var capsule = result['capsule'] as Capsule;
    var key = result['symmetricKey'] as List<int>;
    var iv = encrypt_pkg.IV.fromLength(12); // 96 bits for GCM
    return SharedEncryptor(capsule, key, iv);
  }

  /// Encrypts a message using the shared key.
  ///
  /// The message is encrypted using AES-256-GCM with the symmetric key
  /// and initialization vector stored in this shared key.
  ///
  /// Returns the encrypted message as a base64 string.
  String encrypt(String message) {
    var key = encrypt_pkg.Key(Uint8List.fromList(this.key));
    var encrypter = encrypt_pkg.Encrypter(
        encrypt_pkg.AES(key, mode: encrypt_pkg.AESMode.gcm));
    var encrypted = encrypter.encrypt(message, iv: iv);
    return encrypted.base64;
  }

  /// Decrypts a message using the shared key.
  ///
  /// The message must have been encrypted using the same shared key
  /// (or a re-encrypted version of it) and must be provided as a base64 string.
  ///
  /// Returns the decrypted message as a string.
  String decrypt(String encryptedBase64) {
    var key = encrypt_pkg.Key(Uint8List.fromList(this.key));
    var encrypter = encrypt_pkg.Encrypter(
        encrypt_pkg.AES(key, mode: encrypt_pkg.AESMode.gcm));
    var encrypted = encrypt_pkg.Encrypted.fromBase64(encryptedBase64);
    return encrypter.decrypt(encrypted, iv: iv);
  }

  /// Serializes the shared key to a base64 string.
  ///
  /// This method can be used to:
  /// - Store the shared key for later use
  /// - Transmit the shared key to a proxy for re-encryption
  /// - Share the encrypted capsule with other parties
  ///
  /// The serialized format includes:
  /// - The capsule (for re-encryption)
  /// - The symmetric key (for encryption/decryption)
  /// - The initialization vector (for encryption/decryption)
  String toBase64() {
    var data = {
      'capsule': capsule.toBase64(),
      'key': base64Encode(key),
      'iv': iv.base64,
    };
    return base64Encode(utf8.encode(jsonEncode(data)));
  }

  /// Deserializes a shared key from a base64 string.
  ///
  /// This method can be used to:
  /// - Restore a previously stored shared key
  /// - Reconstruct a shared key received from a proxy
  /// - Create a shared key from a transmitted capsule
  ///
  /// The deserialized shared key will have the same properties
  /// as the original shared key.
  static SharedEncryptor fromBase64(String base64) {
    try {
      var data = jsonDecode(utf8.decode(base64Decode(base64)));
      var capsule = Capsule.fromBase64(data['capsule']);
      var key = base64Decode(data['key']);
      var iv = encrypt_pkg.IV.fromBase64(data['iv']);
      return SharedEncryptor(capsule, key, iv);
    } catch (e) {
      throw FormatException('Invalid shared key format: $e');
    }
  }

  /// Creates a copy of this shared key with a new capsule.
  ///
  /// This is useful when creating a shared key for a re-encrypted capsule
  /// while keeping the same symmetric key and IV.
  SharedEncryptor withCapsule(Capsule newCapsule) {
    return SharedEncryptor(newCapsule, key, iv);
  }

  /// Encrypts a message and packages it with all necessary components for transmission.
  ///
  /// Returns a base64 string containing:
  /// - The encrypted message
  /// - The capsule (for re-encryption)
  /// - The initialization vector (for decryption)
  String encryptAndPackage(String message) {
    var encrypted = encrypt(message);
    var data = {
      'encrypted': encrypted,
      'capsule': capsule.toBase64(),
      'iv': iv.base64,
    };
    return base64Encode(utf8.encode(jsonEncode(data)));
  }

  /// Unpacks and decrypts a message that was packaged using encryptAndPackage.
  ///
  /// The package should be a base64 string containing:
  /// - The encrypted message
  /// - The capsule (for re-encryption)
  /// - The initialization vector (for decryption)
  ///
  /// Returns the decrypted message as a string.
  static String unpackAndDecrypt(String package, List<int> key) {
    try {
      var data = jsonDecode(utf8.decode(base64Decode(package)));
      var encrypted = data['encrypted'] as String;
      var iv = encrypt_pkg.IV.fromBase64(data['iv'] as String);

      var encrypter = encrypt_pkg.Encrypter(encrypt_pkg.AES(
          encrypt_pkg.Key(Uint8List.fromList(key)),
          mode: encrypt_pkg.AESMode.gcm));
      var encryptedData = encrypt_pkg.Encrypted.fromBase64(encrypted);
      return encrypter.decrypt(encryptedData, iv: iv);
    } catch (e) {
      throw FormatException('Invalid package format: $e');
    }
  }
}
