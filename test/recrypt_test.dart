// ignore_for_file: avoid_print

import 'dart:convert';

import 'package:proxy_recrypt/proxy_recrypt.dart';
import 'package:test/test.dart';
// import 'package:recrypt/src/crypto/shared_encryptor.dart';

void main() {
  late Recrypt recrypt;

  setUp(() {
    recrypt = Recrypt();
  });

  test('Key pair generation and serialization', () {
    var keyPair = recrypt.generateKeyPair();

    // Test private key serialization
    var privateKeyBase64 = keyPair.privateKey.toBase64();
    var deserializedPrivateKey = PrivateKey.fromBase64(privateKeyBase64);
    expect(deserializedPrivateKey.scalar.value,
        equals(keyPair.privateKey.scalar.value));

    // Test public key serialization
    var publicKeyBase64 = keyPair.publicKey.toBase64();
    var deserializedPublicKey = PublicKey.fromBase64(publicKeyBase64);
    expect(deserializedPublicKey.point.point?.x?.toBigInteger(),
        equals(keyPair.publicKey.point.point?.x?.toBigInteger()));
    expect(deserializedPublicKey.point.point?.y?.toBigInteger(),
        equals(keyPair.publicKey.point.point?.y?.toBigInteger()));
  });

  test('Encapsulation and decapsulation', () {
    var aliceKeyPair = recrypt.generateKeyPair();
    var result = recrypt.encapsulate(aliceKeyPair.publicKey);

    var capsule = result['capsule'] as Capsule;
    var symmetricKey = result['symmetricKey'] as List<int>;

    // Test capsule serialization
    var capsuleBase64 = capsule.toBase64();
    var deserializedCapsule = Capsule.fromBase64(capsuleBase64);
    expect(deserializedCapsule.E.point?.x?.toBigInteger(),
        equals(capsule.E.point?.x?.toBigInteger()));
    expect(deserializedCapsule.V.point?.x?.toBigInteger(),
        equals(capsule.V.point?.x?.toBigInteger()));

    // Test decapsulation
    var decapsulatedKey = recrypt.decapsulate(capsule, aliceKeyPair.privateKey);
    expect(decapsulatedKey, equals(symmetricKey));
  });

  test('Re-encryption', () {
    var aliceKeyPair = recrypt.generateKeyPair();
    var bobKeyPair = recrypt.generateKeyPair();

    // Alice encapsulates a symmetric key
    var result = recrypt.encapsulate(aliceKeyPair.publicKey);
    var capsule = result['capsule'] as Capsule;
    var symmetricKey = result['symmetricKey'] as List<int>;

    // Generate re-encryption key from Alice to Bob
    var reKey = recrypt.generateReEncryptionKey(
        aliceKeyPair.privateKey, bobKeyPair.publicKey);

    // Test re-encryption key serialization
    var reKeyBase64 = reKey.toBase64();
    var deserializedReKey = ReEncryptionKey.fromBase64(reKeyBase64);
    expect(deserializedReKey.scalar.value, equals(reKey.scalar.value));

    // Re-encrypt the capsule
    var reEncryptedCapsule = recrypt.reEncrypt(capsule, reKey);

    // Test re-encrypted capsule serialization
    var reCapsuleBase64 = reEncryptedCapsule.toBase64();
    var deserializedReCapsule = Capsule.fromBase64(reCapsuleBase64);
    expect(deserializedReCapsule.isReEncrypted, isTrue);

    // Bob decapsulates the re-encrypted capsule
    var bobDecapsulatedKey =
        recrypt.decapsulate(reEncryptedCapsule, bobKeyPair.privateKey);
    expect(bobDecapsulatedKey, equals(symmetricKey));
  });

  test('Multiple re-encryptions', () {
    var recrypt = Recrypt();
    var kp1 = recrypt.generateKeyPair();
    var kp2 = recrypt.generateKeyPair();
    var kp3 = recrypt.generateKeyPair();

    var result = recrypt.encapsulate(kp1.publicKey);
    var capsule = result['capsule'];
    var originalKey = result['symmetricKey'];

    // First re-encryption (Alice -> Bob)
    var rk1 = recrypt.generateReEncryptionKey(kp1.privateKey, kp2.publicKey);
    var reCapsule1 = recrypt.reEncrypt(capsule, rk1);
    var bobKey = recrypt.decapsulate(reCapsule1, kp2.privateKey);

    // Second re-encryption (Alice -> Charlie)
    var rk2 = recrypt.generateReEncryptionKey(kp1.privateKey, kp3.publicKey);
    var reCapsule2 = recrypt.reEncrypt(capsule, rk2);
    var charlieKey = recrypt.decapsulate(reCapsule2, kp3.privateKey);

    // Verify all keys match
    expect(bobKey, equals(originalKey));
    expect(charlieKey, equals(originalKey));
  });

  test('Delegation with Trent (Proxy)', () {
    var recrypt = Recrypt();

    // Use hardcoded keys from JavaScript implementation (converted to base64)
    var alicePrivateKey = PrivateKey.fromBase64(
        'bBwYvr58gkifJNROlh3dQ1OYtmAiy9DS+NdSUrz3WnSnBvAd');
    var bobPrivateKey =
        PrivateKey.fromBase64('94h2s6iv6fYnvz3bLrixs4Dt/NL41VJSvOdadKcPABM=');
    var charliePrivateKey =
        PrivateKey.fromBase64('Gg81JoFes6VayI7lOv5DpucnJWXvHczC8OEKZroxsRQ=');

    var alicePublicKey = alicePrivateKey.getPublicKey();
    var bobPublicKey = bobPrivateKey.getPublicKey();
    var charliePublicKey = charliePrivateKey.getPublicKey();

    // Generate a shared key for the group
    SharedEncryptor groupKeyEncryptor =
        SharedEncryptor.createSharableEncryptor(alicePublicKey);

    // Create a test message
    String messageString = Recrypt.generateSecureRandomMessage();
    print('Original message: $messageString');

    // Encrypt the message
    var encryptedPackage1 = groupKeyEncryptor.encryptAndPackage(messageString);
    print('Encrypted message package: $encryptedPackage1');

    // Test serialization
    var serialized1 = groupKeyEncryptor.toBase64();
    var deserialized1 = SharedEncryptor.fromBase64(serialized1);
    expect(deserialized1.capsule.toBase64(),
        equals(groupKeyEncryptor.capsule.toBase64()));
    expect(deserialized1.key, equals(groupKeyEncryptor.key));
    expect(deserialized1.iv.base64, equals(groupKeyEncryptor.iv.base64));

    // Alice generates re-encryption keys for Bob and Charlie
    var rkAB1 = recrypt.generateReEncryptionKey(alicePrivateKey, bobPublicKey);
    var rkAC1 =
        recrypt.generateReEncryptionKey(alicePrivateKey, charliePublicKey);

    // Print re-encryption keys for comparison
    print('Alice→Bob re-encryption key: ${rkAB1.toBase64()}');
    print('Alice→Charlie re-encryption key: ${rkAC1.toBase64()}');

    // Alice sends rkAB and rkAC to Trent (the proxy)
    // Trent re-encrypts the capsule for Bob and Charlie using only public keys
    var trentCapsuleB1 = recrypt.reEncrypt(groupKeyEncryptor.capsule, rkAB1);
    var trentCapsuleC1 = recrypt.reEncrypt(groupKeyEncryptor.capsule, rkAC1);

    // Serialize and deserialize the Trent capsules
    var trentCapsuleBBase64_1 = trentCapsuleB1.toBase64();
    var trentCapsuleCBase64_1 = trentCapsuleC1.toBase64();
    var deserializedTrentCapsuleB1 = Capsule.fromBase64(trentCapsuleBBase64_1);
    var deserializedTrentCapsuleC1 = Capsule.fromBase64(trentCapsuleCBase64_1);

    // Print re-encrypted capsules for comparison
    print('Trent re-encrypted capsule for Bob: $trentCapsuleBBase64_1');
    print('Trent re-encrypted capsule for Charlie: $trentCapsuleCBase64_1');

    // Bob and Charlie decapsulate their respective capsules
    var bobKey1 =
        recrypt.decapsulate(deserializedTrentCapsuleB1, bobPrivateKey);
    var charlieKey1 =
        recrypt.decapsulate(deserializedTrentCapsuleC1, charliePrivateKey);

    // Print decapsulated keys for comparison
    print(
        'Bob decapsulated key: ${bobKey1.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
    print(
        'Charlie decapsulated key: ${charlieKey1.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');

    // Verify all keys match
    expect(bobKey1, equals(groupKeyEncryptor.key));
    expect(charlieKey1, equals(groupKeyEncryptor.key));

    // Decrypt the message using Bob's and Charlie's keys
    var bobDecrypted1 =
        SharedEncryptor.unpackAndDecrypt(encryptedPackage1, bobKey1);
    var charlieDecrypted1 =
        SharedEncryptor.unpackAndDecrypt(encryptedPackage1, charlieKey1);

    print('Bob decrypted message: $bobDecrypted1');
    print('Charlie decrypted message: $charlieDecrypted1');

    // Verify decrypted messages match the original
    expect(bobDecrypted1, equals(messageString));
    expect(charlieDecrypted1, equals(messageString));

    // Test serialization of re-encryption keys and capsules
    var rkABBase64_1 = rkAB1.toBase64();
    var rkACBase64_1 = rkAC1.toBase64();

    // Verify deserialized re-encryption keys
    var deserializedRKAB1 = ReEncryptionKey.fromBase64(rkABBase64_1);
    var deserializedRKAC1 = ReEncryptionKey.fromBase64(rkACBase64_1);
    expect(deserializedRKAB1.scalar.value, equals(rkAB1.scalar.value));
    expect(deserializedRKAC1.scalar.value, equals(rkAC1.scalar.value));

    // Verify deserialized capsules
    expect(deserializedTrentCapsuleB1.isReEncrypted, isTrue);
    expect(deserializedTrentCapsuleC1.isReEncrypted, isTrue);

    // Verify decapsulation still works with deserialized capsules
    var bobKeyFromDeserialized1 =
        recrypt.decapsulate(deserializedTrentCapsuleB1, bobPrivateKey);
    var charlieKeyFromDeserialized1 =
        recrypt.decapsulate(deserializedTrentCapsuleC1, charliePrivateKey);
    expect(bobKeyFromDeserialized1, equals(groupKeyEncryptor.key));
    expect(charlieKeyFromDeserialized1, equals(groupKeyEncryptor.key));

    // Verify decryption still works with deserialized keys
    var bobDecryptedFromDeserialized1 = SharedEncryptor.unpackAndDecrypt(
        encryptedPackage1, bobKeyFromDeserialized1);
    var charlieDecryptedFromDeserialized1 = SharedEncryptor.unpackAndDecrypt(
        encryptedPackage1, charlieKeyFromDeserialized1);

    expect(bobDecryptedFromDeserialized1, equals(messageString));
    expect(charlieDecryptedFromDeserialized1, equals(messageString));
  });

  test('Delegation with Trent (Proxy) - Generated Keys', () {
    var recrypt = Recrypt();

    // Generate new key pairs
    var aliceKeyPair = recrypt.generateKeyPair();
    var bobKeyPair = recrypt.generateKeyPair();
    var charlieKeyPair = recrypt.generateKeyPair();

    var alicePrivateKey = aliceKeyPair.privateKey;
    var bobPrivateKey = bobKeyPair.privateKey;
    var charliePrivateKey = charlieKeyPair.privateKey;

    var alicePublicKey = aliceKeyPair.publicKey;
    var bobPublicKey = bobKeyPair.publicKey;
    var charliePublicKey = charlieKeyPair.publicKey;

    // Generate a shared key for Alice
    SharedEncryptor sharedEncryptor =
        SharedEncryptor.createSharableEncryptor(alicePublicKey);

    // Create a test message
    String groupMessageSharedKey = Recrypt.generateSecureRandomMessage();
    print('Original message: $groupMessageSharedKey');
    groupMessageSharedKey = 'Hello, world!';

    // Encrypt the message
    var encryptedSharedGroupKey =
        sharedEncryptor.encryptAndPackage(groupMessageSharedKey);
    print('Encrypted message package: $encryptedSharedGroupKey');

    // Test serialization
    var serialized2 = sharedEncryptor.toBase64();
    var deserialized2 = SharedEncryptor.fromBase64(serialized2);
    expect(deserialized2.capsule.toBase64(),
        equals(sharedEncryptor.capsule.toBase64()));
    expect(deserialized2.key, equals(sharedEncryptor.key));
    expect(deserialized2.iv.base64, equals(sharedEncryptor.iv.base64));

    // Alice generates re-encryption keys for Bob and Charlie
    var rkAB2 = recrypt.generateReEncryptionKey(
      alicePrivateKey,
      bobPublicKey,
    );
    var rkAC2 = recrypt.generateReEncryptionKey(
      alicePrivateKey,
      charliePublicKey,
    );

    // Print re-encryption keys for comparison
    print('Alice→Bob re-encryption key (Generated): ${rkAB2.toBase64()}');
    print('Alice→Charlie re-encryption key (Generated): ${rkAC2.toBase64()}');

    // Alice sends rkAB and rkAC to Trent (the proxy)
    // Trent re-encrypts the capsule for Bob and Charlie using only public keys
    var trentCapsuleB2 = recrypt.reEncrypt(sharedEncryptor.capsule, rkAB2);
    var trentCapsuleC2 = recrypt.reEncrypt(sharedEncryptor.capsule, rkAC2);

    // Serialize and deserialize the Trent capsules
    var trentCapsuleBBase64_2 = trentCapsuleB2.toBase64();
    var trentCapsuleCBase64_2 = trentCapsuleC2.toBase64();
    var deserializedTrentCapsuleB2 = Capsule.fromBase64(trentCapsuleBBase64_2);
    var deserializedTrentCapsuleC2 = Capsule.fromBase64(trentCapsuleCBase64_2);

    // Print re-encrypted capsules for comparison
    print(
        'Trent re-encrypted capsule for Bob (Generated): $trentCapsuleBBase64_2');
    print(
        'Trent re-encrypted capsule for Charlie (Generated): $trentCapsuleCBase64_2');

    // Bob and Charlie decapsulate their respective capsules
    var bobKey2 =
        recrypt.decapsulate(deserializedTrentCapsuleB2, bobPrivateKey);
    var charlieKey2 =
        recrypt.decapsulate(deserializedTrentCapsuleC2, charliePrivateKey);

    // Print decapsulated keys for comparison
    print(
        'Bob decapsulated key (Generated): ${bobKey2.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
    print(
        'Charlie decapsulated key (Generated): ${charlieKey2.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');

    // Verify all keys match
    expect(bobKey2, equals(sharedEncryptor.key));
    expect(charlieKey2, equals(sharedEncryptor.key));

    // Decrypt the message using Bob's and Charlie's keys
    var bobDecrypted2 =
        SharedEncryptor.unpackAndDecrypt(encryptedSharedGroupKey, bobKey2);
    var charlieDecrypted2 =
        SharedEncryptor.unpackAndDecrypt(encryptedSharedGroupKey, charlieKey2);

    print('Bob decrypted message: $bobDecrypted2');
    print('Charlie decrypted message: $charlieDecrypted2');

    // Verify decrypted messages match the original
    expect(bobDecrypted2, equals(groupMessageSharedKey));
    expect(charlieDecrypted2, equals(groupMessageSharedKey));

    // Test serialization of re-encryption keys and capsules
    var rkABBase64_2 = rkAB2.toBase64();
    var rkACBase64_2 = rkAC2.toBase64();

    // Verify deserialized re-encryption keys
    var deserializedRKAB2 = ReEncryptionKey.fromBase64(rkABBase64_2);
    var deserializedRKAC2 = ReEncryptionKey.fromBase64(rkACBase64_2);
    expect(deserializedRKAB2.scalar.value, equals(rkAB2.scalar.value));
    expect(deserializedRKAC2.scalar.value, equals(rkAC2.scalar.value));

    // Verify deserialized capsules
    expect(deserializedTrentCapsuleB2.isReEncrypted, isTrue);
    expect(deserializedTrentCapsuleC2.isReEncrypted, isTrue);

    // Verify decapsulation still works with deserialized capsules
    var bobKeyFromDeserialized2 =
        recrypt.decapsulate(deserializedTrentCapsuleB2, bobPrivateKey);
    var charlieKeyFromDeserialized2 =
        recrypt.decapsulate(deserializedTrentCapsuleC2, charliePrivateKey);
    expect(bobKeyFromDeserialized2, equals(sharedEncryptor.key));
    expect(charlieKeyFromDeserialized2, equals(sharedEncryptor.key));

    // Verify decryption still works with deserialized keys
    var bobDecryptedFromDeserialized2 = SharedEncryptor.unpackAndDecrypt(
        encryptedSharedGroupKey, bobKeyFromDeserialized2);
    var charlieDecryptedFromDeserialized2 = SharedEncryptor.unpackAndDecrypt(
        encryptedSharedGroupKey, charlieKeyFromDeserialized2);

    expect(bobDecryptedFromDeserialized2, equals(groupMessageSharedKey));
    expect(charlieDecryptedFromDeserialized2, equals(groupMessageSharedKey));
  });

  group('KeyPair Serialization Tests', () {
    late Recrypt recrypt;
    late KeyPair keyPair;

    setUp(() {
      recrypt = Recrypt();
      keyPair = recrypt.generateKeyPair();
    });

    test('JSON serialization and deserialization', () {
      // Convert to JSON
      Map<String, String> json = keyPair.toJson();

      // Verify JSON structure
      expect(json['privateKey'], isA<String>());
      expect(json['publicKey'], isA<String>());

      // Convert back from JSON
      var reconstructedKeyPair = KeyPair.fromJson(jsonEncode(json));

      // Verify the reconstructed key pair matches the original
      expect(reconstructedKeyPair.privateKey.toBase64(),
          equals(keyPair.privateKey.toBase64()));
      expect(reconstructedKeyPair.publicKey.toBase64(),
          equals(keyPair.publicKey.toBase64()));
    });

    test('Base64 serialization and deserialization', () {
      // Convert to base64
      String base64 = keyPair.toBase64();

      // Convert back from base64
      var reconstructedKeyPair = KeyPair.fromBase64(base64);

      // Verify the reconstructed key pair matches the original
      expect(reconstructedKeyPair.privateKey.toBase64(),
          equals(keyPair.privateKey.toBase64()));
      expect(reconstructedKeyPair.publicKey.toBase64(),
          equals(keyPair.publicKey.toBase64()));
    });

    test('Public key only base64 serialization and deserialization', () {
      // Convert only public key to base64
      String publicKeyBase64 = keyPair.publicKeyToBase64();

      // Create key pair with only public key
      var publicKeyOnlyPair = KeyPair.fromPublicKeyBase64(publicKeyBase64);

      // Verify the public key matches
      expect(publicKeyOnlyPair.publicKey.toBase64(),
          equals(keyPair.publicKey.toBase64()));

      // Verify the private key is a dummy key (zero)
      expect(publicKeyOnlyPair.privateKey.toBase64(),
          isNot(equals(keyPair.privateKey.toBase64())));
    });

    test('Invalid base64 deserialization', () {
      // Test with invalid base64 string (properly padded but wrong length)
      String invalidBase64 = base64Encode(List<int>.filled(50, 0)); // Too short
      expect(() => KeyPair.fromBase64(invalidBase64), throwsArgumentError);

      // Test with base64 string of wrong length
      String shortBase64 = base64Encode(List<int>.filled(30, 0)); // Too short
      expect(() => KeyPair.fromBase64(shortBase64), throwsArgumentError);

      String longBase64 = base64Encode(List<int>.filled(150, 0)); // Too long
      expect(() => KeyPair.fromBase64(longBase64), throwsArgumentError);
    });

    test('Invalid JSON deserialization', () {
      // Test with invalid JSON
      expect(() => KeyPair.fromJson('invalid_json'), throwsFormatException);

      // Test with JSON missing required fields
      expect(() => KeyPair.fromJson('{"privateKey": "some_key"}'),
          throwsA(isA<TypeError>()));
      expect(() => KeyPair.fromJson('{"publicKey": "some_key"}'),
          throwsA(isA<TypeError>()));

      // Test with invalid base64 in JSON fields (properly padded but wrong length)
      String invalidBase64 = base64Encode(List<int>.filled(50, 0));
      expect(
          () => KeyPair.fromJson(
              '{"privateKey": "$invalidBase64", "publicKey": "$invalidBase64"}'),
          throwsArgumentError);
    });

    test('Round trip serialization consistency', () {
      // Test multiple round trips
      var currentKeyPair = keyPair;

      for (var i = 0; i < 3; i++) {
        // JSON round trip
        Map<String, String> json = currentKeyPair.toJson();
        currentKeyPair = KeyPair.fromJson(jsonEncode(json));

        // Base64 round trip
        String base64 = currentKeyPair.toBase64();
        currentKeyPair = KeyPair.fromBase64(base64);
      }

      // Verify the final key pair still matches the original
      expect(currentKeyPair.privateKey.toBase64(),
          equals(keyPair.privateKey.toBase64()));
      expect(currentKeyPair.publicKey.toBase64(),
          equals(keyPair.publicKey.toBase64()));
    });
  });

  test('Bidirectional Group Communication with Alice as Admin and Member', () {
    var recrypt = Recrypt();

    // Generate key pairs for all participants
    var aliceKeyPair = recrypt.generateKeyPair();
    var bobKeyPair = recrypt.generateKeyPair();
    var charlieKeyPair = recrypt.generateKeyPair();

    var alicePrivateKey = aliceKeyPair.privateKey;
    var bobPrivateKey = bobKeyPair.privateKey;
    var charliePrivateKey = charlieKeyPair.privateKey;

    var alicePublicKey = aliceKeyPair.publicKey;
    var bobPublicKey = bobKeyPair.publicKey;
    var charliePublicKey = charlieKeyPair.publicKey;

    // Create a group key pair (controlled by Alice)
    var groupKeyPair = recrypt.generateKeyPair();
    var groupPrivateKey = groupKeyPair.privateKey;
    var groupPublicKey = groupKeyPair.publicKey;

    // Generate re-encryption keys for the group
    var rkGroupToAlice =
        recrypt.generateReEncryptionKey(groupPrivateKey, alicePublicKey);
    var rkGroupToBob =
        recrypt.generateReEncryptionKey(groupPrivateKey, bobPublicKey);
    var rkGroupToCharlie =
        recrypt.generateReEncryptionKey(groupPrivateKey, charliePublicKey);

    // Test 1: Alice sends a message to the group
    print('\nTest 1: Alice sending message to group');
    String aliceMessage = 'Hello from Alice to the group!';

    // Create a shared encryptor for Alice's message
    SharedEncryptor aliceEncryptor =
        SharedEncryptor.createSharableEncryptor(groupPublicKey);

    // Encrypt the message
    var aliceEncryptedPackage = aliceEncryptor.encryptAndPackage(aliceMessage);
    print('Alice encrypted message package: $aliceEncryptedPackage');

    // Serialize both the encryptor and encrypted package to send to Trent
    var serializedEncryptor = aliceEncryptor.toBase64();
    var serializedEncryptedPackage =
        base64Encode(utf8.encode(aliceEncryptedPackage));
    print('Serialized encryptor: $serializedEncryptor');
    print('Serialized encrypted package: $serializedEncryptedPackage');

    // Trent deserializes both the encryptor and encrypted package
    var trentEncryptor = SharedEncryptor.fromBase64(serializedEncryptor);
    var trentEncryptedPackage =
        utf8.decode(base64Decode(serializedEncryptedPackage));
    print(
        'Trent deserialized encryptor capsule: ${trentEncryptor.capsule.toBase64()}');

    // Verify the deserialized encryptor matches the original
    expect(trentEncryptor.capsule.toBase64(),
        equals(aliceEncryptor.capsule.toBase64()));
    expect(trentEncryptor.key, equals(aliceEncryptor.key));
    expect(trentEncryptor.iv.base64, equals(aliceEncryptor.iv.base64));
    expect(trentEncryptedPackage, equals(aliceEncryptedPackage));

    // Trent re-encrypts for each member using the deserialized encryptor
    var trentCapsuleForAlice =
        recrypt.reEncrypt(trentEncryptor.capsule, rkGroupToAlice);
    var trentCapsuleForBob =
        recrypt.reEncrypt(trentEncryptor.capsule, rkGroupToBob);
    var trentCapsuleForCharlie =
        recrypt.reEncrypt(trentEncryptor.capsule, rkGroupToCharlie);

    // Each member decapsulates and decrypts using the deserialized encrypted package
    var aliceKey = recrypt.decapsulate(trentCapsuleForAlice, alicePrivateKey);
    var bobKey = recrypt.decapsulate(trentCapsuleForBob, bobPrivateKey);
    var charlieKey =
        recrypt.decapsulate(trentCapsuleForCharlie, charliePrivateKey);

    var aliceDecrypted =
        SharedEncryptor.unpackAndDecrypt(trentEncryptedPackage, aliceKey);
    var bobDecrypted =
        SharedEncryptor.unpackAndDecrypt(trentEncryptedPackage, bobKey);
    var charlieDecrypted =
        SharedEncryptor.unpackAndDecrypt(trentEncryptedPackage, charlieKey);

    expect(aliceDecrypted, equals(aliceMessage));
    expect(bobDecrypted, equals(aliceMessage));
    expect(charlieDecrypted, equals(aliceMessage));

    // Test 2: Bob sends a message to the group
    print('\nTest 2: Bob sending message to group');
    String bobMessage = 'Hello from Bob to the group!';

    // Create a new shared encryptor for Bob's message
    SharedEncryptor bobEncryptor =
        SharedEncryptor.createSharableEncryptor(groupPublicKey);

    // Encrypt the message
    var bobEncryptedPackage = bobEncryptor.encryptAndPackage(bobMessage);
    print('Bob encrypted message package: $bobEncryptedPackage');

    // Trent re-encrypts for each member
    var trentCapsuleForAlice2 =
        recrypt.reEncrypt(bobEncryptor.capsule, rkGroupToAlice);
    var trentCapsuleForBob2 =
        recrypt.reEncrypt(bobEncryptor.capsule, rkGroupToBob);
    var trentCapsuleForCharlie2 =
        recrypt.reEncrypt(bobEncryptor.capsule, rkGroupToCharlie);

    // Each member decapsulates and decrypts
    var aliceKey2 = recrypt.decapsulate(trentCapsuleForAlice2, alicePrivateKey);
    var bobKey2 = recrypt.decapsulate(trentCapsuleForBob2, bobPrivateKey);
    var charlieKey2 =
        recrypt.decapsulate(trentCapsuleForCharlie2, charliePrivateKey);

    var aliceDecrypted2 =
        SharedEncryptor.unpackAndDecrypt(bobEncryptedPackage, aliceKey2);
    var bobDecrypted2 =
        SharedEncryptor.unpackAndDecrypt(bobEncryptedPackage, bobKey2);
    var charlieDecrypted2 =
        SharedEncryptor.unpackAndDecrypt(bobEncryptedPackage, charlieKey2);

    expect(aliceDecrypted2, equals(bobMessage));
    expect(bobDecrypted2, equals(bobMessage));
    expect(charlieDecrypted2, equals(bobMessage));

    // Test 3: Charlie sends a message to the group
    print('\nTest 3: Charlie sending message to group');
    String charlieMessage = 'Hello from Charlie to the group!';

    // Create a new shared encryptor for Charlie's message
    SharedEncryptor charlieEncryptor =
        SharedEncryptor.createSharableEncryptor(groupPublicKey);

    // Encrypt the message
    var charlieEncryptedPackage =
        charlieEncryptor.encryptAndPackage(charlieMessage);
    print('Charlie encrypted message package: $charlieEncryptedPackage');

    // Trent re-encrypts for each member
    var trentCapsuleForAlice3 =
        recrypt.reEncrypt(charlieEncryptor.capsule, rkGroupToAlice);
    var trentCapsuleForBob3 =
        recrypt.reEncrypt(charlieEncryptor.capsule, rkGroupToBob);
    var trentCapsuleForCharlie3 =
        recrypt.reEncrypt(charlieEncryptor.capsule, rkGroupToCharlie);

    // Each member decapsulates and decrypts
    var aliceKey3 = recrypt.decapsulate(trentCapsuleForAlice3, alicePrivateKey);
    var bobKey3 = recrypt.decapsulate(trentCapsuleForBob3, bobPrivateKey);
    var charlieKey3 =
        recrypt.decapsulate(trentCapsuleForCharlie3, charliePrivateKey);

    var aliceDecrypted3 =
        SharedEncryptor.unpackAndDecrypt(charlieEncryptedPackage, aliceKey3);
    var bobDecrypted3 =
        SharedEncryptor.unpackAndDecrypt(charlieEncryptedPackage, bobKey3);
    var charlieDecrypted3 =
        SharedEncryptor.unpackAndDecrypt(charlieEncryptedPackage, charlieKey3);

    expect(aliceDecrypted3, equals(charlieMessage));
    expect(bobDecrypted3, equals(charlieMessage));
    expect(charlieDecrypted3, equals(charlieMessage));

    // Test serialization of group components
    print('\nTesting serialization of group components');

    // Serialize and deserialize re-encryption keys
    var rkGroupToAliceBase64 = rkGroupToAlice.toBase64();
    var rkGroupToBobBase64 = rkGroupToBob.toBase64();
    var rkGroupToCharlieBase64 = rkGroupToCharlie.toBase64();

    var deserializedRKGroupToAlice =
        ReEncryptionKey.fromBase64(rkGroupToAliceBase64);
    var deserializedRKGroupToBob =
        ReEncryptionKey.fromBase64(rkGroupToBobBase64);
    var deserializedRKGroupToCharlie =
        ReEncryptionKey.fromBase64(rkGroupToCharlieBase64);

    // Verify deserialized re-encryption keys
    expect(deserializedRKGroupToAlice.scalar.value,
        equals(rkGroupToAlice.scalar.value));
    expect(deserializedRKGroupToBob.scalar.value,
        equals(rkGroupToBob.scalar.value));
    expect(deserializedRKGroupToCharlie.scalar.value,
        equals(rkGroupToCharlie.scalar.value));

    // Create a new encryptor for the serialization test
    SharedEncryptor testEncryptor =
        SharedEncryptor.createSharableEncryptor(groupPublicKey);
    var testMessage = 'Test message for serialization';
    var testEncryptedPackage = testEncryptor.encryptAndPackage(testMessage);

    // Re-encrypt using deserialized keys
    var testTrentCapsuleForAlice =
        recrypt.reEncrypt(testEncryptor.capsule, deserializedRKGroupToAlice);
    var testTrentCapsuleForBob =
        recrypt.reEncrypt(testEncryptor.capsule, deserializedRKGroupToBob);
    var testTrentCapsuleForCharlie =
        recrypt.reEncrypt(testEncryptor.capsule, deserializedRKGroupToCharlie);

    // Decapsulate and decrypt
    var testAliceKey =
        recrypt.decapsulate(testTrentCapsuleForAlice, alicePrivateKey);
    var testBobKey = recrypt.decapsulate(testTrentCapsuleForBob, bobPrivateKey);
    var testCharlieKey =
        recrypt.decapsulate(testTrentCapsuleForCharlie, charliePrivateKey);

    var testAliceDecrypted =
        SharedEncryptor.unpackAndDecrypt(testEncryptedPackage, testAliceKey);
    var testBobDecrypted =
        SharedEncryptor.unpackAndDecrypt(testEncryptedPackage, testBobKey);
    var testCharlieDecrypted =
        SharedEncryptor.unpackAndDecrypt(testEncryptedPackage, testCharlieKey);

    expect(testAliceDecrypted, equals(testMessage));
    expect(testBobDecrypted, equals(testMessage));
    expect(testCharlieDecrypted, equals(testMessage));
  });
}
