import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

class IV {
  final Uint8List _bytes;

  IV(Uint8List bytes) : _bytes = Uint8List.fromList(bytes);

  IV.fromBase16(String encoded) : this(_decodeHex(encoded));

  IV.fromBase64(String encoded) : this(base64Decode(encoded));

  IV.fromUtf8(String input) : this(Uint8List.fromList(utf8.encode(input)));

  IV.fromLength(int length) : this(_randomBytes(length));

  IV.fromSecureRandom(int length) : this(_randomBytes(length));

  IV.allZerosOfLength(int length) : this(Uint8List(length));

  Uint8List get bytes => Uint8List.fromList(_bytes);

  String get base16 =>
      _bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

  String get base64 => base64Encode(_bytes);

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! IV) return false;
    return _hasSameBytes(_bytes, other._bytes);
  }

  @override
  int get hashCode => Object.hashAll(_bytes);

  static Uint8List _randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(
        List<int>.generate(length, (_) => random.nextInt(256)));
  }

  static Uint8List _decodeHex(String encoded) {
    final sanitized = encoded.replaceAll(' ', '');
    if (sanitized.length.isOdd) {
      throw const FormatException('Invalid hex string length.');
    }
    final result = Uint8List(sanitized.length ~/ 2);
    for (var i = 0; i < sanitized.length; i += 2) {
      result[i ~/ 2] = int.parse(sanitized.substring(i, i + 2), radix: 16);
    }
    return result;
  }

  static bool _hasSameBytes(List<int> a, List<int> b) {
    if (identical(a, b)) return true;
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
