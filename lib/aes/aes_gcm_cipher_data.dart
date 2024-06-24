import 'dart:typed_data';

import 'package:cryptography_dart/aes/aes_cipher_data.dart';

class AesGcmEncryptedData extends AESEncryptedData {
  final Uint8List tag;

  AesGcmEncryptedData({
    required super.iv,
    required super.value,
    required this.tag,
  });
}
