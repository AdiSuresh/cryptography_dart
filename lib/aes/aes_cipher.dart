import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography_dart/aes/aes_cipher_data.dart';
import 'package:cryptography_dart/cipher_utils.dart';
import 'package:pointycastle/export.dart';

enum AesKeySize {
  aes128,
  aes192,
  aes256,
}

extension AesKeySizeExtension on AesKeySize {
  int get value {
    return switch (this) {
      AesKeySize.aes128 => 128,
      AesKeySize.aes192 => 192,
      AesKeySize.aes256 => 256,
    };
  }
}

class AesCipher {
  static const keySizes = [128, 192, 256];
  static const blockSize = 16;

  final Uint8List key;
  final FortunaRandom _prng;

  AesCipher({
    required this.key,
    FortunaRandom? prng,
  })  : assert(keySizes.contains(key.length * 8)),
        _prng = prng ?? CipherUtils.createFortunaPRNG();

  factory AesCipher.fresh({
    AesKeySize keySize = AesKeySize.aes256,
    FortunaRandom? prng,
  }) {
    prng ??= CipherUtils.createFortunaPRNG();
    final result = AesCipher(
      key: prng.nextBytes(
        keySize.value ~/ 8,
      ),
      prng: prng,
    );
    return result;
  }

  AESEncryptedData<Uint8List> encrypt(
    String text,
  ) {
    final (iv, value) = _performCipher(
      AESDecryptedData(
        value: _pad(
          utf8.encode(
            text,
          ),
        ),
      ),
    );
    return AESEncryptedData(
      iv: iv,
      value: value,
    );
  }

  Uint8List _pad(
    Uint8List bytes,
  ) {
    final padLength = blockSize - (bytes.length % blockSize);
    final padded = Uint8List(
      bytes.length + padLength,
    )..setAll(
        0,
        bytes,
      );
    PKCS7Padding().addPadding(
      padded,
      bytes.length,
    );
    return padded;
  }

  AESDecryptedData<Uint8List> decrypt(
    AESEncryptedData<Uint8List> cipherText,
  ) {
    assert(cipherText.iv.length == blockSize);
    final (_, value) = _performCipher(
      cipherText,
    );
    return AESDecryptedData(
      value: value,
    );
  }

  AESDecryptedData<String> decryptToString(
    AESEncryptedData<Uint8List> cipherText,
  ) {
    final paddedDecryptedBytes = decrypt(
      cipherText,
    );
    final decryptedBytes = _unpad(
      paddedDecryptedBytes.value,
    );
    final decryptedText = utf8.decode(
      decryptedBytes,
    );
    return AESDecryptedData(
      value: decryptedText,
    );
  }

  Uint8List _unpad(
    Uint8List padded,
  ) {
    final padBytes = PKCS7Padding().padCount(
      padded,
    );
    return padded.sublist(
      0,
      padded.length - padBytes,
    );
  }

  (Uint8List, Uint8List) _performCipher(
    AESCipherData<Uint8List> data,
  ) {
    final (forEncryption, iv) = switch (data) {
      AESEncryptedData<Uint8List> e => (false, e.iv),
      AESDecryptedData<Uint8List> _ => (true, _prng.nextBytes(blockSize)),
    };
    final cipher = CBCBlockCipher(
      AESEngine(),
    )..init(
        forEncryption,
        ParametersWithIV(
          KeyParameter(
            key,
          ),
          iv,
        ),
      );
    final paddedBytes = data.value;
    final result = Uint8List(
      paddedBytes.length,
    );
    var offset = 0;
    while (offset < paddedBytes.length) {
      offset += cipher.processBlock(
        paddedBytes,
        offset,
        result,
        offset,
      );
    }
    assert(offset == paddedBytes.length);
    return (iv, result);
  }
}
