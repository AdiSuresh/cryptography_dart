import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography_dart/aes/aes_cipher_data.dart';
import 'package:cryptography_dart/cipher_utils.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

abstract class AesCipherBase {
  static const keySizes = [128, 192, 256];
  static const blockSize = 16;

  final Uint8List key;

  @protected
  final FortunaRandom prng;

  AesCipherBase({
    required this.key,
    FortunaRandom? prng,
  })  : assert(keySizes.contains(key.length * 8)),
        prng = prng ?? CipherUtils.createFortunaPRNG();

  AESEncryptedData<Uint8List> encrypt(
    String text,
  ) {
    final (iv, value) = performCipher(
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
    final (_, value) = performCipher(
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

  @protected
  (bool, Uint8List) preProcess(
    AESCipherData<Uint8List> data,
  ) {
    return switch (data) {
      AESEncryptedData<Uint8List> e => (
          false,
          e.iv,
        ),
      AESDecryptedData<Uint8List> _ => (
          true,
          prng.nextBytes(
            blockSize,
          ),
        ),
    };
  }

  @protected
  (Uint8List, Uint8List) performCipher(
    AESCipherData<Uint8List> data,
  );
}
