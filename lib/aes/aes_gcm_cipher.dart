import 'dart:typed_data';
import 'package:cryptography_dart/aes/aes_cipher_base.dart';
import 'package:cryptography_dart/aes/aes_cipher_data.dart';
import 'package:cryptography_dart/aes/aes_key_size.dart';
import 'package:cryptography_dart/cipher_utils.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

class AesGcmCipher extends AesCipherBase {
  AesGcmCipher({
    required super.key,
    FortunaRandom? prng,
  }) : super(
          prng: prng,
        );

  factory AesGcmCipher.fresh({
    AesKeySize keySize = AesKeySize.aes256,
    FortunaRandom? prng,
  }) {
    prng ??= CipherUtils.createFortunaPRNG();
    final result = AesGcmCipher(
      key: prng.nextBytes(
        keySize.value ~/ 8,
      ),
      prng: prng,
    );
    return result;
  }

  @protected
  (Uint8List, Uint8List) performCipher(
    AESCipherData<Uint8List> data,
  ) {
    final (forEncryption, iv) = preProcess(
      data,
    );
    final cipher = GCMBlockCipher(
      AESEngine(),
    )..init(
        forEncryption,
        AEADParameters(
          KeyParameter(
            key,
          ),
          128,
          iv,
          Uint8List(0),
        ),
      );
    final result = cipher.process(
      data.value,
    );
    return (iv, result);
  }
}
