import 'dart:typed_data';
import 'package:cryptography_dart/aes/aes_cipher_base.dart';
import 'package:cryptography_dart/aes/aes_cipher_data.dart';
import 'package:cryptography_dart/aes/aes_key_size.dart';
import 'package:cryptography_dart/cipher_utils.dart';
import 'package:pointycastle/export.dart';

class AesCbcCipher extends AesCipherBase {
  AesCbcCipher({
    required super.key,
    FortunaRandom? prng,
  }) : super(
          prng: prng,
        );

  factory AesCbcCipher.fresh({
    AesKeySize keySize = AesKeySize.aes256,
    FortunaRandom? prng,
  }) {
    prng ??= CipherUtils.createFortunaPRNG();
    final result = AesCbcCipher(
      key: prng.nextBytes(
        keySize.value ~/ 8,
      ),
      prng: prng,
    );
    return result;
  }

  @override
  (Uint8List, Uint8List) performCipher(
    AESCipherData<Uint8List> data,
  ) {
    final (forEncryption, iv) = preProcess(
      data,
    );
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
