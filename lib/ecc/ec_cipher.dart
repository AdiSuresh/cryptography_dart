import 'dart:typed_data';
import 'package:cryptography_dart/aes/aes_cipher.dart';
import 'package:cryptography_dart/cipher_utils.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/key_derivators/ecdh_kdf.dart';

class ECCipher {
  final ECPrivateKey privateKey;
  final ECPublicKey publicKey;
  final FortunaRandom _prng;

  const ECCipher({
    required this.privateKey,
    required this.publicKey,
    required FortunaRandom prng,
  }) : _prng = prng;

  factory ECCipher.fresh() {
    final prng = CipherUtils.createFortunaPRNG();
    final keyPair = CipherUtils().generateECKeyPair(
      prng: prng,
    );
    return ECCipher(
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      prng: prng,
    );
  }

  ECSignature generateSignature(
    String message,
  ) {
    final signer = ECDSASigner(
      SHA256Digest(),
    )..init(
        true,
        ParametersWithRandom(
          PrivateKeyParameter(
            privateKey,
          ),
          _prng,
        ),
      );
    final result = signer.generateSignature(
      Uint8List.fromList(
        message.codeUnits,
      ),
    ) as ECSignature;
    return result;
  }

  Uint8List deriveKey(
    ECPublicKey publicKey, [
    int keySize = 32,
  ]) {
    assert(AesCipher.keySizes.contains(keySize * 8));
    final derivator = ECDHKeyDerivator()
      ..init(
        ECDHKDFParameters(
          privateKey,
          publicKey,
        ),
      );
    return derivator
        .process(
          Uint8List(32),
        )
        .sublist(
          0,
          keySize,
        );
  }

  bool verifySignature(
    String message,
    ECSignature signature,
    ECPublicKey publicKey,
  ) {
    final signer = ECDSASigner(
      SHA256Digest(),
    )..init(
        false,
        PublicKeyParameter(
          publicKey,
        ),
      );
    final result = signer.verifySignature(
      Uint8List.fromList(
        message.codeUnits,
      ),
      signature,
    );
    return result;
  }
}
