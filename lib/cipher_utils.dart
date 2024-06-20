import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography_dart/ecc/ec_cipher.dart';
import 'package:pointycastle/export.dart';

class CipherUtils {
  static FortunaRandom createFortunaPRNG() {
    final random = Random.secure();
    final key = Uint8List.fromList(
      List.generate(
        32,
        (_) => random.nextInt(
          256,
        ),
      ),
    );
    final result = FortunaRandom()
      ..seed(
        KeyParameter(
          key,
        ),
      );
    return result;
  }

  AsymmetricKeyPair<ECPublicKey, ECPrivateKey> generateECKeyPair({
    SecureRandom? prng,
  }) {
    prng ??= createFortunaPRNG();
    final keyGen = ECKeyGenerator()
      ..init(
        ParametersWithRandom(
          ECKeyGeneratorParameters(
            ECCipher.domainParameters,
          ),
          prng,
        ),
      );
    final keyPair = keyGen.generateKeyPair();
    return AsymmetricKeyPair(
      keyPair.publicKey as ECPublicKey,
      keyPair.privateKey as ECPrivateKey,
    );
  }
}
