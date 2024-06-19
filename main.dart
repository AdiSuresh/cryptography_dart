import 'package:cryptography_dart/aes/aes_cipher.dart';

void main(List<String> args) {
  const testcases = [
    'Lorem ipsum dolor sit amet, consectetur adipiscing elit',
  ];
  final cipher = AesCipher.fresh();
  final t1 = DateTime.now();
  for (var i = 0; i < 1; i++) {
    for (var message in testcases) {
      final encrypted = cipher.encrypt(
        message,
      );
      final _ = cipher.decryptToString(
        encrypted,
      );
    }
  }
  final t2 = DateTime.now();
  final total = t2.difference(t1).inMilliseconds;
  print('total: $total ms');
}
