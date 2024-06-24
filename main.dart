import 'dart:convert';
import 'package:cryptography_dart/aes/aes_cbc_cipher.dart';

void main(List<String> args) {
  const testcases = [
    'Lorem ipsum dolor sit amet, consectetur adipiscing elit',
  ];
  final cipher = AesCbcCipher.fresh();
  final t1 = DateTime.now();
  for (var i = 0; i < 1; i++) {
    for (final message in testcases) {
      print('message: ${utf8.encode(message)}');
      final encrypted = cipher.encrypt(
        message,
      );
      print('encrypted.value: ${encrypted.value}');
      final decrypted = cipher.decrypt(
        encrypted,
      );
      print('decrypted.value: ${decrypted.value}');
    }
  }
  final t2 = DateTime.now();
  final total = t2.difference(t1).inMilliseconds;
  print('total: $total ms');
}
