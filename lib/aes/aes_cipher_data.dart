import 'dart:typed_data';

abstract class AESCipherData<T extends Object> {
  final T value;

  const AESCipherData({
    required this.value,
  });
}

class AESEncryptedData<T extends Object> extends AESCipherData<T> {
  final Uint8List iv;

  const AESEncryptedData({
    required this.iv,
    required super.value,
  });
}

class AESDecryptedData<T extends Object> extends AESCipherData<T> {
  const AESDecryptedData({
    required super.value,
  });
}
