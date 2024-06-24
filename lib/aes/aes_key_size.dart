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
