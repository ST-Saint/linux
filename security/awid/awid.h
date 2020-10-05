#ifndef __AWID_H_
#define __AWID_H_

void ToChar(unsigned char *chr, unsigned long n) {
  int i;
  for (i = 0; i < 4; ++i) {
    chr[i] = (unsigned char)((unsigned long)n >> (i * 8) & 0xffu);
  }
}

unsigned long ToUnsignedLong(unsigned char *chr) {
  unsigned long n = 0;
  int i;
  for (i = 3; i >= 0; --i) {
    n = (n << 8) | chr[i];
  }
  return n;
}

#endif // __AWID_H_
