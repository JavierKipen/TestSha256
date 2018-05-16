#include <iostream>
#include <vector>
#include "picosha2.h"


void main(void)
{
	std::string src_str = "The quick brown fox jumps over the lazy dog";

	std::vector<unsigned char> hash(picosha2::k_digest_size);
	picosha2::hash256(src_str.begin(), src_str.end(), hash.begin(), hash.end());

	std::string hex_str = picosha2::bytes_to_hex_string(hash.begin(), hash.end());
}