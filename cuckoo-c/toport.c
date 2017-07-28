// Cuckoo Cycle, a memory-hard proof-of-work
// Copyright (c) 2013-2016 John Tromp

#include "cuckoo.h"
#include <inttypes.h> // for SCNx64 macro
#include <stdio.h>    // printf/scanf
#include <stdlib.h>   // exit
#include <unistd.h>   // getopt
#include <assert.h>   // d'uh

// arbitrary length of header hashed into siphash key
#define HEADERLEN 80

int main(int argc, char **argv) {
  const char *header = "";
  int nonce = 0;
  int c;

  // Set header and nonce(removed)

  char headernonce[HEADERLEN];
  u32 hdrlen = strlen(header);

  // Copy header inside headernonce
  memcpy(headernonce, header, hdrlen);

  // Zero out all the memory after the header
  memset(headernonce+hdrlen, 0, sizeof(headernonce)-hdrlen);

  // Add little endian nonce at index 19(why tho? 80/4-1???)
  ((u32 *)headernonce)[HEADERLEN/sizeof(u32)-1] = htole32(nonce);


  // Set header
  siphash_keys keys;
  setheader(headernonce, sizeof(headernonce), &keys);
  
  printf("Verifying size %d proof for cuckoo%d(\"%s\",%d) k0 %lu k1 %lu\n",
               PROOFSIZE, EDGEBITS+1, header, nonce, keys.k0, keys.k1);

  // Keep asking for input till it matched " Solution"
  for (int nsols=0; scanf(" Solution") == 0; nsols++) {
    
    // Parse the hex numbers separated by a space
    edge_t nonces[PROOFSIZE];
    for (int n = 0; n < PROOFSIZE; n++) {
      u64 nonce;
      int nscan = scanf(" %" SCNx64, &nonce);
      assert(nscan == 1);
      nonces[n] = nonce;
    }

    // Verify nonce and keys
    int pow_rc = verify(nonces, &keys);

    // Check if it was ok
    if (pow_rc == POW_OK) {
      printf("Verified with cyclehash ");

      // Compute hash to check difficulty
      unsigned char cyclehash[32];
      SHA256((unsigned char *)nonces, sizeof(nonces), cyclehash);
      
      printf("\n");
    } else {
      printf("FAILED due to %s\n", errstr[pow_rc]);
    }
  }
  return 0;
}