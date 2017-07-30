package verify

/*
#include "cuckoo-c/cuckoo.h"

siphash_keys* SetSipKey(char* headernonce, size_t len){
    siphash_keys* keys = malloc(sizeof(siphash_keys));
    setheader(headernonce, len, keys);

    return keys;
}
*/
import "C"

import(
    "math/big"

	"github.com/minio/blake2b-simd"
)

func Verify(difficulty big.Int, header, nonces []byte) bool{
    hash := blake2b.Sum256(nonces)
    
    real_diff := new(big.Int)
    real_diff.SetBytes(hash[:])

    if real_diff > difficulty{
        return false
    }

    nonceHeader := append(nonces, header)

    keys := C.SetSipKey(C.CBytes(nonceHeader), len(nonceHeader))

    res := C.verify(C.CBytes(nonces), keys)

    return res == C.POW_OK
}