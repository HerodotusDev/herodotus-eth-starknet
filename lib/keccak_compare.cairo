from lib.types import Keccak256Hash

func keccak_compare{range_check_ptr}(hash0: Keccak256Hash, hash1: Keccak256Hash) -> (res: felt) {
    alloc_locals;

    if (hash0.word_1 == hash1.word_1) {
    } else {
        return (0,);
    }

    if (hash0.word_2 == hash1.word_2) {
    } else {
        return (0,);
    }

    if (hash0.word_3 == hash1.word_3) {
    } else {
        return (0,);
    }

    if (hash0.word_4 == hash1.word_4) {
    } else {
        return (0,);
    }

    return (1,);
}
