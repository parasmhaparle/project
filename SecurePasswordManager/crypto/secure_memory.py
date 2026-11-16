def wipe_bytearray(buffer: bytearray) -> None:
    """
    Overwrite the contents of a mutable bytearray with zeros.

    This is best-effort cleanup, not guaranteed secure memory erasure.
    """

    if not isinstance(buffer, bytearray):
        raise TypeError("buffer must be a bytearray")

    for index in range(len(buffer)):
        buffer[index] = 0