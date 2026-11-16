
import secrets
import string


def generate_password(
    length=16,
    use_uppercase=True,
    use_lowercase=True,
    use_numbers=True,
    use_symbols=True,
):
    # Validate password length.
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("Password length must be an integer.")

    if length < 4:
        raise ValueError("Password length must be at least 4.")

    if length > 128:
        raise ValueError("Password length must not exceed 128.")

    # Validate character category options.
    options = [
        use_uppercase,
        use_lowercase,
        use_numbers,
        use_symbols,
    ]

    if not all(isinstance(option, bool) for option in options):
        raise TypeError("Character category options must be Boolean.")

    character_sets = []

    if use_uppercase:
        character_sets.append(string.ascii_uppercase)

    if use_lowercase:
        character_sets.append(string.ascii_lowercase)

    if use_numbers:
        character_sets.append(string.digits)

    if use_symbols:
        character_sets.append(string.punctuation)

    if not character_sets:
        raise ValueError("At least one character type must be selected.")

    if length < len(character_sets):
        raise ValueError(
            "Password length is too short for the selected character types."
        )

    # Guarantee at least one character from every selected category.
    password_characters = [
        secrets.choice(character_set)
        for character_set in character_sets
    ]

    # Combine all selected character sets.
    all_characters = "".join(character_sets)

    # Fill the remaining positions securely.
    for _ in range(length - len(password_characters)):
        password_characters.append(
            secrets.choice(all_characters)
        )

    # Securely shuffle the generated password.
    secrets.SystemRandom().shuffle(password_characters)

    return "".join(password_characters)
