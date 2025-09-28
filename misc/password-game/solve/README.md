# Password Game - Solution

The 5 basic requirements can be met with a single character each: lowercase, uppercase, digit, symbol, and a character that becomes 2 or more characters when converted to uppercase.

To satisfy the palindrome requirement, we need to repeat at least 4 of these characters. For odd-length strings, the character in the middle doesn't need to be repeated. This leaves us with a string of 9 characters, passing the length constraints.

The final requirement is that we cannot reuse any UTF-16 code unit in the string. To "repeat" characters for the palindrome, we need to find different unicode code points that are canonically equivalent. From the swift docs:

> Comparing strings for equality using the equal-to operator (==) or a relational operator (like < or >=) is always performed using Unicode canonical representation.

For each basic requirement, we need to find a character that satisfies it with multiple equivalent code points. We can do this by looking up the unicode tables or writing a swift script to iterate over possible solutions.

    symbol:

        "\u{37e}" == "\u{3b}"
        "\u{1fef}" == "\u{60}"

    case length:

        "\u{1f80}" == "\u{3b1}\u{313}\u{345}"
        ...
        "\u{1fcc}" == "\u{397}\u{345}"
        "\u{1ff2}" == "\u{3c9}\u{300}\u{345}"
        "\u{1ff3}" == "\u{3c9}\u{345}"
        "\u{1ff4}" == "\u{3c9}\u{301}\u{345}"
        "\u{1ff7}" == "\u{3c9}\u{342}\u{345}"
        "\u{1ffc}" == "\u{3a9}\u{345}"

    uppercase:

        "\u{212a}" == "\u{4b}"

    digit:

        "\u{f96b}" == "\u{53c3}"
        "\u{f973}" == "\u{62fe}"
        "\u{f978}" == "\u{5169}"
        "\u{f9b2}" == "\u{96f6}"
        "\u{f9d1}" == "\u{516d}"
        "\u{f9d3}" == "\u{9678}"
        "\u{f9fd}" == "\u{4ec0}"
        "\u{2f890}" == "\u{5efe}"

Note that there aren't any solutions for the lowercase character, so we need to place it in the middle. Here is an example solution:

    "K`拾ῲaῲ拾`K" == "\u{212a}\u{1fef}\u{f973}\u{1ff2}\u{61}\u{3c9}\u{300}\u{345}\u{62fe}\u{60}\u{4b}"

