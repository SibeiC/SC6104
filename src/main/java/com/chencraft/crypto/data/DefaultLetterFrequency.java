package com.chencraft.crypto.data;

import com.chencraft.crypto.models.LetterFrequency;

import java.util.List;

public class DefaultLetterFrequency {
    private static final List<LetterFrequency> DEFAULT_LETTER_FREQUENCY_LIST = List.of(
            new LetterFrequency('A', 0.0817),
            new LetterFrequency('B', 0.0150),
            new LetterFrequency('C', 0.0278),
            new LetterFrequency('D', 0.0425),
            new LetterFrequency('E', 0.1270),
            new LetterFrequency('F', 0.0223),
            new LetterFrequency('G', 0.0202),
            new LetterFrequency('H', 0.0609),
            new LetterFrequency('I', 0.0697),
            new LetterFrequency('J', 0.0015),
            new LetterFrequency('K', 0.0077),
            new LetterFrequency('L', 0.0403),
            new LetterFrequency('M', 0.0241),
            new LetterFrequency('N', 0.0675),
            new LetterFrequency('O', 0.0751),
            new LetterFrequency('P', 0.0193),
            new LetterFrequency('Q', 0.0010),
            new LetterFrequency('R', 0.0599),
            new LetterFrequency('S', 0.0633),
            new LetterFrequency('T', 0.0906),
            new LetterFrequency('U', 0.0276),
            new LetterFrequency('V', 0.0098),
            new LetterFrequency('W', 0.0236),
            new LetterFrequency('X', 0.0015),
            new LetterFrequency('Y', 0.0197),
            new LetterFrequency('Z', 0.0007)
    );

    public static List<LetterFrequency> inOrder() {
        return DEFAULT_LETTER_FREQUENCY_LIST.stream()
                                            .sorted()
                                            .toList();
    }
}
