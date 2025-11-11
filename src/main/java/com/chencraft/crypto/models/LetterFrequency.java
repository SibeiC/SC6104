package com.chencraft.crypto.models;

import lombok.NonNull;

public record LetterFrequency(Character letter, Double frequency) implements Comparable<LetterFrequency> {
    public LetterFrequency(Character letter, Double frequency) {
        this.letter = Character.toUpperCase(letter);
        this.frequency = frequency;
    }

    @Override
    public int compareTo(LetterFrequency o) {
        return Double.compare(o.frequency, frequency);
    }

    @NonNull
    @Override
    public String toString() {
        return String.format("%s: %.3f", letter, frequency);
    }
}
