package com.chencraft.crypto.analysis;

import com.chencraft.crypto.data.DefaultLetterFrequency;
import com.chencraft.crypto.models.LetterFrequency;
import com.chencraft.crypto.simpleSubstituion.SimpleSubstitutionAlgorithm;
import com.chencraft.crypto.utils.Decrypt;
import lombok.extern.slf4j.Slf4j;
import org.sk.PrettyTable;

import java.util.*;

/**
 * Simple Substitution Solver through analysis of the word frequency
 */
@Slf4j
public class SimpSubSolver {
    public static String solve(String cipherText, Map<Character, Character> overrideMapping) {
        List<LetterFrequency> frequencies = buildLetterFrequencyMap(cipherText);

        List<LetterFrequency> defaultFrequency = DefaultLetterFrequency.inOrder();
        String privateKey = buildPrivateKey(frequencies, defaultFrequency, overrideMapping);

        logPrivateKey(privateKey, frequencies);

        try {
            return Decrypt.with(cipherText, privateKey, SimpleSubstitutionAlgorithm.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static List<LetterFrequency> buildLetterFrequencyMap(String cipherText) {
        Map<Character, Integer> letterFrequencyMap = new HashMap<>();
        int size = 0;

        for (char c : cipherText.toUpperCase().toCharArray()) {
            if (c < 'A' || c > 'Z') {
                continue;
            }

            letterFrequencyMap.putIfAbsent(c, 0);
            letterFrequencyMap.put(c, letterFrequencyMap.get(c) + 1);
            size++;
        }

        List<LetterFrequency> frequencies = new ArrayList<>();

        for (int i = 0; i < 26; i++) {
            letterFrequencyMap.putIfAbsent((char) ('A' + i), 0);
            letterFrequencyMap.put((char) ('A' + i), letterFrequencyMap.get((char) ('A' + i)));
            frequencies.add(new LetterFrequency((char) ('A' + i), letterFrequencyMap.get((char) ('A' + i)) / (double) size));
        }

        return frequencies.stream()
                          .sorted()
                          .toList();
    }

    private static String buildPrivateKey(List<LetterFrequency> frequencies,
                                          List<LetterFrequency> defaultFrequency,
                                          Map<Character, Character> overrideMapping) {
        log.info("Actual: {}", frequencies.toString());
        log.info("Expect: {}", defaultFrequency.toString());

        // Key maps plaintext index (A..Z) to a ciphertext character
        char[] key = new char[26];
        Arrays.fill(key, '\0');

        // Track which ciphertext letters are already assigned
        Set<Character> usedCipher = new HashSet<>();

        // Normalize and apply overrides first: key is plaintext, value is ciphertext
        if (overrideMapping != null) {
            for (Map.Entry<Character, Character> e : overrideMapping.entrySet()) {
                char p = Character.toUpperCase(e.getKey());
                char c = Character.toUpperCase(e.getValue());
                if (p < 'A' || p > 'Z' || c < 'A' || c > 'Z') {
                    continue; // ignore invalid mapping entries
                }
                int pi = p - 'A';
                if (key[pi] != '\0') {
                    // already set for this plaintext; keep existing to preserve first-come mapping
                    continue;
                }
                if (usedCipher.contains(c)) {
                    // ciphertext letter already used by another mapping; skip to maintain distinctness
                    continue;
                }
                key[pi] = c;
                usedCipher.add(c);
            }
        }

        // Order cipher letters by observed frequency (descending)
        List<Character> cipherByFreq = new ArrayList<>(26);
        for (LetterFrequency lf : frequencies) {
            cipherByFreq.add(lf.letter());
        }

        // Fill remaining plaintext letters in order of expected frequency, choosing unused cipher letters by highest freq
        for (LetterFrequency expected : defaultFrequency) {
            char p = expected.letter();
            int pi = p - 'A';
            if (key[pi] != '\0') continue; // already assigned by override

            // pick first unused ciphertext by observed frequency
            for (char c : cipherByFreq) {
                if (!usedCipher.contains(c)) {
                    key[pi] = c;
                    usedCipher.add(c);
                    break;
                }
            }
        }

        // As a safety net, fill any still-unset slots with remaining unused alphabet letters
        for (int pi = 0; pi < 26; pi++) {
            if (key[pi] == '\0') {
                for (char c = 'A'; c <= 'Z'; c++) {
                    if (!usedCipher.contains(c)) {
                        key[pi] = c;
                        usedCipher.add(c);
                        break;
                    }
                }
            }
        }

        // Validate: all positions filled and 26 distinct letters used
        for (int pi = 0; pi < 26; pi++) {
            if (key[pi] == '\0') {
                throw new IllegalStateException("Private key generation failed: position " + pi + " is unset");
            }
        }
        if (usedCipher.size() != 26) {
            throw new IllegalStateException("Private key must contain 26 distinct letters; found " + usedCipher.size());
        }

        return new String(key);
    }

    private static void logPrivateKey(String privateKey, List<LetterFrequency> frequencies) {
        PrettyTable table = new PrettyTable("Plain Text", "Cipher Text", "Frequency", "Expected Frequency", "Deviation");
        frequencies = frequencies.stream().sorted(Comparator.comparing(LetterFrequency::letter)).toList();
        List<LetterFrequency> defaultFrequency = DefaultLetterFrequency.inOrder().stream().sorted(Comparator.comparing(LetterFrequency::letter)).toList();

        for (int i = 0; i < 26; i++) {
            char plainText = (char) ('A' + i);
            char cipherText = privateKey.charAt(i);
            Double f = frequencies.get(cipherText - 'A').frequency();
            Double df = defaultFrequency.get(i).frequency();
            double deviation = Math.abs(f - df) * 100;

            table.addRow(String.valueOf(plainText),
                         String.valueOf(cipherText),
                         f.toString(),
                         df.toString(),
                         String.format("%.2f%%", deviation));
        }

        log.info("Private Key: {}", privateKey);
        log.info("\n{}", table);
    }

    private static String colorSolvedWithOverrides(String solved, Map<Character, Character> overrideMapping) {
        if (solved == null || overrideMapping == null || overrideMapping.isEmpty()) {
            return solved;
        }
        Set<Character> keys = new HashSet<>();
        for (Map.Entry<Character, Character> e : overrideMapping.entrySet()) {
            if (e.getKey() != null) {
                char k = Character.toUpperCase(e.getKey());
                if (k >= 'A' && k <= 'Z') keys.add(k);
            }
        }
        if (keys.isEmpty()) return solved;

        final String GREEN = "\u001B[32m";
        final String RESET = "\u001B[0m";
        StringBuilder sb = new StringBuilder(solved.length() + 16);
        for (int i = 0; i < solved.length(); i++) {
            char ch = solved.charAt(i);
            char up = Character.toUpperCase(ch);
            if (keys.contains(up)) {
                sb.append(GREEN).append(ch).append(RESET);
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    static void main() {
        String cipherText = getCipherText();

        Map<Character, Character> overrides = new HashMap<>() {{
            put('T', 'P');
            put('H', 'B');
            put('E', 'F');
            put('A', 'Q');
            put('V', 'U');
            put('C', 'Z');
            put('R', 'H');
            put('P', 'C');
            put('N', 'W');
            put('D', 'A');
            put('K', 'K');
            put('Y', 'I');
            put('O', 'T');
            put('S', 'X');
            put('I', 'V');
            put('M', 'Y');
            put('B', 'G');
            put('U', 'D');
            put('F', 'O');
            put('L', 'J');
            put('W', 'E');
            put('G', 'L');
            put('X', 'N');
        }};

        String solved = solve(cipherText, overrides);
        List<String> foundWords = List.of("THE", "THAT", "HAVE", "CARPENTER", "NEED", "PEPPER", "AND", "THANKED",
                                          "THEY", "OYSTERS", "HAS", "TIME", "COME", "SAID", "OUT", "BREATH", "OF",
                                          "OUR", "CHAT", "FOR", "SOME", "US", "ARE", "FAT", "NO", "HURRY", "ALL");
        for (String word : foundWords) {
            solved = solved.replace(word, " " + word + " ");
        }
        solved = solved.trim();
        String colored = colorSolvedWithOverrides(solved, overrides);
        log.info("Guessed plaintext: {}", colored);

        log.info("Actual plaintext: The time has come, the walrus said, to talk of many things of shoes and ships and sealing-wax of cabbages, and kings, and why the sea is boiling hot. And whether pigs have wings. But wait a bit, the oysters cried, before we have our chat, for some of us are out of breath, and all of us are fat. No hurry, said the carpenter, they thanked him much for that a loaf of bread. The walrus said, is what we chiefly need, pepper and vinegar. Besides are very good indeed. Now if you're ready, oysters dear we can begin to feed. ");
    }

    private static String getCipherText() {
        return "PBFPVYFBQXZTYFPBFEQJHDXXQVAPTPQJKTOYQWIPBVWLXTOXBTFXQWAXBVCXQWAXFQJVWLEQNTOZQGGQLFXQWAKVWLXQWAEBIPBFXFQVXGTVJVWLBTPQWAEBFPBFHCVLXBQUFEVWLXGDPEQVPQGVPPBFTIXPFHXZHVFAGFOTHFEFBQUFTDHZBQPOTHXTYFTODXQHFTDPTOGHFQPBQWAQJJTODXQHFOQPWTBDHHIXQVAPBFZQHCFWPFHPBFIPBQWKFABVYYDZBOTHPBQPQJTQOTOGHFQAPBFEQJHDXXQVAVXEBQPEFZBVFOJIWFFACFCCFHQWAUVWFLQHGFXVAFXQHFUFHILTTAVWAFFAWTEVOITDHFHFQAITIXPFHXAFQHEFZQWGFLVWPTOFFA";
    }
}
