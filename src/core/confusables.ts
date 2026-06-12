/**
 * Confusable-character (homoglyph) mapping: visually similar Unicode
 * characters → their ASCII skeleton. A practical subset of Unicode TR39
 * covering the scripts most abused in IDN homograph attacks
 * (Cyrillic, Greek, fullwidth forms, common Latin diacritics).
 */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic lookalikes
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', х: 'x', у: 'y', і: 'i', ј: 'j',
  ѕ: 's', ԁ: 'd', ԛ: 'q', ԝ: 'w', һ: 'h', ո: 'n', ѵ: 'v', ɡ: 'g',
  А: 'a', В: 'b', Е: 'e', К: 'k', М: 'm', Н: 'h', О: 'o', Р: 'p',
  С: 'c', Т: 't', Х: 'x', Ь: 'b',
  // Greek lookalikes
  ο: 'o', ν: 'v', α: 'a', ρ: 'p', τ: 't', υ: 'u', κ: 'k', η: 'n',
  Α: 'a', Β: 'b', Ε: 'e', Ζ: 'z', Η: 'h', Ι: 'i', Κ: 'k', Μ: 'm',
  Ν: 'n', Ο: 'o', Ρ: 'p', Τ: 't', Υ: 'y', Χ: 'x', ω: 'w',
  // Latin diacritics & extensions commonly used in typosquats
  à: 'a', á: 'a', â: 'a', ã: 'a', ä: 'a', å: 'a', ā: 'a', ă: 'a', ą: 'a',
  è: 'e', é: 'e', ê: 'e', ë: 'e', ē: 'e', ĕ: 'e', ė: 'e', ę: 'e', ě: 'e',
  ì: 'i', í: 'i', î: 'i', ï: 'i', ī: 'i', į: 'i', ı: 'i',
  ò: 'o', ó: 'o', ô: 'o', õ: 'o', ö: 'o', ō: 'o', ŏ: 'o', ő: 'o', ø: 'o',
  ù: 'u', ú: 'u', û: 'u', ü: 'u', ū: 'u', ŭ: 'u', ů: 'u', ű: 'u',
  ç: 'c', ć: 'c', ĉ: 'c', č: 'c', ñ: 'n', ń: 'n', ņ: 'n', ň: 'n',
  ś: 's', ŝ: 's', ş: 's', š: 's', ý: 'y', ÿ: 'y', ź: 'z', ż: 'z', ž: 'z',
  ğ: 'g', ĝ: 'g', ł: 'l', ŀ: 'l', ĺ: 'l', ļ: 'l', ľ: 'l',
  ť: 't', ţ: 't', ŕ: 'r', ř: 'r', ď: 'd', đ: 'd', ŵ: 'w', ŷ: 'y',
  // Digits / symbols
  '０': '0', '１': '1', '２': '2', '٥': '0',
  ⅼ: 'l', Ⅰ: 'i', ⅰ: 'i', ℓ: 'l',
};

/**
 * Reduces a string to its ASCII "skeleton": lowercases, then maps each
 * confusable character to its ASCII equivalent. Characters with no mapping
 * are kept as-is.
 */
export function toSkeleton(input: string): string {
  let out = '';
  for (const ch of input) {
    const lower = CONFUSABLES[ch] ?? CONFUSABLES[ch.toLowerCase()] ?? ch.toLowerCase();
    out += lower;
  }
  return out;
}

/** True if the string contains at least one non-ASCII confusable character. */
export function hasConfusables(input: string): boolean {
  for (const ch of input) {
    if (ch.charCodeAt(0) > 0x7f && (CONFUSABLES[ch] !== undefined || CONFUSABLES[ch.toLowerCase()] !== undefined)) {
      return true;
    }
  }
  return false;
}

/** True if the string mixes ASCII letters with non-ASCII characters (classic IDN spoof shape). */
export function isMixedScript(input: string): boolean {
  let ascii = false;
  let nonAscii = false;
  for (const ch of input) {
    if (/[a-z]/i.test(ch)) ascii = true;
    else if (ch.charCodeAt(0) > 0x7f) nonAscii = true;
  }
  return ascii && nonAscii;
}
