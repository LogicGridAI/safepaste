// patterns.js — Threat pattern library (loaded before content.js)
// Each entry: { type, group, freeTier?, basic?, regex, validate? }
// basic: IP/API “Basic Protection” (always gated by basicProtection toggle, Free + Pro).
// group: "devsec" | "fintech" — Pro toggle gating (MAC = devsec, non-basic).
// freeTier: when true, pattern may run on Free tier (still requires basicProtection for basic patterns).

'use strict';

function isPureHex(s) {
  return /^[a-f0-9]+$/i.test(s);
}

function isFalsePositiveApiMatch(match) {
  const lower = String(match).toLowerCase();
  if (lower.startsWith('bearer ')) {
    const t = lower.slice(7).trim();
    return t.length >= 16 && isPureHex(t);
  }
  if (/^sk-|^pk-/i.test(match)) {
    const t = lower.replace(/^(sk|pk)-/, '').trim();
    return t.length >= 16 && isPureHex(t);
  }
  return false;
}

function luhnValid(digitsOnly) {
  if (digitsOnly.length !== 15 && digitsOnly.length !== 16) return false;
  let sum = 0;
  let alt = false;
  for (let i = digitsOnly.length - 1; i >= 0; i--) {
    let n = parseInt(digitsOnly[i], 10);
    if (Number.isNaN(n)) return false;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function validIpv4(match) {
  const octets = match.split('.').map(Number);
  if (octets[0] === 127 || octets[0] === 255) return false;
  return octets.every((o) => o >= 0 && o <= 255);
}

function validCreditCard(match) {
  const d = match.replace(/\D/g, '');
  return (d.length === 15 || d.length === 16) && luhnValid(d);
}

const RE_API_KEYS = new RegExp(
  [
    '\\b(?:sk|pk)-[a-zA-Z0-9_-]{16,}\\b',
    '\\bbearer\\s+[a-zA-Z0-9._~+/=-]{16,}\\b',
    '\\bxox[bap]-[a-zA-Z0-9-]{10,}\\b',
    '\\bsk-ant-[a-zA-Z0-9_-]{10,}\\b',
    '\\bAKIA[0-9A-Z]{16}\\b',
    '\\bASIA[0-9A-Z]{16}\\b',
    '\\bghp_[a-zA-Z0-9]{20,}\\b',
    '\\bgithub_pat_[a-zA-Z0-9_]{20,}\\b',
    '\\bgho_[a-zA-Z0-9]{20,}\\b',
    '\\bghu_[a-zA-Z0-9]{20,}\\b',
    '\\bghs_[a-zA-Z0-9]{20,}\\b',
  ].join('|'),
  'gi'
);

const THREAT_PATTERNS = Object.freeze([
  {
    type: 'IP',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g,
    validate: validIpv4,
  },
  {
    type: 'API_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: RE_API_KEYS,
    validate: (m) => !isFalsePositiveApiMatch(m),
  },
  {
    type: 'MAC_ADDRESS',
    group: 'devsec',
    freeTier: false,
    basic: false,
    regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
  },
  {
    type: 'CREDIT_CARD',
    group: 'fintech',
    freeTier: false,
    regex: /\b(?:\d{4}[-\s]?){3}\d{3,4}\b/g,
    validate: validCreditCard,
  },
  {
    type: 'US_SSN',
    group: 'fintech',
    freeTier: false,
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  {
    type: 'EU_IBAN',
    group: 'fintech',
    freeTier: false,
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi,
  },
  {
    type: 'UK_NINO',
    group: 'fintech',
    freeTier: false,
    regex: /\b[A-Z]{2}\d{6}[A-Z]\b/g,
  },
  {
    type: 'NG_BANK',
    group: 'fintech',
    freeTier: false,
    regex: /\b\d{10}\b/g,
  },
  {
    type: 'NG_PHONE',
    group: 'fintech',
    freeTier: false,
    regex: /\b0[789][01]\d{8}\b/g,
  },
  {
    type: 'NG_NIN',
    group: 'fintech',
    freeTier: false,
    regex: /\b(?!0[789][01]\d{8})\d{11}\b/g,
  },

  // ── Canada ──────────────────────────────────────────────────
  {
    type: 'CA_SIN',
    group: 'fintech',
    freeTier: false,
    // Social Insurance Number: 123-456-789 (first digit never 0 or 8)
    regex: /\b[1-79]\d{2}-\d{3}-\d{3}\b/g,
  },

  // ── India ────────────────────────────────────────────────────
  {
    type: 'IN_AADHAAR',
    group: 'fintech',
    freeTier: false,
    // Aadhaar: 12 digits, optionally space-separated in groups of 4
    // First digit never 0 or 1
    regex: /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    validate(m) {
      const d = m.replace(/[\s-]/g, '');
      return d.length === 12;
    },
  },
  {
    type: 'IN_PAN',
    group: 'fintech',
    freeTier: false,
    // PAN Card: ABCDE1234F — 5 alpha, 4 numeric, 1 alpha
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
  },

  // ── South Africa ─────────────────────────────────────────────
  {
    type: 'ZA_ID',
    group: 'fintech',
    freeTier: false,
    // SA ID: 13 digits YYMMDD GGGG C A Z
    // First 6 digits are a valid date (YYMMDD)
    regex: /\b\d{13}\b/g,
    validate(m) {
      const month = parseInt(m.slice(2, 4), 10);
      const day   = parseInt(m.slice(4, 6), 10);
      return month >= 1 && month <= 12 && day >= 1 && day <= 31;
    },
  },

  // ── Australia ────────────────────────────────────────────────
  {
    type: 'AU_TFN',
    group: 'fintech',
    freeTier: false,
    // Tax File Number: 8-9 digits, optionally space-separated
    regex: /\b\d{3}[\s-]?\d{3}[\s-]?\d{2,3}\b/g,
    validate(m) {
      const d = m.replace(/[\s-]/g, '');
      return d.length === 8 || d.length === 9;
    },
  },

  // ── Brazil ───────────────────────────────────────────────────
  {
    type: 'BR_CPF',
    group: 'fintech',
    freeTier: false,
    // CPF: 123.456.789-09
    regex: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g,
  },

  // ── Singapore ────────────────────────────────────────────────
  {
    type: 'SG_NRIC',
    group: 'fintech',
    freeTier: false,
    // NRIC/FIN: S/T/F/G + 7 digits + 1 alpha
    regex: /\b[STFG]\d{7}[A-Z]\b/g,
  },

  // ── Germany ──────────────────────────────────────────────────
  {
    type: 'DE_TAX_ID',
    group: 'fintech',
    freeTier: false,
    // Steueridentifikationsnummer: 11 digits, first digit 1-9
    regex: /\b[1-9]\d{10}\b/g,
  },

  // ── United States ─────────────────────────────────────────────
  {
    type: 'US_GREEN_CARD',
    group: 'fintech',
    freeTier: false,
    // Permanent Resident Card (Form I-551)
    // Format: 3 alpha + 10 digits  e.g. ABC1234567890
    // Or older format: 2 alpha + 9 digits  e.g. AB123456789
    regex: /\b[A-Z]{2,3}\d{9,10}\b/g,
    validate(m) {
      // Must start with known USCIS prefixes
      // Common prefixes: A (Alien Registration), LIN, EAC, WAC, SRC, MSC, IOE
      const prefixes = ['LIN','EAC','WAC','SRC','MSC','IOE'];
      const upper = m.toUpperCase();
      // 3-letter prefix format
      if (prefixes.some(p => upper.startsWith(p))) return true;
      // A-number format: A + 8-9 digits
      if (/^A\d{8,9}$/.test(upper)) return true;
      // I-551 card number: 3 alpha + 10 digits
      if (/^[A-Z]{3}\d{10}$/.test(upper)) return true;
      return false;
    },
  },

  {
    type: 'BTC_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
  },
  {
    type: 'BTC_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
  },
  {
    type: 'BTC_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bbc1[a-z0-9]{6,87}\b/gi,
  },
  {
    type: 'ETH_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b0x[a-fA-F0-9]{40}\b/g,
  },
  {
    type: 'CRYPTO_KEY',
    group: 'devsec',
    freeTier: false,
    basic: false,
    regex: /\b[a-fA-F0-9]{64}\b/g,
  },
  {
    type: 'CRYPTO_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g,
  },
  {
    type: 'GEMINI_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  {
    type: 'SOL_ADDRESS',
    group: 'devsec',
    freeTier: false,
    basic: false,
    regex: /\b[1-9A-HJ-NP-Za-km-z]{44}\b/g,
  },
  {
    type: 'ENV_VALUE',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /(?<=^[A-Z][A-Z0-9_]*=).+$/gm,
  },
  {
    type: 'SEED_PHRASE',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b([a-z]+\s){11}[a-z]+\b/g,
    validate(m) {
      const words = m.trim().split(/\s+/)
      return words.length === 12
    }
  },
  {
    type: 'SEED_PHRASE',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b([a-z]+\s){23}[a-z]+\b/g,
    validate(m) {
      const words = m.trim().split(/\s+/)
      return words.length === 24
    }
  },
  {
    type: 'ETH_PRIVATE_KEY',
    group: 'devsec',
    freeTier: false,
    basic: false,
    regex: /\b0x[a-fA-F0-9]{64}\b/g,
  },
  {
    type: 'PEM_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /-----BEGIN\s(?:RSA\s|EC\s|OPENSSH\s)?PRIVATE KEY-----/g,
  },
]);
