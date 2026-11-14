//! Secret-egress regex scanner, bounded base64 decode-and-rescan, and FIPS 180-4 SHA-256 span fingerprinting.

use regex::Regex;

/// Base64 candidate spans inspected by the bounded decode-and-rescan pass.
const BASE64_CANDIDATE_PATTERN: &str = r"[A-Za-z0-9+/]{24,}={0,2}";
/// Maximum number of base64 candidates decoded per surface (ReDoS / work bound).
const MAX_B64_CANDIDATES: usize = 16;
/// Maximum bytes kept from any decoded base64 candidate.
const MAX_B64_DECODED_BYTES: usize = 65536;

struct SecretRule {
    rule_id: &'static str,
    regex: Regex,
    requires_digit: bool,
}

fn compile_const_pattern(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(regex) => regex,
        Err(err) => panic!("const regex '{pattern}' must compile: {err}"),
    }
}

/// Ordered secret signature table plus the bounded base64 decode-and-rescan pass.
pub(super) struct SecretScanner {
    rules: Vec<SecretRule>,
    base64_candidate_regex: Regex,
}

impl SecretScanner {
    pub(super) fn new() -> Self {
        let raw_rules: &[(&str, &str, bool)] = &[
            (
                "SECRET_GITHUB_PAT",
                r"(?i)(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{22,})",
                false,
            ),
            ("SECRET_OPENAI_KEY", r"(?i)sk-[A-Za-z0-9_-]{20,}", true),
            (
                "SECRET_AWS_ACCESS_KEY",
                r"(?i)(?:AKIA|ASIA)[0-9A-Z]{16}",
                true,
            ),
            (
                "SECRET_PRIVATE_KEY_PEM",
                r"(?i)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
                false,
            ),
            (
                "SECRET_JWT_BEARER",
                r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                false,
            ),
            (
                "SECRET_ENV_ASSIGNMENT",
                r"(?i)(?:DATABASE_URL|FERNET_KEY|JWT_PRIVATE_KEY|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*=",
                false,
            ),
        ];

        let mut rules = Vec::with_capacity(raw_rules.len());
        for (rule_id, pattern, requires_digit) in raw_rules {
            rules.push(SecretRule {
                rule_id,
                regex: compile_const_pattern(pattern),
                requires_digit: *requires_digit,
            });
        }

        Self {
            rules,
            base64_candidate_regex: compile_const_pattern(BASE64_CANDIDATE_PATTERN),
        }
    }

    fn scan_variants(&self, text: &str) -> Option<(&'static str, String)> {
        let collapsed = collapse_whitespace(text);
        for variant in [text, collapsed.as_str()] {
            for rule in &self.rules {
                for matched in rule.regex.find_iter(variant) {
                    let span = matched.as_str();
                    if rule.requires_digit && !span_has_digit(span) {
                        continue;
                    }
                    return Some((rule.rule_id, span.to_owned()));
                }
            }
        }
        None
    }

    /// Scans one surface for secrets: raw text, whitespace-collapsed variant,
    /// then a bounded base64 decode-and-rescan pass.
    pub(super) fn scan(&self, text: &str) -> Option<(&'static str, String)> {
        if let Some(hit) = self.scan_variants(text) {
            return Some(hit);
        }
        let mut candidates = 0usize;
        for matched in self.base64_candidate_regex.find_iter(text) {
            candidates += 1;
            if candidates > MAX_B64_CANDIDATES {
                break;
            }
            let Some(decoded) = decode_base64_candidate(matched.as_str()) else {
                continue;
            };
            let decoded_text = String::from_utf8_lossy(&decoded);
            if let Some(hit) = self.scan_variants(&decoded_text) {
                return Some(hit);
            }
        }
        None
    }
}

fn span_has_digit(span: &str) -> bool {
    span.bytes().any(|b| b.is_ascii_digit())
}

fn collapse_whitespace(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn base64_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict standard-alphabet base64 decoder (padding only at the end, at most two `=` per final block).
pub(super) fn decode_base64_candidate(candidate: &str) -> Option<Vec<u8>> {
    let bytes = candidate.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut seen_padding = false;
    for chunk in bytes.chunks(4) {
        let mut sextets = [0u8; 4];
        let mut pad_count = 0usize;
        for (idx, byte) in chunk.iter().enumerate() {
            match byte {
                b'=' if idx >= 2 => {
                    pad_count += 1;
                    seen_padding = true;
                }
                b'=' => return None,
                _ => {
                    if seen_padding {
                        return None;
                    }
                    sextets[idx] = base64_sextet(*byte)?;
                }
            }
        }
        if pad_count > 2 {
            return None;
        }
        let block = (u32::from(sextets[0]) << 18)
            | (u32::from(sextets[1]) << 12)
            | (u32::from(sextets[2]) << 6)
            | u32::from(sextets[3]);
        let decoded = block.to_be_bytes();
        out.extend_from_slice(&decoded[1..4 - pad_count]);
    }
    if out.is_empty() {
        return None;
    }
    out.truncate(MAX_B64_DECODED_BYTES);
    Some(out)
}

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn sha256_words(input: &[u8]) -> [u32; 8] {
    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let rem = (input.len() + 1) % 64;
    let pad_zeros = if rem <= 56 { 56 - rem } else { 120 - rem };
    let mut padded = Vec::with_capacity(input.len() + 1 + pad_zeros + 8);
    padded.extend_from_slice(input);
    padded.push(0x80);
    padded.resize(padded.len() + pad_zeros, 0);
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.as_chunks::<64>().0 {
        let mut schedule = [0u32; 64];
        for (idx, chunk) in block.as_chunks::<4>().0.iter().take(16).enumerate() {
            schedule[idx] = u32::from_be_bytes(*chunk);
        }
        for idx in 16..64 {
            let s0 = schedule[idx - 15].rotate_right(7)
                ^ schedule[idx - 15].rotate_right(18)
                ^ (schedule[idx - 15] >> 3);
            let s1 = schedule[idx - 2].rotate_right(17)
                ^ schedule[idx - 2].rotate_right(19)
                ^ (schedule[idx - 2] >> 10);
            schedule[idx] = schedule[idx - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[idx - 7])
                .wrapping_add(s1);
        }

        let mut reg = state;

        for idx in 0..64 {
            let s1 = reg[4].rotate_right(6) ^ reg[4].rotate_right(11) ^ reg[4].rotate_right(25);
            let ch = (reg[4] & reg[5]) ^ ((!reg[4]) & reg[6]);
            let temp1 = reg[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[idx])
                .wrapping_add(schedule[idx]);
            let s0 = reg[0].rotate_right(2) ^ reg[0].rotate_right(13) ^ reg[0].rotate_right(22);
            let maj = (reg[0] & reg[1]) ^ (reg[0] & reg[2]) ^ (reg[1] & reg[2]);
            let temp2 = s0.wrapping_add(maj);

            reg[7] = reg[6];
            reg[6] = reg[5];
            reg[5] = reg[4];
            reg[4] = reg[3].wrapping_add(temp1);
            reg[3] = reg[2];
            reg[2] = reg[1];
            reg[1] = reg[0];
            reg[0] = temp1.wrapping_add(temp2);
        }

        for (slot, val) in state.iter_mut().zip(reg.iter()) {
            *slot = slot.wrapping_add(*val);
        }
    }

    state
}

/// Returns the non-reversible 16-hex-character SHA-256 fingerprint of a matched secret span.
pub fn secret_fingerprint(span: &str) -> String {
    let words = sha256_words(span.as_bytes());
    format!("{:08x}{:08x}", words[0], words[1])
}
