// Original Header Block (OHB) for PERC Double Encryption (RFC 8723 §4)
//
// The OHB carries the original values of RTP header fields that a Media Distributor
// (SFU) may have modified. It is appended after the E2E-encrypted payload and before
// the HBH authentication tag.
//
// Wire format:
//   [RTP header] [E2E ciphertext + E2E auth tag] [OHB] [HBH auth tag]
//
// OHB format:
//   [ PT (1 byte, optional) ] [ SEQ (2 bytes, optional) ] [ Config (1 byte) ]
//
// Config byte:
//   ┌───┬───┬───┬───┬───────┐
//   │ P │ Q │ M │ B │ R (4) │
//   └───┴───┴───┴───┴───────┘
//   P = 1: PT field present
//   Q = 1: SEQ field present
//   M = 1: marker bit present in config (overrides RTP header marker)
//   B = marker bit value (only meaningful when M=1)
//   R = reserved, must be 0
//
// An all-zero config byte (0x00) means no header fields were modified.

/// Parsed Original Header Block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ohb {
    /// Original payload type (if the MD changed it).
    pub original_pt: Option<u8>,
    /// Original sequence number (if the MD changed it).
    pub original_seq: Option<u16>,
    /// Original marker bit value (if the MD changed it).
    pub original_marker: Option<bool>,
}

/// Config byte bit positions.
const CONFIG_P: u8 = 0x80; // PT present
const CONFIG_Q: u8 = 0x40; // SEQ present
const CONFIG_M: u8 = 0x20; // Marker present
const CONFIG_B: u8 = 0x10; // Marker value

impl Ohb {
    /// Create an empty OHB (no modifications).
    pub fn empty() -> Self {
        Ohb {
            original_pt: None,
            original_seq: None,
            original_marker: None,
        }
    }

    /// Check if this OHB indicates no header modifications.
    pub fn is_empty(&self) -> bool {
        self.original_pt.is_none() && self.original_seq.is_none() && self.original_marker.is_none()
    }

    /// Parse an OHB from the end of a decrypted PERC payload.
    ///
    /// The OHB is the last 1-4 bytes of the buffer (after E2E ciphertext + E2E auth tag).
    /// The config byte is always the last byte.
    ///
    /// Returns `(ohb, ohb_len)` where `ohb_len` is the number of bytes consumed from the end.
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.is_empty() {
            return None;
        }

        let config = buf[buf.len() - 1];
        let has_pt = config & CONFIG_P != 0;
        let has_seq = config & CONFIG_Q != 0;
        let has_marker = config & CONFIG_M != 0;
        let marker_value = config & CONFIG_B != 0;

        let mut ohb_len: usize = 1; // config byte
        if has_pt {
            ohb_len += 1;
        }
        if has_seq {
            ohb_len += 2;
        }

        if buf.len() < ohb_len {
            return None;
        }

        let ohb_start = buf.len() - ohb_len;
        let mut pos = ohb_start;

        let original_pt = if has_pt {
            let pt = buf[pos] & 0x7F;
            pos += 1;
            Some(pt)
        } else {
            None
        };

        let original_seq = if has_seq {
            let seq = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            Some(seq)
        } else {
            None
        };

        let original_marker = if has_marker {
            Some(marker_value)
        } else {
            None
        };

        Some((
            Ohb {
                original_pt,
                original_seq,
                original_marker,
            },
            ohb_len,
        ))
    }

    /// Serialize this OHB to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4);
        let mut config: u8 = 0;

        if let Some(pt) = self.original_pt {
            buf.push(pt & 0x7F);
            config |= CONFIG_P;
        }

        if let Some(seq) = self.original_seq {
            buf.push((seq >> 8) as u8);
            buf.push((seq & 0xFF) as u8);
            config |= CONFIG_Q;
        }

        if let Some(marker) = self.original_marker {
            config |= CONFIG_M;
            if marker {
                config |= CONFIG_B;
            }
        }

        buf.push(config);
        buf
    }

    /// Build an OHB from the difference between original and modified header fields.
    ///
    /// `orig_*` are the values from the sender's original packet.
    /// `modified_*` are the values after the MD's changes.
    /// Only fields that differ are recorded in the OHB.
    pub fn from_diff(
        orig_pt: u8,
        modified_pt: u8,
        orig_seq: u16,
        modified_seq: u16,
        orig_marker: bool,
        modified_marker: bool,
    ) -> Self {
        Ohb {
            original_pt: if orig_pt != modified_pt {
                Some(orig_pt)
            } else {
                None
            },
            original_seq: if orig_seq != modified_seq {
                Some(orig_seq)
            } else {
                None
            },
            original_marker: if orig_marker != modified_marker {
                Some(orig_marker)
            } else {
                None
            },
        }
    }

    /// Merge this OHB with a new set of MD modifications.
    ///
    /// If the MD changes a field that already has an OHB entry, keep the original.
    /// If the MD changes a field back to its original value, remove the OHB entry.
    pub fn update(
        &self,
        current_pt: u8,
        new_pt: u8,
        current_seq: u16,
        new_seq: u16,
        current_marker: bool,
        new_marker: bool,
    ) -> Self {
        let original_pt = if new_pt != self.original_pt.unwrap_or(current_pt) {
            self.original_pt.or(Some(current_pt))
        } else {
            None // changed back to original
        };

        let original_seq = if new_seq != self.original_seq.unwrap_or(current_seq) {
            self.original_seq.or(Some(current_seq))
        } else {
            None
        };

        let original_marker = if new_marker != self.original_marker.unwrap_or(current_marker) {
            self.original_marker.or(Some(current_marker))
        } else {
            None
        };

        Ohb {
            original_pt,
            original_seq,
            original_marker,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ohb_roundtrip() {
        let ohb = Ohb::empty();
        assert!(ohb.is_empty());

        let bytes = ohb.to_bytes();
        assert_eq!(bytes, vec![0x00]);

        let (parsed, len) = Ohb::parse(&bytes).unwrap();
        assert_eq!(len, 1);
        assert!(parsed.is_empty());
        assert_eq!(ohb, parsed);
    }

    #[test]
    fn ohb_with_pt_only() {
        let ohb = Ohb {
            original_pt: Some(96),
            original_seq: None,
            original_marker: None,
        };

        let bytes = ohb.to_bytes();
        assert_eq!(bytes.len(), 2); // PT + config
        assert_eq!(bytes[0], 96);
        assert_eq!(bytes[1], CONFIG_P);

        let (parsed, len) = Ohb::parse(&bytes).unwrap();
        assert_eq!(len, 2);
        assert_eq!(parsed.original_pt, Some(96));
        assert_eq!(parsed.original_seq, None);
        assert_eq!(parsed.original_marker, None);
    }

    #[test]
    fn ohb_with_seq_only() {
        let ohb = Ohb {
            original_pt: None,
            original_seq: Some(0x1234),
            original_marker: None,
        };

        let bytes = ohb.to_bytes();
        assert_eq!(bytes.len(), 3); // SEQ(2) + config
        assert_eq!(bytes[0], 0x12);
        assert_eq!(bytes[1], 0x34);
        assert_eq!(bytes[2], CONFIG_Q);

        let (parsed, len) = Ohb::parse(&bytes).unwrap();
        assert_eq!(len, 3);
        assert_eq!(parsed.original_seq, Some(0x1234));
    }

    #[test]
    fn ohb_with_marker() {
        let ohb = Ohb {
            original_pt: None,
            original_seq: None,
            original_marker: Some(true),
        };

        let bytes = ohb.to_bytes();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], CONFIG_M | CONFIG_B);

        let (parsed, _) = Ohb::parse(&bytes).unwrap();
        assert_eq!(parsed.original_marker, Some(true));
    }

    #[test]
    fn ohb_with_all_fields() {
        let ohb = Ohb {
            original_pt: Some(111),
            original_seq: Some(0xABCD),
            original_marker: Some(false),
        };

        let bytes = ohb.to_bytes();
        assert_eq!(bytes.len(), 4); // PT + SEQ(2) + config

        let (parsed, len) = Ohb::parse(&bytes).unwrap();
        assert_eq!(len, 4);
        assert_eq!(parsed.original_pt, Some(111));
        assert_eq!(parsed.original_seq, Some(0xABCD));
        assert_eq!(parsed.original_marker, Some(false));
    }

    #[test]
    fn ohb_from_diff_no_changes() {
        let ohb = Ohb::from_diff(96, 96, 100, 100, false, false);
        assert!(ohb.is_empty());
    }

    #[test]
    fn ohb_from_diff_pt_changed() {
        let ohb = Ohb::from_diff(96, 111, 100, 100, false, false);
        assert_eq!(ohb.original_pt, Some(96));
        assert_eq!(ohb.original_seq, None);
    }

    #[test]
    fn ohb_update_preserves_original() {
        // Original sender: PT=96, SEQ=100
        // First MD changes PT to 111
        let ohb1 = Ohb::from_diff(96, 111, 100, 100, false, false);
        assert_eq!(ohb1.original_pt, Some(96));

        // Second MD changes PT again to 120 — should still record original 96
        let ohb2 = ohb1.update(111, 120, 100, 100, false, false);
        assert_eq!(ohb2.original_pt, Some(96));
    }

    #[test]
    fn ohb_update_removes_when_restored() {
        // Original: PT=96, MD changes to 111
        let ohb = Ohb::from_diff(96, 111, 100, 100, false, false);
        assert_eq!(ohb.original_pt, Some(96));

        // MD changes back to 96 — OHB should clear
        let ohb2 = ohb.update(111, 96, 100, 100, false, false);
        assert_eq!(ohb2.original_pt, None);
    }

    #[test]
    fn parse_ohb_from_larger_buffer() {
        // Simulate: [encrypted_payload... | ohb_bytes]
        let ohb = Ohb {
            original_pt: Some(96),
            original_seq: None,
            original_marker: None,
        };
        let ohb_bytes = ohb.to_bytes();

        let mut buf = vec![0xDE, 0xAD, 0xBE, 0xEF]; // fake payload
        buf.extend_from_slice(&ohb_bytes);

        // Parse from end of buffer
        let (parsed, len) = Ohb::parse(&buf[buf.len() - ohb_bytes.len()..]).unwrap();
        assert_eq!(len, 2);
        assert_eq!(parsed.original_pt, Some(96));
    }
}
