use std::cmp;
use std::num::NonZeroU8;

use anyhow::{bail, Result};
use paste::paste;
use tracing::log::warn;

macro_rules! gen_parser_inner {
    (
        $self:ident $last_consume:ident $reader:ident $timestamp:ident [$top:literal:$bottom:literal] dt: $ty:ty
    ) => {
        if $top - $last_consume > 60 {
            $reader.consume($bottom - $last_consume);
            $last_consume = $bottom;
        }
        *$timestamp += $reader.bits($bottom - $last_consume, $top + 1 - $bottom)? as u64;
    };
    (
        $self:ident $last_consume:ident $reader:ident $timestamp:ident [$top:literal:$bottom:literal] $field:ident: $ty:ty
    ) => {
        if $top - $last_consume > 60 {
            $reader.consume($bottom - $last_consume);
            $last_consume = $bottom;
        }
        let $field = $reader.bits($bottom - $last_consume, $top + 1 - $bottom)? as $ty;
        $self.$field.push($field);
    };
}

macro_rules! gen_parser {
    (
        $(packet $pkt:ident {
            $([$top:literal:$bottom:literal] $field:ident: $ty:ty,)+
        })+
    ) => {
        $(
            #[derive(Default)]
            pub struct $pkt {
                pub seq: Vec<u32>,
                pub timestamp: Vec<u64>,
                $(pub $field: Vec<$ty>),+
            }

            impl $pkt {
                #[allow(unused_variables, unused_assignments)]
                fn parse(&mut self, reader: &mut BitReader, seq: u32, timestamp: &mut u64) -> Option<()> {
                    let mut last_consume = 0;
                    $(
                        gen_parser_inner!(self last_consume reader timestamp [$top:$bottom] $field: $ty);
                    )+
                    self.seq.push(seq);
                    self.timestamp.push(*timestamp);
                    Some(())
                }
            }
        )+

        paste! {
            #[derive(Default)]
            pub struct SqttChunk {
                $(pub [<$pkt:snake>]: $pkt),+
            }
        }
    };
}

gen_parser! {
    packet Packet0x21 {
        [10: 8] dt: u8,
    }

    packet Packet0x31 {
        [ 8: 7] dt: u8,
    }

    packet Packet0x41 {
        [ 9: 7] dt: u8,
    }

    packet Packet0x51 {
        [15: 7] dt: u16,
    }

    packet LongTimestamp {
        [15:14] ty: u8,
        [63:16] timestamp_value: u64,
    }

    packet EventA {
        [10: 8] dt: u8,
        [11:11] b0: u8,
        [13:12] selector: u8,
        [17:14] stage: u8,
        [23:18] a0: u8,
    }

    packet EventB {
        [10: 8] dt: u8,
        [11:11] b0: u8,
        [13:12] selector: u8,
        [17:14] stage: u8,
        [19:18] a0: u8,
        [31:20] a1: u8,
    }

    packet Initiator {
        [ 9: 7] dt: u8,
        [15:14] a0: u8,
        [17:16] a1: u8,
        [19:18] initiator_type: u8,
        [52:20] val: u32,
        // [46:44] context: u8,
    }

    packet RegWrite {
        [ 6: 4] dt: u8,
        [ 8: 7] a0: u8,
        [10: 9] a1: u8,
        [11:11] b0: u8,
        [15:15] is_write: u8,
        [31:16] reg: u16,
        [63:32] val: u32,
    }

    packet WaveStart {
        [ 6: 4] dt: u8,
        [ 7: 7] a0: u8,
        [ 9: 8] a1: u8,
        [12:10] a2: u8,
        [17:13] a3: u8,
        [21:18] stage: u8,
        [31:25] threads: u8,
    }

    packet WaveAllocEnd {
        [ 4: 4] is_end: u8,
        [ 7: 5] dt: u8,
        [ 8: 8] a0: u8,
        [10: 9] a1: u8,
        [13:11] a2: u8,
        [19:15] a3: u8,
    }

    packet GenericInst {
        [ 6: 4] dt: u8,
        [ 7: 7] b0: u8,
        [12: 8] a0: u8,
        [19:13] insn: u8,
    }

    packet ValuInst {
        [ 5: 3] dt: u8,
        [ 6: 6] b0: u8,
        [11: 7] a0: u8,
    }

    packet Immediate {
        [ 7: 5] dt: u8,
        [23: 8] wave_mask: u32,
    }

    packet ImmediateOne {
        [ 6: 4] dt: u8,
        [11: 7] wave_id: u8,
    }

    packet ShortTimestamp {
        [ 7: 4] dt_4: u8,
    }

    packet Packet0x6 {
        [ 7: 5] dt: u8,
    }

    packet Packet0xe {
        [ 5: 4] dt: u8,
    }

    packet Packet0xf {
        [ 5: 4] dt: u8,
    }
}

#[derive(Clone)]
struct BitReader<'a> {
    input: &'a [u8],
    bits: u64,
    bits_consumed: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(input: &'a [u8]) -> BitReader<'a> {
        if input.len() < 8 {
            unimplemented!("Short input initialization not implemented");
        }

        Self {
            input,
            bits: 0,
            bits_consumed: 0,
        }
    }

    #[inline]
    pub fn bits(&self, lsb: usize, width: usize) -> Option<u64> {
        // We maintain an invariant of bits_consumed <= 4 after refill.
        assert!(lsb + width <= 60);

        if lsb + width > 64 - self.bits_consumed {
            return None;
        }

        Some((self.bits >> (lsb + self.bits_consumed)) & ((1 << width) - 1))
    }

    #[inline]
    pub fn consume(&mut self, bits: usize) -> Option<()> {
        if bits + self.bits_consumed > self.input.len() * 8 {
            return None;
        }
        self.bits_consumed += bits;
        self.refill();
        Some(())
    }

    fn refill(&mut self) {
        // We can consume a maximum of 12B at once + 4 bit leftover (1B) + 8B read
        if self.input.len() < 29 {
            return self.refill_slow();
        }
        self.input = unsafe { self.input.get_unchecked(self.bits_consumed / 8..) };
        self.bits_consumed %= 8;
        self.bits = u64::from_le_bytes(unsafe { self.input.get_unchecked(..8) }.try_into().unwrap());
    }

    fn refill_slow(&mut self) {
        let advance = cmp::min(self.bits_consumed / 8, self.input.len() - 8);
        self.input = &self.input[advance..];
        self.bits_consumed -= advance * 8;
        self.bits = u64::from_le_bytes(self.input[..8].try_into().unwrap());
    }
}

/// The length in bits of a SQTT packet.
/// `selector` is the bottom 8 bits of the packet.
fn sqtt_packet_length(selector: u8) -> Option<NonZeroU8> {
    Some(
        NonZeroU8::new(match selector % 8 {
            2 => 20,
            3 => 12,
            _ => match selector % 16 {
                0 => 4,
                1 => match (selector / 16) % 8 {
                    0 | 1 | 2 | 3 | 7 => 64,
                    4 => 96,
                    5 => 24,
                    6 => match selector / 16 {
                        6 => 24,
                        14 => 32,
                        _ => unreachable!(),
                    },
                    _ => return None,
                },
                4 => {
                    if true {
                        24
                    } else {
                        28
                    }
                }
                5 => 20,
                6 => match selector % 32 {
                    6 => 52,
                    22 => 28,
                    _ => unreachable!(),
                },
                8 | 14 | 15 => 8,
                9 => 64,
                12 => 32,
                13 => 12,
                _ => return None,
            },
        })
        .unwrap(),
    )
}

fn build_packet_length_table() -> [Option<NonZeroU8>; 256] {
    (0..=255)
        .map(sqtt_packet_length)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn parse_sqtt(i: &[u8]) -> Result<SqttChunk> {
    let mut reader = BitReader::new(i);
    let mut seq = 0;
    let mut timestamp = 0;

    let pkt_len_table = build_packet_length_table();

    let mut result = SqttChunk::default();

    loop {
        let selector = reader.bits(0, 8);
        if selector.is_none() {
            let selector = reader.bits(0, 4);
            match selector {
                None => break,    // Reached end of stream
                Some(0) => break, // Reached end of stream with final 4-byte padding,
                Some(x) => bail!("Unknown packet type {}", x),
            }
        }
        let selector = selector.unwrap();

        let pkt_len = pkt_len_table[selector as usize];
        if pkt_len.is_none() {
            bail!("Unknown packet type {}", selector);
        }
        let pkt_len = pkt_len.unwrap().get() as usize;

        let mut subreader = reader.clone();
        let advance = reader.consume(pkt_len);

        // TODO: this part should be error free (assuming advance.is_some())
        let parse_result = match selector % 8 {
            2 => result.generic_inst.parse(&mut subreader, seq, &mut timestamp),
            3 => result.valu_inst.parse(&mut subreader, seq, &mut timestamp),
            _ => match selector % 16 {
                1 => match (selector / 16) % 8 {
                    0 => {
                        let ret = result.long_timestamp.parse(&mut subreader, seq, &mut timestamp);
                        if *result.long_timestamp.ty.last().unwrap() == 1 {
                            timestamp += result.long_timestamp.timestamp_value.last().unwrap();
                        }
                        ret
                    }
                    2 => result.packet0x21.parse(&mut subreader, seq, &mut timestamp),
                    3 => result.packet0x31.parse(&mut subreader, seq, &mut timestamp),
                    4 => result.packet0x41.parse(&mut subreader, seq, &mut timestamp),
                    5 => result.packet0x51.parse(&mut subreader, seq, &mut timestamp),
                    6 => match selector / 16 {
                        6 => result.event_a.parse(&mut subreader, seq, &mut timestamp),
                        14 => result.event_b.parse(&mut subreader, seq, &mut timestamp),
                        _ => unreachable!(),
                    },
                    7 => result.initiator.parse(&mut subreader, seq, &mut timestamp),
                    _ => Some(()),
                },
                4 => result.immediate.parse(&mut subreader, seq, &mut timestamp),
                5 => result.wave_alloc_end.parse(&mut subreader, seq, &mut timestamp),
                6 => result.packet0x6.parse(&mut subreader, seq, &mut timestamp),
                8 => {
                    let ret = result.short_timestamp.parse(&mut subreader, seq, &mut timestamp);
                    timestamp += *result.short_timestamp.dt_4.last().unwrap() as u64 + 4;
                    ret
                }
                9 => result.reg_write.parse(&mut subreader, seq, &mut timestamp),
                12 => result.wave_start.parse(&mut subreader, seq, &mut timestamp),
                13 => result.immediate_one.parse(&mut subreader, seq, &mut timestamp),
                14 => result.packet0xe.parse(&mut subreader, seq, &mut timestamp),
                15 => result.packet0xf.parse(&mut subreader, seq, &mut timestamp),
                _ => Some(()),
            },
        };

        if parse_result.is_none() || advance.is_none() {
            warn!("Unexpected EOF during parsing, truncated capture?");
            break;
        }
        seq += 1;
    }

    Ok(result)
}
