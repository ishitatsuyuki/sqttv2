use anyhow::{bail, Result};
use num_enum::IntoPrimitive;

#[derive(IntoPrimitive)]
#[repr(u8)]
pub enum SqttMarkerType {
    RGP_SQTT_MARKER_IDENTIFIER_EVENT = 0x0,
    RGP_SQTT_MARKER_IDENTIFIER_CB_START = 0x1,
    RGP_SQTT_MARKER_IDENTIFIER_CB_END = 0x2,
    RGP_SQTT_MARKER_IDENTIFIER_BARRIER_START = 0x3,
    RGP_SQTT_MARKER_IDENTIFIER_BARRIER_END = 0x4,
    RGP_SQTT_MARKER_IDENTIFIER_USER_EVENT = 0x5,
    RGP_SQTT_MARKER_IDENTIFIER_GENERAL_API = 0x6,
    RGP_SQTT_MARKER_IDENTIFIER_SYNC = 0x7,
    RGP_SQTT_MARKER_IDENTIFIER_PRESENT = 0x8,
    RGP_SQTT_MARKER_IDENTIFIER_LAYOUT_TRANSITION = 0x9,
    RGP_SQTT_MARKER_IDENTIFIER_RENDER_PASS = 0xA,
    RGP_SQTT_MARKER_IDENTIFIER_RESERVED2 = 0xB,
    RGP_SQTT_MARKER_IDENTIFIER_BIND_PIPELINE = 0xC,
    RGP_SQTT_MARKER_IDENTIFIER_RESERVED4 = 0xD,
    RGP_SQTT_MARKER_IDENTIFIER_RESERVED5 = 0xE,
    RGP_SQTT_MARKER_IDENTIFIER_RESERVED6 = 0xF
}

pub struct SqttUserdata {
    dw: Vec<u32>,
}

impl SqttUserdata {
    pub fn new(dw: Vec<u32>) -> Result<SqttUserdata> {
        if dw.len() == 0 {
            bail!("Userdata is empty");
        }
        let ret = SqttUserdata { dw };
        if Self::len(ret.dw[0]) != ret.dw.len() {
            bail!("Userdata length {} does not match metadata {}", ret.dw.len(), Self::len(ret.dw[0]));
        }
        Ok(ret)
    }

    pub fn id(&self) -> u8 {
        (self.dw[0] & ((1 << 4) - 1)) as _
    }

    pub fn len(dw0: u32) -> usize {
        ((dw0 >> 4) & ((1 << 3) - 1)) as usize
    }

    pub fn api_type(&self) -> u32 {
        ((self.dw[0] >> 7) & ((1 << 20) - 1)) as u32
    }
}
