use anyhow::{bail, Context, Result};
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(TryFromPrimitive, IntoPrimitive, Debug)]
#[repr(u8)]
// For several marker types we don't know their layouts; those are omitted from the enum.
pub enum RgpSqttMarkerIdentifier {
    Event = 0x0,
    CbStart = 0x1,
    CbEnd = 0x2,
    BarrierStart = 0x3,
    BarrierEnd = 0x4,
    UserEvent = 0x5,
    GeneralApi = 0x6,
    LayoutTransition = 0x9,
    BindPipeline = 0xC,
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
        Self::try_id(ret.dw[0]).with_context(|| "Unknown marker type")?;
        Ok(ret)
    }

    pub fn id(&self) -> RgpSqttMarkerIdentifier {
        Self::try_id(self.dw[0]).unwrap()
    }

    pub fn try_id(dw0: u32) -> Result<RgpSqttMarkerIdentifier> {
        ((dw0 & ((1 << 4) - 1)) as u8).try_into().map_err(Into::into)
    }

    pub fn len(dw0: u32) -> Result<usize> {
        use RgpSqttMarkerIdentifier::*;
        Ok(match Self::try_id(dw0)? {
            Event => 3 + if (dw0 & (1 << 31)) != 0 { 3 } else { 0 },
            CbStart => 4,
            CbEnd => 3,
            BarrierStart => 2,
            BarrierEnd => 2,
            UserEvent => 1, // TODO: adaptive length
            GeneralApi => 1,
            LayoutTransition => 2,
            BindPipeline => 3,
        })
    }

    pub fn api_type(&self) -> u32 {
        ((self.dw[0] >> 7) & ((1 << 20) - 1)) as u32
    }
}
