use num_enum::{IntoPrimitive, TryFromPrimitive};
use scroll::Pread;

#[derive(Clone, Debug, Pread)]
pub struct RgpHeader {
    pub magic_number: u32,
    pub version_major: u32,
    pub version_minor: u32,
    pub flags: u32,
    pub chunk_offset: u32,
    pub second: u32,
    pub minute: u32,
    pub hour: u32,
    pub day_in_month: u32,
    pub month: u32,
    pub year: u32,
    pub day_in_week: u32,
    pub day_in_year: u32,
    pub is_daylight_savings: u32,
}

#[derive(TryFromPrimitive, IntoPrimitive, Debug)]
#[repr(u8)]
pub enum SqttFileChunkType {
    AsicInfo,
    SqttDesc,
    SqttData,
    ApiInfo,
    Reserved,
    QueueEventTimings,
    ClockCalibration,
    CpuInfo,
    SpmDb,
    CodeObjectDatabase,
    CodeObjectLoaderEvents,
    PsoCorrelation,
    InstrumentationTable,
    Count,
}

#[derive(Clone, Debug, Pread)]
pub struct ChunkId {
    pub ty: u8,
    pub index: u8,
    pub reserved: u16,
}

#[derive(Clone, Debug, Pread)]
pub struct RgpEntryHeader {
    pub chunk_id: ChunkId,
    pub version_major: u16,
    pub version_minor: u16,
    pub size: u32,
    pub reserved: u32,
}

pub const ENTRY_HEADER_SIZE: usize = 16;

#[derive(TryFromPrimitive, IntoPrimitive, Debug)]
#[repr(u32)]
pub enum SqttGfxipLevel {
    None = 0x0,
    GfxIp6 = 0x1,
    GfxIp7 = 0x2,
    GfxIp8 = 0x3,
    GfxIp8_1 = 0x4,
    GfxIp9 = 0x5,
    GfxIp10_1 = 0x7,
    GfxIp10_3 = 0x9,
}

#[derive(Clone, Debug, Pread)]
pub struct RgpAsicInfo {
    pub flags: u64,
    pub trace_shader_core_clock: u64,
    pub trace_memory_clock: u64,
    pub device_id: u32,
    pub device_revision_id: u32,
    pub vgprs_per_simd: u32,
    pub sgprs_per_simd: u32,
    pub shader_engines: u32,
    pub compute_unit_per_shader_engine: u32,
    pub simd_per_compute_unit: u32,
    pub wavefronts_per_simd: u32,
    pub minimum_vgpr_alloc: u32,
    pub vgpr_alloc_granularity: u32,
    pub minimum_sgpr_alloc: u32,
    pub sgpr_alloc_granularity: u32,
    pub hardware_contexts: u32,
    pub gpu_type: u32,
    pub gfxip_level: u32,
    pub gpu_index: u32,
    pub gds_size: u32,
    pub gds_per_shader_engine: u32,
    pub ce_ram_size: u32,
    pub ce_ram_size_graphics: u32,
    pub ce_ram_size_compute: u32,
    pub max_number_of_dedicated_cus: u32,
    pub vram_size: i64,
    pub vram_bus_width: u32,
    pub l2_cache_size: u32,
    pub l1_cache_size: u32,
    pub lds_size: u32,
    pub gpu_name: [u8; 256],
    pub alu_per_clock: f32,
    pub texture_per_clock: f32,
    pub prims_per_clock: f32,
    pub pixels_per_clock: f32,
    pub gpu_timestamp_frequency: u64,
    pub max_shader_core_clock: u64,
    pub max_memory_clock: u64,
    pub memory_ops_per_clock: u32,
    pub memory_chip_type: u32,
    pub lds_granularity: u32,
    pub cu_mask: [u16; 64],
    pub reserved1: [u8; 128],
    pub padding: [u8; 4],
}
