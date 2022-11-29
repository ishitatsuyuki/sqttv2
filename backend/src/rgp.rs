use anyhow::Result;
use scroll::{Pread, LE};

#[derive(Clone, Debug, Pread)]
pub struct RgpHeader {
    pub magic_number: u32,
    pub version_major: u32,
    pub version_minor: u32,
    pub flags: u32,
    pub chunk_offset: i32,
    pub second: i32,
    pub minute: i32,
    pub hour: i32,
    pub day_in_month: i32,
    pub month: i32,
    pub year: i32,
    pub day_in_week: i32,
    pub day_in_year: i32,
    pub is_daylight_savings: i32,
}

pub fn parse_header(i: &[u8]) -> Result<RgpHeader> {
    Ok(i.pread_with(0, LE)?)
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
    pub size: i32,
    pub reserved: i32,
}

pub fn parse_entry_header(i: &[u8]) -> Result<RgpEntryHeader> {
    Ok(i.pread_with(0, LE)?)
}

pub const ENTRY_HEADER_SIZE: usize = 16;

#[derive(Clone, Debug, Pread)]
pub struct RgpAsicInfo {
    pub flags: u64,
    pub trace_shader_core_clock: u64,
    pub trace_memory_clock: u64,
    pub device_id: i32,
    pub device_revision_id: i32,
    pub vgprs_per_simd: i32,
    pub sgprs_per_simd: i32,
    pub shader_engines: i32,
    pub compute_unit_per_shader_engine: i32,
    pub simd_per_compute_unit: i32,
    pub wavefronts_per_simd: i32,
    pub minimum_vgpr_alloc: i32,
    pub vgpr_alloc_granularity: i32,
    pub minimum_sgpr_alloc: i32,
    pub sgpr_alloc_granularity: i32,
    pub hardware_contexts: i32,
    pub gpu_type: i32,
    pub gfxip_level: i32,
    pub gpu_index: i32,
    pub gds_size: i32,
    pub gds_per_shader_engine: i32,
    pub ce_ram_size: i32,
    pub ce_ram_size_graphics: i32,
    pub ce_ram_size_compute: i32,
    pub max_number_of_dedicated_cus: i32,
    pub vram_size: i64,
    pub vram_bus_width: i32,
    pub l2_cache_size: i32,
    pub l1_cache_size: i32,
    pub lds_size: i32,
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
