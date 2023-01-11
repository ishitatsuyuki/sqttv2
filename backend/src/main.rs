use std::env::args_os;
use std::fs;

use anyhow::{anyhow, bail, Result};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use scroll::{Pread, LE};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::log::warn;

use crate::merge::{MergedIterator, MergedIteratorItem};
use crate::proto::sqtt_service_server::*;
use crate::proto::{Event, GetEventsRequest, GetEventsResponse};
use crate::rgp::{RgpAsicInfo, RgpEntryHeader, RgpHeader, SqttFileChunkType, ENTRY_HEADER_SIZE};
use crate::sqtt::{parse_sqtt, SqttChunk};
use crate::userdata::SqttUserdata;

mod merge;
mod rgp;
mod sqtt;
mod userdata;

pub mod proto {
    tonic::include_proto!("sqtt.v2");
}

struct Service {
    asic_info: RgpAsicInfo,
    chunks: Vec<SqttChunk>,
}

#[tonic::async_trait]
impl SqttService for Service {
    async fn get_events(
        &self,
        _request: Request<GetEventsRequest>,
    ) -> std::result::Result<Response<GetEventsResponse>, Status> {
        const SQ_THREAD_TRACE_USERDATA_2: u32 = 0x030D08 / 4;
        const SQ_THREAD_TRACE_USERDATA_3: u32 = 0x030D0C / 4;
        const THREAD_TRACE_MARKER: u32 = 53;

        let reg_write = &self.chunks[0].reg_write;
        let initiator = &self.chunks[0].initiator;
        let iter = MergedIterator::new(vec![&reg_write.seq, &initiator.seq]);

        let mut userdata_buf = vec![];
        let mut events = vec![];
        for MergedIteratorItem { kind, index: i } in iter {
            match kind {
                0 => {
                    if reg_write.reg[i] as u32 == SQ_THREAD_TRACE_USERDATA_2
                        || reg_write.reg[i] as u32 == SQ_THREAD_TRACE_USERDATA_3
                    {
                        userdata_buf.push(reg_write.val[i]);
                        if SqttUserdata::len(userdata_buf[0]).unwrap() == userdata_buf.len() {
                            events.push(Event {
                                r#type: SqttUserdata::new(userdata_buf).unwrap().api_type(),
                                start: 0,
                                end: 0,
                            });
                            userdata_buf = vec![];
                        }
                    }
                }
                1 => {
                    if initiator.initiator_type[i] == 0 && (initiator.val[i] & 0xfffff) == THREAD_TRACE_MARKER {
                        if !userdata_buf.is_empty() {
                            warn!("encountered initiator but userdata packet is incomplete");
                            userdata_buf.clear(); // Try to re-synchronize
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        Ok(Response::new(GetEventsResponse { events }))
    }
}

fn parse(data: &[u8]) -> Result<Service> {
    use SqttFileChunkType::*;
    let hdr: RgpHeader = data.pread_with(0, LE)?;
    let mut asic_info = None;
    let mut offset = hdr.chunk_offset as usize;
    let mut sqtt_chunks = vec![];
    while offset < data.len() {
        let entry: RgpEntryHeader = data.pread_with(offset, LE)?;
        if entry.size < ENTRY_HEADER_SIZE as _ {
            bail!("Corrupt chunk (size too small)");
        }
        let len = (entry.size as usize) - ENTRY_HEADER_SIZE;
        let chunk_type: SqttFileChunkType = entry.chunk_id.ty.try_into()?;
        match chunk_type {
            AsicInfo => {
                let start = offset + ENTRY_HEADER_SIZE;
                asic_info = Some(data.pread_with(start, LE)?);
            }
            SqttData => {
                let start = offset + ENTRY_HEADER_SIZE + 8;
                let sqtt_data = &data[start..offset + len];
                sqtt_chunks.push(sqtt_data);
            }
            _ => {}
        }
        offset += entry.size as usize;
    }
    let asic_info = asic_info.ok_or_else(|| anyhow!("No asic info found"))?;
    let chunks = sqtt_chunks
        .into_par_iter()
        .map(|chunk| parse_sqtt(chunk, &asic_info))
        .collect::<Result<Vec<_>>>()?;
    Ok(Service { asic_info, chunks })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let file = args_os().nth(1).ok_or_else(|| anyhow!("Missing file argument"))?;
    let buf = fs::read(file)?;

    let addr = "[::1]:50051".parse()?;
    let greeter = parse(&buf)?;

    Server::builder()
        .accept_http1(true)
        .add_service(tonic_web::enable(SqttServiceServer::new(greeter)))
        .serve(addr)
        .await?;

    Ok(())
}
