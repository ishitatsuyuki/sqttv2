use std::env::args_os;
use std::fs;

use anyhow::{anyhow, bail, Result};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::log::{info, warn};

use crate::rgp::{parse_entry_header, parse_header, ENTRY_HEADER_SIZE};
use crate::sqtt::{parse_sqtt, SqttChunk};

mod merge;
mod rgp;
mod sqtt;
mod userdata;

pub mod proto {
    tonic::include_proto!("sqtt.v2");
}

use crate::proto::{GetEventsRequest, GetEventsResponse};
use proto::sqtt_service_server::*;
use crate::merge::{MergedIterator, MergedIteratorItem};
use crate::userdata::SqttUserdata;

struct Service {
    chunks: Vec<SqttChunk>,
}

#[tonic::async_trait]
impl SqttService for Service {
    async fn get_events(
        &self,
        request: Request<GetEventsRequest>,
    ) -> std::result::Result<Response<GetEventsResponse>, Status> {
        const SQ_THREAD_TRACE_USERDATA_2: u32 = 0x030D08 / 4;
        const SQ_THREAD_TRACE_USERDATA_3: u32 = 0x030D0C / 4;
        const THREAD_TRACE_MAKRER: u32 = 53;

        let reg_write = &self.chunks[0].reg_write;
        let initiator = &self.chunks[0].initiator;
        let iter = MergedIterator::new(vec![&reg_write.seq, &initiator.seq]);

        let mut userdata_buf = vec![];
        let mut events = vec![];
        for MergedIteratorItem {
          kind, index: i
        } in iter {
            match kind {
                0 => {
                    if reg_write.reg[i] as u32 == SQ_THREAD_TRACE_USERDATA_2 || reg_write.reg[i] as u32 == SQ_THREAD_TRACE_USERDATA_3 {
                        userdata_buf.push(reg_write.val[i]);
                        if SqttUserdata::len(userdata_buf[0]) == userdata_buf.len() {
                            events.push(SqttUserdata::new(userdata_buf).unwrap()); // TODO: error handling
                            userdata_buf = vec![];
                        }
                    }
                },
                1 => {
                    if initiator.initiator_type[i] == 0 && (initiator.val[i] & 0xfffff) == THREAD_TRACE_MAKRER {
                       if !userdata_buf.is_empty() {
                           warn!("encountered initiator but userdata packet is incomplete");
                       }
                    }
                },
                _ => unreachable!(),
            }
        }
        Ok(Response::new(GetEventsResponse {}))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let file = args_os().nth(1).ok_or_else(|| anyhow!("Missing file argument"))?;
    info!("Parsing file {:?}", file);
    let buf = fs::read(file)?;
    let hdr = parse_header(&buf)?;
    let mut sqtt_chunks = vec![];
    let mut offset = hdr.chunk_offset as usize;
    while offset < buf.len() {
        let entry = parse_entry_header(&buf[offset..])?;
        if entry.size < ENTRY_HEADER_SIZE as _ {
            bail!("Corrupt chunk (size too small)");
        }
        let len = (entry.size as usize) - ENTRY_HEADER_SIZE;
        if entry.chunk_id.ty == 2 {
            let start = offset + ENTRY_HEADER_SIZE + 8;
            let sqtt_data = &buf[start..offset + len];
            sqtt_chunks.push(parse_sqtt(sqtt_data)?);
        }
        offset += entry.size as usize;
    }
    info!("Done parsing");

    let addr = "[::1]:50051".parse()?;
    let greeter = Service { chunks: sqtt_chunks };

    Server::builder()
        .accept_http1(true)
        .add_service(tonic_web::enable(SqttServiceServer::new(greeter)))
        .serve(addr)
        .await?;

    Ok(())
}
