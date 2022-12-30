use anyhow::anyhow;
use clap::Parser;
use defmt_decoder::{DecodeError, Frame, Locations, Table};
use std::{
    env, fs,
    io::Read,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

const MAX_ITM_PAYLOAD: usize = 4;

#[derive(Parser, Debug, Clone)]
struct Args {
    #[arg(long, default_value_t = 60)]
    wait: u64,
    #[arg(long)]
    listen: String,
    #[arg(long)]
    port: u8,
    #[arg(long)]
    elf: std::path::PathBuf,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    show_skipped_frames: bool,
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug)]
struct ItmHeader {
    pub port: u8,
    pub payload_size: usize,
}

struct ItmPacket {
    header: Option<ItmHeader>,
    payload: [u8; MAX_ITM_PAYLOAD],
    payload_size: usize,
}

#[derive(Debug)]
struct Context {
    args: Args,
    table: Table,
    locs: Option<Locations>,
    current_dir: PathBuf,
    tcp_stream: TcpStream,
}

impl ItmHeader {
    fn from_byte(byte: u8) -> anyhow::Result<Self> {
        match byte & 0b111 {
            0b001 | 0b010 | 0b011 => Ok(ItmHeader {
                port: byte >> 3,
                payload_size: match byte & 0b11 {
                    0b01 => 1,
                    0b10 => 2,
                    0b11 => 4,
                    _ => unreachable!(),
                },
            }),
            _ => Err(anyhow!("Unknown ITM header {}", byte)),
        }
    }
}

impl ItmPacket {
    fn new() -> Self {
        ItmPacket {
            header: None,
            payload: [0; MAX_ITM_PAYLOAD],
            payload_size: 0,
        }
    }

    fn receive(&mut self, port: u8, byte: u8) -> anyhow::Result<Option<&[u8]>> {
        match &self.header {
            Some(header) => {
                self.payload[self.payload_size] = byte;
                self.payload_size += 1;

                if self.payload_size == header.payload_size {
                    self.header = None;
                    return Ok(Some(&self.payload[..self.payload_size]));
                }
            }
            None => match ItmHeader::from_byte(byte) {
                Ok(header) => {
                    if header.port == port {
                        self.header = Some(header);
                        self.payload_size = 0;
                    }
                }
                Err(err) => println!("Failed to parse ITM header: {}", err),
            },
        };

        Ok(None)
    }
}

impl Context {
    fn try_new(args: Args) -> anyhow::Result<Option<Self>> {
        let bytes = fs::read(args.elf.clone())?;
        let table = Table::parse(&bytes)?.ok_or_else(|| anyhow!(".defmt data not found"))?;
        let locs = table.get_locations(&bytes)?;
        let locs = if table.indices().all(|idx| locs.contains_key(&(idx as u64))) {
            Some(locs)
        } else {
            log::warn!("(BUG) location info is incomplete; it will be omitted from the output");
            None
        };

        let current_dir = env::current_dir()?;

        println!("Connection to {}...", args.listen);

        match TcpStream::connect_timeout(
            &SocketAddr::from_str(args.listen.as_str()).unwrap(),
            Duration::from_secs(args.wait),
        ) {
            Ok(tcp_stream) => Ok(Some(Context {
                args,
                table,
                locs,
                current_dir,
                tcp_stream,
            })),
            Err(err) => {
                println!("Connection failed: {}", err);
                Ok(None)
            }
        }
    }

    fn exec(&mut self) -> anyhow::Result<()> {
        let mut buffer = [0; 1];
        let mut itm_packet = ItmPacket::new();
        let mut decoder = self.table.new_stream_decoder();

        loop {
            match self.tcp_stream.read(&mut buffer) {
                Ok(n) if n > 0 && n <= buffer.len() => {
                    if let Some(packet) = itm_packet.receive(self.args.port, buffer[0])? {
                        decoder.received(packet);

                        loop {
                            match decoder.decode() {
                                Ok(frame) => forward_to_logger(
                                    &frame,
                                    location_info(&self.locs, &frame, &self.current_dir),
                                ),
                                Err(DecodeError::UnexpectedEof) => break,
                                Err(DecodeError::Malformed) => {
                                    match self.table.encoding().can_recover() {
                                        // if recovery is impossible, abort
                                        false => return Err(DecodeError::Malformed.into()),
                                        // if recovery is possible, skip the current frame and continue with new data
                                        true => {
                                            if self.args.show_skipped_frames || self.args.verbose {
                                                println!("(HOST) malformed frame skipped");
                                                println!(
                                                    "└─ {} @ {}:{}",
                                                    env!("CARGO_PKG_NAME"),
                                                    file!(),
                                                    line!()
                                                );
                                            }
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(n) => return Err(anyhow!("Read invalid count: {}", n)),
                Err(err) => {
                    println!("Read failed: {}.", err);
                    return Ok(());
                }
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    defmt_decoder::log::init_logger(args.verbose, args.json, move |metadata| {
        match args.verbose {
            false => defmt_decoder::log::is_defmt_frame(metadata), // We display *all* defmt frames, but nothing else.
            true => true,                                          // We display *all* frames.
        }
    });

    loop {
        match Context::try_new(args.clone())? {
            Some(mut context) => {
                println!("Connected!");
                context.exec()?
            }
            None => println!("Reconnecting..."),
        }
    }
}

type LocationInfo = (Option<String>, Option<u32>, Option<String>);

fn forward_to_logger(frame: &Frame, location_info: LocationInfo) {
    let (file, line, mod_path) = location_info;
    defmt_decoder::log::log_defmt(frame, file.as_deref(), line, mod_path.as_deref());
}

fn location_info(locs: &Option<Locations>, frame: &Frame, current_dir: &Path) -> LocationInfo {
    let (mut file, mut line, mut mod_path) = (None, None, None);

    // NOTE(`[]` indexing) all indices in `table` have been verified to exist in the `locs` map
    let loc = locs.as_ref().map(|locs| &locs[&frame.index()]);

    if let Some(loc) = loc {
        // try to get the relative path, else the full one
        let path = loc.file.strip_prefix(current_dir).unwrap_or(&loc.file);

        file = Some(path.display().to_string());
        line = Some(loc.line as u32);
        mod_path = Some(loc.module.clone());
    }

    (file, line, mod_path)
}
