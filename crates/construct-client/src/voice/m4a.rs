//! An M4A file of one AAC-LC track, box by box as Apple's encoder writes one (`afconvert -f
//! m4af -d aac`): ftyp, mdat, then moov with the sample tables. Written here rather than by a
//! crate: the one tried wrote a malformed `esds` (an empty SL descriptor) that Apple tolerates and
//! other parsers do not.

/// Samples per AAC frame.
pub(super) const FRAME: u32 = 1024;

/// The file of `frames` (raw AAC-LC access units, 1024 samples each) at `rate`, mono,
/// `bit_rate` bits a second on average.
pub(super) fn write(frames: &[Vec<u8>], rate: u32, bit_rate: u32) -> Vec<u8> {
    let duration = frames.len() as u64 * u64::from(FRAME);
    let data_len: usize = frames.iter().map(Vec::len).sum();

    let mut out = Vec::with_capacity(data_len + 1024);
    boxed(&mut out, b"ftyp", |b| {
        b.extend_from_slice(b"M4A ");
        b.extend_from_slice(&0u32.to_be_bytes());
        for brand in [b"M4A ", b"mp42", b"isom"] {
            b.extend_from_slice(brand);
        }
    });
    // The chunk offset: the frames start after mdat's header.
    let chunk_offset = out.len() as u32 + 8;
    boxed(&mut out, b"mdat", |b| {
        for frame in frames {
            b.extend_from_slice(frame);
        }
    });
    let max_frame = frames.iter().map(Vec::len).max().unwrap_or(0) as u32;
    boxed(&mut out, b"moov", |b| {
        full(b, b"mvhd", 0, |b| {
            b.extend_from_slice(&[0; 8]); // created, modified
            b.extend_from_slice(&rate.to_be_bytes()); // timescale
            b.extend_from_slice(&(duration as u32).to_be_bytes());
            b.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // rate 1.0
            b.extend_from_slice(&0x0100u16.to_be_bytes()); // volume 1.0
            b.extend_from_slice(&[0; 10]);
            matrix(b);
            b.extend_from_slice(&[0; 24]); // pre-defined
            b.extend_from_slice(&2u32.to_be_bytes()); // next track id
        });
        boxed(b, b"trak", |b| {
            full(b, b"tkhd", 0x7, |b| {
                b.extend_from_slice(&[0; 8]);
                b.extend_from_slice(&1u32.to_be_bytes()); // track id
                b.extend_from_slice(&[0; 4]);
                b.extend_from_slice(&(duration as u32).to_be_bytes());
                b.extend_from_slice(&[0; 8]);
                b.extend_from_slice(&0u16.to_be_bytes()); // layer
                b.extend_from_slice(&0u16.to_be_bytes()); // alternate group
                b.extend_from_slice(&0x0100u16.to_be_bytes()); // volume
                b.extend_from_slice(&[0; 2]);
                matrix(b);
                b.extend_from_slice(&[0; 8]); // width, height
            });
            boxed(b, b"mdia", |b| {
                full(b, b"mdhd", 0, |b| {
                    b.extend_from_slice(&[0; 8]);
                    b.extend_from_slice(&rate.to_be_bytes());
                    b.extend_from_slice(&(duration as u32).to_be_bytes());
                    b.extend_from_slice(&0x55C4u16.to_be_bytes()); // language "und"
                    b.extend_from_slice(&[0; 2]);
                });
                full(b, b"hdlr", 0, |b| {
                    b.extend_from_slice(&[0; 4]);
                    b.extend_from_slice(b"soun");
                    b.extend_from_slice(&[0; 12]);
                    b.push(0); // name
                });
                boxed(b, b"minf", |b| {
                    full(b, b"smhd", 0, |b| b.extend_from_slice(&[0; 4]));
                    boxed(b, b"dinf", |b| {
                        full(b, b"dref", 0, |b| {
                            b.extend_from_slice(&1u32.to_be_bytes());
                            full(b, b"url ", 1, |_| {}); // in this file
                        });
                    });
                    boxed(b, b"stbl", |b| {
                        full(b, b"stsd", 0, |b| {
                            b.extend_from_slice(&1u32.to_be_bytes());
                            mp4a(b, rate, bit_rate, max_frame);
                        });
                        full(b, b"stts", 0, |b| {
                            b.extend_from_slice(&1u32.to_be_bytes());
                            b.extend_from_slice(&(frames.len() as u32).to_be_bytes());
                            b.extend_from_slice(&FRAME.to_be_bytes());
                        });
                        full(b, b"stsc", 0, |b| {
                            // One chunk holding every frame.
                            b.extend_from_slice(&1u32.to_be_bytes());
                            b.extend_from_slice(&1u32.to_be_bytes());
                            b.extend_from_slice(&(frames.len() as u32).to_be_bytes());
                            b.extend_from_slice(&1u32.to_be_bytes());
                        });
                        full(b, b"stsz", 0, |b| {
                            b.extend_from_slice(&0u32.to_be_bytes());
                            b.extend_from_slice(&(frames.len() as u32).to_be_bytes());
                            for frame in frames {
                                b.extend_from_slice(&(frame.len() as u32).to_be_bytes());
                            }
                        });
                        full(b, b"stco", 0, |b| {
                            b.extend_from_slice(&1u32.to_be_bytes());
                            b.extend_from_slice(&chunk_offset.to_be_bytes());
                        });
                    });
                });
            });
        });
    });
    out
}

/// The sample entry: mono, 16-bit, `rate`, and the decoder's configuration.
fn mp4a(b: &mut Vec<u8>, rate: u32, bit_rate: u32, max_frame: u32) {
    boxed(b, b"mp4a", |b| {
        b.extend_from_slice(&[0; 6]);
        b.extend_from_slice(&1u16.to_be_bytes()); // data reference
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&1u16.to_be_bytes()); // channels
        b.extend_from_slice(&16u16.to_be_bytes()); // sample size
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&(rate << 16).to_be_bytes()); // 16.16
        full(b, b"esds", 0, |b| {
            let config = audio_specific_config(rate);
            let mut decoder = vec![0x40, 0x15]; // MPEG-4 audio, audio stream
            decoder.extend_from_slice(&(max_frame * 8).to_be_bytes()[1..]); // buffer size
            decoder.extend_from_slice(&bit_rate.to_be_bytes()); // max
            decoder.extend_from_slice(&bit_rate.to_be_bytes()); // average
            descriptor(&mut decoder, 0x05, &config);
            let mut es = vec![0, 1, 0]; // ES id 1, no flags
            descriptor(&mut es, 0x04, &decoder);
            descriptor(&mut es, 0x06, &[0x02]); // SL: predefined for MP4
            descriptor(b, 0x03, &es);
        });
    });
}

/// AAC-LC (object type 2), the rate's index, one channel.
fn audio_specific_config(rate: u32) -> [u8; 2] {
    let index: u16 = match rate {
        96_000 => 0,
        88_200 => 1,
        64_000 => 2,
        48_000 => 3,
        44_100 => 4,
        32_000 => 5,
        24_000 => 6,
        22_050 => 7,
        16_000 => 8,
        12_000 => 9,
        11_025 => 10,
        _ => 11,
    };
    (2 << 11 | index << 7 | 1 << 3).to_be_bytes()
}

fn descriptor(b: &mut Vec<u8>, tag: u8, body: &[u8]) {
    b.push(tag);
    // Lengths here are under 128: one byte.
    b.push(body.len() as u8);
    b.extend_from_slice(body);
}

fn matrix(b: &mut Vec<u8>) {
    for v in [0x0001_0000u32, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000] {
        b.extend_from_slice(&v.to_be_bytes());
    }
}

fn boxed(out: &mut Vec<u8>, kind: &[u8; 4], body: impl FnOnce(&mut Vec<u8>)) {
    let start = out.len();
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(kind);
    body(out);
    let size = (out.len() - start) as u32;
    out[start..start + 4].copy_from_slice(&size.to_be_bytes());
}

fn full(out: &mut Vec<u8>, kind: &[u8; 4], flags: u32, body: impl FnOnce(&mut Vec<u8>)) {
    boxed(out, kind, |b| {
        b.extend_from_slice(&flags.to_be_bytes()); // version 0, then the flags
        body(b);
    });
}
