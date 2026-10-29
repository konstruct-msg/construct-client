//! Voice notes recorded here, as iOS and Android record them (`AudioRecorderService`,
//! `VoiceRecorder`): AAC-LC in an MP4 file, mono, 64 kbit/s, at most five minutes, with a
//! waveform of up to 100 bars. The recording is sent by [`crate::ClientCommand::SendVoice`].
//!
//! The encoder is Fraunhofer's (fdk-aac, built into the app): there is no AAC encoder in Rust,
//! and the systems' own are not on every Linux. The waveform follows iOS: a level every 50 ms,
//! −50…0 dBFS as 0…1, averaged down to 100 bars — over the whole recording (iOS keeps the last
//! 400 levels only, so its long notes show their last 20 seconds).

mod recorder;

pub use recorder::Recorder;

use crate::outgoing::{MAX_VOICE_MS, Voice};

/// One level per this many milliseconds, as iOS meters.
const LEVEL_MS: u32 = 50;
/// Bars sent, as iOS and Android send.
const BARS: usize = 100;
/// Rates the file is written at as captured; anything else is resampled to 44.1 kHz.
const NATIVE_RATES: [u32; 2] = [44_100, 48_000];
const BIT_RATE: u32 = 64_000;
/// Samples per AAC frame.
const FRAME: usize = 1024;

/// A level 0..=1 for `samples` (−1..1): their power in dBFS, −50 dBFS and below as 0.
pub fn level(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let power = samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32;
    let db = 10.0 * power.max(1e-12).log10();
    ((db + 50.0) / 50.0).clamp(0.0, 1.0)
}

/// The bars of `pcm` at `rate`: a level per 50 ms, averaged down to [`BARS`] (fewer for a note
/// shorter than five seconds), each 0..=255.
pub fn waveform(pcm: &[f32], rate: u32) -> Vec<u8> {
    let window = (rate * LEVEL_MS / 1000).max(1) as usize;
    let levels: Vec<f32> = pcm.chunks(window).map(level).collect();
    let bars: Vec<f32> = if levels.len() <= BARS {
        levels
    } else {
        let step = levels.len() as f32 / BARS as f32;
        (0..BARS)
            .map(|i| {
                let start = (i as f32 * step) as usize;
                let end = (((i + 1) as f32 * step) as usize).clamp(start + 1, levels.len());
                levels[start..end].iter().sum::<f32>() / (end - start) as f32
            })
            .collect()
    };
    bars.iter().map(|b| (b * 255.0).round() as u8).collect()
}

/// `pcm` (mono, −1..1, at `rate`) as a voice note ready to send. Past five minutes it is cut.
pub fn encode(pcm: &[f32], rate: u32) -> Result<Voice, String> {
    if rate == 0 || pcm.is_empty() {
        return Err("nothing recorded".into());
    }
    let max = (u64::from(MAX_VOICE_MS) * u64::from(rate) / 1000) as usize;
    let pcm = &pcm[..pcm.len().min(max)];
    let (pcm, rate) = if NATIVE_RATES.contains(&rate) {
        (pcm.to_vec(), rate)
    } else {
        (resample(pcm, rate, 44_100), 44_100)
    };
    let duration_ms = (pcm.len() as u64 * 1000 / u64::from(rate)) as u32;
    Ok(Voice {
        bytes: m4a(&pcm, rate)?,
        duration_ms: duration_ms.max(1),
        waveform: waveform(&pcm, rate),
    })
}

/// Linear interpolation: enough for a voice, and only for a microphone at an unusual rate.
fn resample(pcm: &[f32], from: u32, to: u32) -> Vec<f32> {
    let out_len = (pcm.len() as u64 * u64::from(to) / u64::from(from)) as usize;
    let ratio = f64::from(from) / f64::from(to);
    (0..out_len)
        .map(|i| {
            let at = i as f64 * ratio;
            let j = at as usize;
            let frac = (at - j as f64) as f32;
            let a = pcm[j.min(pcm.len() - 1)];
            let b = pcm[(j + 1).min(pcm.len() - 1)];
            a + (b - a) * frac
        })
        .collect()
}

/// AAC-LC frames of `pcm` in an M4A file.
fn m4a(pcm: &[f32], rate: u32) -> Result<Vec<u8>, String> {
    use fdk_aac::enc::{AudioObjectType, BitRate, ChannelMode, Encoder, EncoderParams, Transport};
    let encoder = Encoder::new(EncoderParams {
        bit_rate: BitRate::Cbr(BIT_RATE),
        sample_rate: rate,
        transport: Transport::Raw,
        channels: ChannelMode::Mono,
        audio_object_type: AudioObjectType::Mpeg4LowComplexity,
    })
    .map_err(|e| format!("AAC encoder: {e}"))?;
    let delay = encoder
        .info()
        .map_err(|e| format!("AAC encoder: {e}"))?
        .nDelay as usize;
    let mut input: Vec<i16> = pcm
        .iter()
        .map(|s| (s.clamp(-1.0, 1.0) * f32::from(i16::MAX)) as i16)
        .collect();
    // Silence after the end pushes the encoder's look-ahead out as frames.
    input.resize(input.len() + delay + FRAME, 0);
    let mut frames = Vec::new();
    let mut out = vec![0u8; 8 * FRAME];
    for chunk in input.chunks(FRAME) {
        let info = encoder
            .encode(chunk, &mut out)
            .map_err(|e| format!("AAC encoder: {e}"))?;
        if info.output_size > 0 {
            frames.push(out[..info.output_size].to_vec());
        }
    }
    mux(&frames, rate)
}

fn mux(frames: &[Vec<u8>], rate: u32) -> Result<Vec<u8>, String> {
    use mp4::{
        AacConfig, AudioObjectType, ChannelConfig, MediaConfig, Mp4Config, Mp4Sample, Mp4Writer,
        SampleFreqIndex, TrackConfig, TrackType,
    };
    let err = |e: mp4::Error| format!("M4A: {e}");
    let brand = |b: &str| b.parse().map_err(err);
    let mut file = std::io::Cursor::new(Vec::new());
    let mut writer = Mp4Writer::write_start(
        &mut file,
        &Mp4Config {
            major_brand: brand("M4A ")?,
            minor_version: 512,
            compatible_brands: vec![brand("M4A ")?, brand("isom")?, brand("mp42")?],
            timescale: 1000,
        },
    )
    .map_err(err)?;
    writer
        .add_track(&TrackConfig {
            track_type: TrackType::Audio,
            timescale: rate,
            language: "und".into(),
            media_conf: MediaConfig::AacConfig(AacConfig {
                bitrate: BIT_RATE,
                profile: AudioObjectType::AacLowComplexity,
                // `encode` writes at one of `NATIVE_RATES` only.
                freq_index: if rate == 48_000 {
                    SampleFreqIndex::Freq48000
                } else {
                    SampleFreqIndex::Freq44100
                },
                chan_conf: ChannelConfig::Mono,
            }),
        })
        .map_err(err)?;
    for (i, frame) in frames.iter().enumerate() {
        writer
            .write_sample(
                1,
                &Mp4Sample {
                    start_time: (i * FRAME) as u64,
                    duration: FRAME as u32,
                    rendering_offset: 0,
                    is_sync: true,
                    bytes: bytes::Bytes::copy_from_slice(frame),
                },
            )
            .map_err(err)?;
    }
    writer.write_end().map_err(err)?;
    Ok(file.into_inner())
}

#[cfg(test)]
mod tests;
