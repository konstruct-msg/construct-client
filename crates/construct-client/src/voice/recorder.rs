//! The microphone, through cpal (ALSA on Linux, so PulseAudio and PipeWire through their ALSA
//! plugins; WASAPI on Windows). The stream lives on a thread of its own, as it may not move
//! between threads on every system; the samples gather, mono, until the recording is finished or
//! dropped.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{FromSample, SampleFormat, SizedSample};

use crate::outgoing::{MAX_VOICE_MS, Voice};

/// A recording under way. Dropped without [`Recorder::finish`], it ends and nothing is kept.
pub struct Recorder {
    shared: Arc<Shared>,
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    rate: u32,
}

struct Shared {
    pcm: Mutex<Vec<f32>>,
    /// The level of the last callback's samples, 0..=1, as f32 bits.
    level: AtomicU32,
    /// Samples beyond five minutes are not kept.
    max: usize,
}

impl Recorder {
    /// Start recording from the system's default microphone.
    pub fn start() -> Result<Self, String> {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("voice-recorder".into())
            .spawn(move || {
                let stream = match open() {
                    Ok((stream, rate, shared)) => {
                        let _ = ready_tx.send(Ok((rate, shared)));
                        stream
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                // Until finished or dropped: either sends or hangs up.
                let _ = stop_rx.recv();
                drop(stream);
            })
            .map_err(|e| format!("recorder thread: {e}"))?;
        let (rate, shared) = ready_rx
            .recv()
            .map_err(|_| "the recorder stopped".to_string())??;
        Ok(Self {
            shared,
            stop: Some(stop_tx),
            thread: Some(thread),
            rate,
        })
    }

    /// How loud the microphone is now, 0..=1 (−50…0 dBFS), for the live bars.
    pub fn level(&self) -> f32 {
        f32::from_bits(self.shared.level.load(Ordering::Relaxed))
    }

    /// How long the recording is so far.
    pub fn elapsed_ms(&self) -> u32 {
        let len = self
            .shared
            .pcm
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        (len as u64 * 1000 / u64::from(self.rate)) as u32
    }

    /// Whether five minutes are recorded: nothing more is kept.
    pub fn full(&self) -> bool {
        self.shared
            .pcm
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
            >= self.shared.max
    }

    /// End the recording and make it a voice note.
    pub fn finish(mut self) -> Result<Voice, String> {
        self.end();
        let pcm = std::mem::take(&mut *self.shared.pcm.lock().unwrap_or_else(|e| e.into_inner()));
        super::encode(&pcm, self.rate)
    }

    fn end(&mut self) {
        self.stop.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.end();
    }
}

fn open() -> Result<(cpal::Stream, u32, Arc<Shared>), String> {
    let device = cpal::default_host()
        .default_input_device()
        .ok_or("no microphone")?;
    let config = device
        .default_input_config()
        .map_err(|e| format!("microphone: {e}"))?;
    let rate = config.sample_rate();
    let channels = usize::from(config.channels()).max(1);
    let shared = Arc::new(Shared {
        pcm: Mutex::new(Vec::with_capacity(rate as usize * 30)),
        level: AtomicU32::new(0),
        max: (u64::from(MAX_VOICE_MS) * u64::from(rate) / 1000) as usize,
    });
    let format = config.sample_format();
    let config: cpal::StreamConfig = config.into();
    let stream = match format {
        SampleFormat::F32 => build::<f32>(&device, config, channels, shared.clone()),
        SampleFormat::I16 => build::<i16>(&device, config, channels, shared.clone()),
        SampleFormat::I32 => build::<i32>(&device, config, channels, shared.clone()),
        SampleFormat::U16 => build::<u16>(&device, config, channels, shared.clone()),
        SampleFormat::U8 => build::<u8>(&device, config, channels, shared.clone()),
        other => return Err(format!("microphone sample format {other}")),
    }?;
    stream.play().map_err(|e| format!("microphone: {e}"))?;
    Ok((stream, rate, shared))
}

fn build<T>(
    device: &cpal::Device,
    config: cpal::StreamConfig,
    channels: usize,
    shared: Arc<Shared>,
) -> Result<cpal::Stream, String>
where
    T: SizedSample,
    f32: FromSample<T>,
{
    device
        .build_input_stream::<T, _, _>(
            config,
            move |data: &[T], _| {
                // Mono: the channels of each frame averaged.
                let mono: Vec<f32> = data
                    .chunks(channels)
                    .map(|frame| {
                        frame.iter().map(|s| s.to_sample::<f32>()).sum::<f32>() / channels as f32
                    })
                    .collect();
                shared
                    .level
                    .store(super::level(&mono).to_bits(), Ordering::Relaxed);
                let mut pcm = shared.pcm.lock().unwrap_or_else(|e| e.into_inner());
                let room = shared.max.saturating_sub(pcm.len());
                pcm.extend_from_slice(&mono[..mono.len().min(room)]);
            },
            |e| tracing::warn!("microphone: {e}"),
            None,
        )
        .map_err(|e| format!("microphone: {e}"))
}
