use super::*;

fn tone(secs: f32, rate: u32, amplitude: f32) -> Vec<f32> {
    (0..(secs * rate as f32) as usize)
        .map(|i| (i as f32 * 440.0 * std::f32::consts::TAU / rate as f32).sin() * amplitude)
        .collect()
}

/// What iOS and Android expect: an M4A with one AAC-LC track, mono, the length it was.
#[test]
fn a_recording_becomes_an_m4a_voice_note() {
    let voice = encode(&tone(2.0, 48_000, 0.5), 48_000).unwrap();
    assert!(crate::outgoing::check_voice(&voice).is_ok());
    assert_eq!(voice.duration_ms, 2_000);
    let size = voice.bytes.len() as u64;
    let file = mp4::Mp4Reader::read_header(std::io::Cursor::new(&voice.bytes), size).unwrap();
    assert_eq!(file.major_brand().to_string(), "M4A ");
    let tracks: Vec<_> = file.tracks().values().collect();
    assert_eq!(tracks.len(), 1);
    let track = tracks[0];
    assert_eq!(track.media_type().unwrap(), mp4::MediaType::AAC);
    assert_eq!(
        track.sample_freq_index().unwrap(),
        mp4::SampleFreqIndex::Freq48000
    );
    assert_eq!(track.channel_config().unwrap(), mp4::ChannelConfig::Mono);
    // Two seconds of 1024-sample frames, and the encoder's look-ahead after them.
    let frames = track.sample_count() as usize;
    assert!((94..=100).contains(&frames), "{frames} frames");
    // About 64 kbit/s, as the others send.
    assert!((12_000..24_000).contains(&size), "{size} bytes");
}

/// An independent decoder reads the file back as the sound it was: Symphonia, as the desktop
/// plays notes with it, and a stricter parser than Apple's.
#[test]
fn a_recording_decodes_back_to_its_sound() {
    use symphonia::core::codecs::audio::AudioDecoderOptions;
    use symphonia::core::formats::probe::Hint;
    use symphonia::core::formats::{FormatOptions, TrackType};
    use symphonia::core::io::MediaSourceStream;

    let voice = encode(&tone(1.0, 44_100, 0.5), 44_100).unwrap();
    let source = MediaSourceStream::new(
        Box::new(std::io::Cursor::new(voice.bytes)),
        Default::default(),
    );
    let mut format = symphonia::default::get_probe()
        .probe(
            &Hint::new(),
            source,
            FormatOptions::default(),
            Default::default(),
        )
        .expect("the file parses");
    let track = format.default_track(TrackType::Audio).unwrap();
    let id = track.id;
    let mut decoder = symphonia::default::get_codecs()
        .make_audio_decoder(
            track.codec_params.as_ref().unwrap().audio().unwrap(),
            &AudioDecoderOptions::default(),
        )
        .unwrap();
    let (mut samples, mut loudest, mut rate) = (0, 0f32, 0);
    let mut buf = Vec::new();
    while let Ok(Some(packet)) = format.next_packet() {
        if packet.track_id != id {
            continue;
        }
        let decoded = decoder.decode(&packet).expect("every frame decodes");
        rate = decoded.spec().rate();
        assert_eq!(decoded.spec().channels().count(), 1);
        buf.resize(decoded.samples_interleaved(), 0f32);
        decoded.copy_to_slice_interleaved(&mut buf);
        samples += buf.len();
        loudest = buf.iter().fold(loudest, |m, s| m.max(s.abs()));
    }
    assert_eq!(rate, 44_100);
    let secs = samples as f32 / 44_100.0;
    assert!((1.0..1.2).contains(&secs), "{secs} s");
    assert!(
        (0.4..0.6).contains(&loudest),
        "the tone at half scale: {loudest}"
    );
}

#[test]
fn an_unusual_rate_is_resampled_to_44_1_khz() {
    let voice = encode(&tone(1.0, 16_000, 0.5), 16_000).unwrap();
    assert_eq!(voice.duration_ms, 1_000);
    let size = voice.bytes.len() as u64;
    let file = mp4::Mp4Reader::read_header(std::io::Cursor::new(&voice.bytes), size).unwrap();
    let track = file.tracks().values().next().unwrap();
    assert_eq!(
        track.sample_freq_index().unwrap(),
        mp4::SampleFreqIndex::Freq44100
    ); // A second at 44.1 kHz in 1024-sample frames, not at 16 kHz.
    let frames = track.sample_count();
    assert!((44..=50).contains(&frames), "{frames} frames");
}

#[test]
fn past_five_minutes_the_recording_is_cut() {
    let rate = 8_000;
    let voice = encode(&vec![0.0; rate as usize * 301], rate).unwrap();
    assert_eq!(voice.duration_ms, crate::outgoing::MAX_VOICE_MS);
}

#[test]
fn nothing_recorded_is_no_voice_note() {
    assert!(encode(&[], 48_000).is_err());
}

/// iOS's scale: −50 dBFS and below is no bar, full scale a full one.
#[test]
fn levels_follow_the_ios_scale() {
    assert_eq!(level(&[0.0; 100]), 0.0);
    assert_eq!(level(&[0.003; 100]), 0.0, "−50 dBFS");
    assert_eq!(level(&[1.0, -1.0, 1.0, -1.0]), 1.0, "0 dBFS");
    let half = level(&[0.1, -0.1]); // −20 dBFS
    assert!((half - 0.6).abs() < 0.01, "{half}");
}

/// A bar per 50 ms up to five seconds, then 100 bars over the whole length, in order.
#[test]
fn the_waveform_has_a_bar_per_moment_up_to_100() {
    let rate = 8_000;
    assert_eq!(waveform(&tone(2.0, rate, 0.5), rate).len(), 40);
    assert_eq!(waveform(&tone(10.0, rate, 0.5), rate).len(), 100);
    let mut quiet_then_loud = vec![0.0; rate as usize * 30];
    quiet_then_loud.extend(tone(30.0, rate, 0.5));
    let bars = waveform(&quiet_then_loud, rate);
    assert_eq!(bars.len(), 100);
    assert!(bars[..50].iter().all(|&b| b == 0), "the silent half");
    // A sine at half scale is −9 dBFS: (−9 + 50) / 50 of 255.
    assert!(
        bars[50..].iter().all(|&b| (205..=212).contains(&b)),
        "{:?}",
        &bars[50..]
    );
}
