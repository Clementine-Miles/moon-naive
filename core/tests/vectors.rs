use moon_naive_core::{
    auth::{Binding, Context, Credentials},
    codec::{Decoder, Mode, Offer},
};

#[test]
fn independent_python_authentication_vectors() {
    let credentials = Credentials::new(&[("user", "a-long-test-secret-123")]).unwrap();
    for line in include_str!("vectors/auth.tsv")
        .lines()
        .filter(|s| !s.starts_with('#'))
    {
        let f: Vec<_> = line.split('\t').collect();
        let binding = Binding {
            exporter: [7; 32],
            stream_id: f[0].parse().unwrap(),
        };
        let optional = |s| if s == "-" { None } else { Some(s) };
        let context = Context {
            binding: &binding,
            method: f[3],
            authority: f[4],
            scheme: optional(f[5]),
            path: optional(f[6]),
            protocol: optional(f[7]),
        };
        let offer = Offer::from_bits(f[1].parse().unwrap()).unwrap();
        let mode = Mode::from_bits(f[2].parse().unwrap()).unwrap();
        assert_eq!(
            credentials.authorization_with(0, &context, offer).unwrap(),
            f[8]
        );
        assert_eq!(
            credentials.authenticate(&[f[8]], &context),
            Some((0, offer))
        );
        assert_eq!(
            credentials
                .confirmation_with(0, &context, offer, mode)
                .unwrap(),
            f[9]
        );
        assert_eq!(
            credentials.verify_selection(0, &context, offer, f[9]),
            Some(mode)
        );
        for bad in [
            format!("{} ", f[8]),
            f[8].replace("moon-naive", "Basic"),
            f[8].replace('.', ".."),
            f[8].replace("=", ""),
            f[8].replacen(&format!("{:02x}.", offer.bits()), "80.", 1),
            f[9].into(),
        ] {
            assert!(credentials.authenticate(&[&bad], &context).is_none());
        }
        assert!(credentials.authenticate(&[], &context).is_none());
        assert!(credentials.authenticate(&[f[8], f[8]], &context).is_none());
        let changed = Binding {
            stream_id: binding.stream_id + 4,
            ..binding
        };
        assert!(
            credentials
                .authenticate(
                    &[f[8]],
                    &Context {
                        binding: &changed,
                        ..context
                    }
                )
                .is_none()
        );
        let changed = Binding {
            exporter: [8; 32],
            ..binding
        };
        assert!(
            credentials
                .authenticate(
                    &[f[8]],
                    &Context {
                        binding: &changed,
                        ..context
                    }
                )
                .is_none()
        );
        assert!(
            credentials
                .verify_selection(0, &context, offer, f[8])
                .is_none()
        );
    }
}
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn independent_framing_vectors_every_fragmentation_and_eof() {
    for line in include_str!("vectors/framing.tsv")
        .lines()
        .filter(|s| !s.starts_with('#'))
    {
        let f: Vec<_> = line.split('\t').collect();
        let mode = Mode::from_bits(f[1].parse().unwrap()).unwrap();
        let wire = hex(f[2]);
        let expected = hex(f[3]);
        for chunk in 1..=wire.len().max(1) {
            let mut decoder = Decoder::new(mode);
            let mut out = Vec::new();
            let mut valid = true;
            for part in wire.chunks(chunk) {
                if decoder.feed_into(part, &mut out).is_err() {
                    valid = false;
                    break;
                }
            }
            valid &= decoder.finish().is_ok();
            assert_eq!(valid, f[4] == "1", "{} chunk={chunk}", f[0]);
            if valid {
                assert_eq!(out, expected, "{} chunk={chunk}", f[0]);
            }
        }
    }
}
