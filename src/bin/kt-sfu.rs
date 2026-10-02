//! `kt-sfu`: KeepTalking SFU (presence + topic fan-out) with an embedded iroh
//! relay.

use std::{net::SocketAddr, num::NonZeroU32, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use clap::Parser;
use iroh::{RelayUrl, SecretKey};
use keeptalking_sfu::{
    info,
    server::{Limits, RelayRateLimit, Sfu, SfuConfig, StatsSnapshot},
    tls::{DevCert, reloading_cert},
};
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "kt-sfu",
    about = "KeepTalking SFU (topic rooms + fan-out) + embedded iroh relay"
)]
struct Args {
    /// Plain-HTTP listener for captive-portal probes.
    #[arg(long, env = "KT_SFU_RELAY_HTTP_BIND", default_value = "[::]:80")]
    relay_http_bind: SocketAddr,

    /// HTTPS listener serving the relay.
    #[arg(long, env = "KT_SFU_RELAY_HTTPS_BIND", default_value = "[::]:443")]
    relay_https_bind: SocketAddr,

    /// UDP listener for QUIC address discovery (helps hole punching).
    #[arg(long, env = "KT_SFU_RELAY_QUIC_BIND", default_value = "[::]:7842")]
    relay_quic_bind: SocketAddr,

    /// Disable QUIC address discovery.
    #[arg(long)]
    no_qad: bool,

    /// PEM certificate chain (reloaded periodically).
    #[arg(long, env = "KT_SFU_TLS_CERT", required_unless_present = "dev")]
    tls_cert: Option<PathBuf>,

    /// PEM private key (reloaded periodically).
    #[arg(long, env = "KT_SFU_TLS_KEY", required_unless_present = "dev")]
    tls_key: Option<PathBuf>,

    /// Local development: generate a self-signed certificate and write it
    /// to --dev-cert-out for probes to trust.
    #[arg(long, conflicts_with_all = ["tls_cert", "tls_key"])]
    dev: bool,

    /// Where --dev writes the generated certificate.
    #[arg(long, default_value = "kt-sfu-dev-cert.pem")]
    dev_cert_out: PathBuf,

    /// Extra hostnames/IPs the --dev certificate is valid for.
    #[arg(long = "dev-host")]
    dev_hosts: Vec<String>,

    /// Relay URL clients use, e.g. https://signal.rcex.live. Defaults to
    /// https://<https bind addr> (development only).
    #[arg(long, env = "KT_SFU_PUBLIC_RELAY_URL")]
    public_relay_url: Option<RelayUrl>,

    /// QAD port clients use, if it differs from the bound one (e.g. behind a
    /// load balancer).
    #[arg(long, env = "KT_SFU_PUBLIC_QUIC_PORT")]
    public_quic_port: Option<u16>,

    /// UDP socket(s) for the SFU endpoint. Repeatable.
    #[arg(
        long = "sfu-bind",
        env = "KT_SFU_BIND",
        value_delimiter = ',',
        default_value = "[::]:9702"
    )]
    sfu_bind: Vec<SocketAddr>,

    /// File holding the SFU endpoint's 32-byte secret key; created if missing. The
    /// SFU id must stay stable because clients pin it.
    #[arg(long, env = "KT_SFU_KEY", default_value = "kt-sfu.key")]
    sfu_key: PathBuf,

    /// Plain-HTTP listener for `GET /kt/sfu` (SFU id, relay, ALPN, QAD port).
    /// Put it behind the TLS proxy at the relay's domain.
    #[arg(long, env = "KT_SFU_INFO_BIND")]
    info_bind: Option<SocketAddr>,

    /// Bytes per second the relay reads from each client connection; 0
    /// disables the limit. The SFU endpoint's own relay connection, which
    /// carries its fan-out to relay-only clients, is limited too.
    #[arg(long, env = "KT_SFU_RELAY_CLIENT_RATE", default_value_t = 2 * 1024 * 1024)]
    relay_client_rate: u32,

    /// Burst allowance, in bytes, for --relay-client-rate.
    #[arg(long, env = "KT_SFU_RELAY_CLIENT_BURST", default_value_t = 4 * 1024 * 1024)]
    relay_client_burst: u32,

    /// Concurrent SFU connections; handshakes beyond it are refused.
    #[arg(long, env = "KT_SFU_MAX_CONNECTIONS", default_value_t = 10_000)]
    max_connections: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,iroh=warn,iroh_relay=warn".into()),
        )
        .init();
    let args = Args::parse();

    let sfu_secret = load_or_create_key(&args.sfu_key).await?;
    let (cert, sfu_ca) = if args.dev {
        let dev = DevCert::generate(&args.dev_hosts)?;
        tokio::fs::write(&args.dev_cert_out, &dev.cert_pem)
            .await
            .with_context(|| format!("writing {}", args.dev_cert_out.display()))?;
        info!(path = %args.dev_cert_out.display(), "wrote self-signed dev certificate");
        (dev.cert_config()?, Some(dev.ca()))
    } else {
        let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) else {
            bail!("--tls-cert and --tls-key are required without --dev");
        };
        (reloading_cert(cert, key).await?, None)
    };

    let mut sfu = Sfu::spawn(SfuConfig {
        relay_http_bind: args.relay_http_bind,
        relay_https_bind: args.relay_https_bind,
        relay_quic_bind: (!args.no_qad).then_some(args.relay_quic_bind),
        cert,
        public_relay_url: args.public_relay_url,
        public_quic_port: args.public_quic_port,
        relay_rate_limit: NonZeroU32::new(args.relay_client_rate).map(|rate| RelayRateLimit {
            bytes_per_second: rate,
            burst_bytes: NonZeroU32::new(args.relay_client_burst).unwrap_or(rate),
        }),
        sfu_bind: args.sfu_bind,
        sfu_secret,
        sfu_ca,
        limits: Limits {
            max_connections: args.max_connections,
            ..Limits::default()
        },
    })
    .await?;

    println!("sfu id     {}", sfu.sfu_id());
    println!("relay url  {}", sfu.relay_url());
    println!("sfu udp    {:?}", sfu.sfu_sockets());
    if let Some(addr) = sfu.relay_quic_addr() {
        println!("qad udp    {addr}");
    }
    let mut extra = String::new();
    if let Some(port) = args
        .public_quic_port
        .or(sfu.relay_quic_addr().map(|a| a.port()))
    {
        extra.push_str(&format!(" --qad-port {port}"));
    }
    if args.dev {
        extra.push_str(&format!(" --relay-ca {}", args.dev_cert_out.display()));
    }
    println!(
        "probe      kt-probe room --sfu {} --relay {}{extra} --context <uuid>",
        sfu.sfu_id(),
        sfu.relay_url()
    );

    if let Some(bind) = args.info_bind {
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .with_context(|| format!("info listener {bind}"))?;
        let body = info::sfu_info_json(
            &sfu.sfu_id().to_string(),
            sfu.relay_url().as_str(),
            args.public_quic_port
                .or(sfu.relay_quic_addr().map(|addr| addr.port())),
        );
        println!("info       http://{bind}{}", info::INFO_PATH);
        println!(
            "probe      kt-probe room --info http://{bind}{}{} --context <uuid>",
            info::INFO_PATH,
            if args.dev {
                format!(" --relay-ca {}", args.dev_cert_out.display())
            } else {
                String::new()
            }
        );
        tokio::spawn(info::serve(listener, body));
    }

    let stats = sfu.stats_handle();
    tokio::spawn(async move {
        let mut last = StatsSnapshot::default();
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let now = stats.snapshot();
            if now != last {
                info!(
                    connections = now.connections,
                    refused = now.connections_refused,
                    no_stream = now.no_stream,
                    slow_consumers = now.slow_consumers,
                    stalled = now.stalled,
                    published.control = now.published.control,
                    published.interactive = now.published.interactive,
                    published.bulk = now.published.bulk,
                    delivered.control = now.delivered.control,
                    delivered.interactive = now.delivered.interactive,
                    delivered.bulk = now.delivered.bulk,
                    directed = now.directed,
                    bulk_dropped = now.bulk_dropped,
                    bulk_stalled = now.bulk_stalled,
                    bad_lanes = now.bad_lanes,
                    bulk_stopped = now.bulk_stopped,
                    rate_limited = now.rate_limited,
                    malformed = now.malformed,
                    datagrams_in = now.datagrams_in,
                    datagrams_out = now.datagrams_out,
                    datagrams_dropped = now.datagrams_dropped,
                    "sfu totals"
                );
                last = now;
            }
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
        _ = sfu.relay_stopped() => bail!("relay server stopped unexpectedly"),
    }
    sfu.shutdown().await
}

async fn load_or_create_key(path: &PathBuf) -> Result<SecretKey> {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let bytes: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .with_context(|| format!("{} must hold exactly 32 bytes", path.display()))?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            write_private(path, &key.to_bytes()).await?;
            info!(path = %path.display(), "generated sfu key");
            Ok(key)
        }
        Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
    }
}

async fn write_private(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    use tokio::io::AsyncWriteExt;
    let mut file = options
        .open(path)
        .await
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes).await?;
    Ok(())
}
