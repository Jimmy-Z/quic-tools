use std::{
	fmt::Display,
	net::SocketAddr,
	sync::{Arc, Mutex},
	time::Duration,
};

use clap::{Parser, Subcommand};
use tokio::{
	io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
	net::{TcpListener, TcpStream},
};

/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CERT_PEM: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/cert.pem"));
pub static KEY_PEM: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/key.pem"));
pub static CERT_DER: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/cert.der"));
pub static KEY_DER: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/key.der"));

#[derive(Parser)]
#[command(version)]
struct Args {
	#[command(subcommand)]
	cmd: Cmds,

	#[arg(long)]
	bbr: bool,
}

#[derive(Subcommand)]
enum Cmds {
	#[command(alias = "s")]
	TCPServer {
		#[arg(default_value = "0.0.0.0:2501")]
		bind: SocketAddr,
	},
	#[command(alias = "ss")]
	S2NServer {
		#[arg(default_value = "0.0.0.0:2501")]
		bind: SocketAddr,

		#[arg(short, long, default_value_t = 1048576)]
		max_snd_buf: u32,
	},
	#[command(alias = "qs")]
	QUINNServer {
		#[arg(default_value = "0.0.0.0:2501")]
		bind: SocketAddr,
	},
	#[command(alias = "c")]
	TCPClient {
		#[arg(default_value = "127.0.0.1:2501")]
		remote: SocketAddr,
	},
	#[command(alias = "sc")]
	S2NClient {
		#[arg(default_value = "127.0.0.1:2501")]
		remote: SocketAddr,

		#[arg(default_value = "localhost")]
		remote_name: String,

		#[arg(short, long, default_value = "0.0.0.0:0")]
		bind: SocketAddr,

		#[arg(short, long, default_value_t = 1048576)]
		max_snd_buf: u32,
	},
	#[command(alias = "qc")]
	QUINNClient {
		#[arg(default_value = "127.0.0.1:2501")]
		remote: SocketAddr,

		#[arg(default_value = "localhost")]
		remote_name: String,

		#[arg(short, long, default_value = "0.0.0.0:0")]
		bind: SocketAddr,
	},
}

#[tokio::main]
async fn main() {
	let args = Args::parse();
	match &args.cmd {
		Cmds::TCPServer { bind } => {
			tcp_server(*bind).await;
		}
		Cmds::S2NServer { bind, max_snd_buf } => {
			s2n_server(*bind, args.bbr, *max_snd_buf).await;
		}
		Cmds::QUINNServer { bind } => {
			quinn_server(*bind, args.bbr).await;
		}
		Cmds::TCPClient { remote } => {
			tcp_client(*remote).await;
		}
		Cmds::S2NClient {
			remote,
			remote_name,
			bind,
			max_snd_buf
		} => {
			s2n_client(*remote, remote_name, *bind, args.bbr, *max_snd_buf).await;
		}
		Cmds::QUINNClient {
			remote,
			remote_name,
			bind,
		} => {
			quinn_client(*remote, remote_name, *bind, args.bbr).await;
		}
	}
}

async fn tcp_server(bind: SocketAddr) {
	let server = TcpListener::bind(bind).await.unwrap();
	eprintln!("listening on {}", server.local_addr().unwrap());

	while let Ok((conn, addr)) = server.accept().await {
		eprintln!("connection accepted from {:?}", addr);
		tokio::spawn(write(conn));
	}
}

async fn tcp_client(remote: SocketAddr) {
	let conn = TcpStream::connect(remote).await.unwrap();
	eprintln!("connected");

	read(conn).await;
}

async fn quinn_server(bind: SocketAddr, bbr: bool) {
	let cert = rustls::Certificate(CERT_DER.to_vec());
	let key = rustls::PrivateKey(KEY_DER.to_vec());
	let mut config = quinn::ServerConfig::with_single_cert(vec![cert], key).unwrap();

	if bbr {
		let mut t_conf = quinn::TransportConfig::default();
		t_conf.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
		config.transport_config(Arc::new(t_conf));
	}

	let ep = quinn::Endpoint::server(config, bind).unwrap();
	eprintln!("listening on {}", ep.local_addr().unwrap());

	while let Some(cning) = ep.accept().await {
		let conn = cning.await.unwrap();
		let c_id = conn.stable_id();
		eprintln!(
			"connection {} accepted from {:?}",
			c_id,
			conn.remote_address()
		);

		tokio::spawn(async move {
			while let Ok((s, _)) = conn.accept_bi().await {
				eprintln!("stream {} opened from connection {}", s.id(), c_id);
				write(s).await;
			}
		});
	}
}

async fn quinn_client(remote: SocketAddr, remote_name: &str, bind: SocketAddr, bbr: bool) {
	let mut root = rustls::RootCertStore::empty();
	root.add(&rustls::Certificate(CERT_DER.to_vec())).unwrap();
	let crypto = rustls::ClientConfig::builder()
		.with_safe_defaults()
		.with_root_certificates(root)
		.with_no_client_auth();

	let mut config = quinn::ClientConfig::new(Arc::new(crypto));

	if bbr {
		let mut t_conf = quinn::TransportConfig::default();
		t_conf.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
		config.transport_config(Arc::new(t_conf));
	}

	let ep = quinn::Endpoint::client(bind).unwrap();

	let conn = ep
		.connect_with(config, remote, remote_name)
		.unwrap()
		.await
		.unwrap();
	eprintln!("connected, id: {}", conn.stable_id());

	let (_, s) = conn.open_bi().await.unwrap();
	eprintln!("stream opened, id: {}", s.id());
	read(s).await;
}

async fn s2n_server(bind: SocketAddr, bbr: bool, max_snd_buf: u32) {
	let builder = s2n_quic::Server::builder()
		.with_tls((CERT_PEM, KEY_PEM))
		.unwrap()
		.with_io(bind)
		.unwrap()
		.with_limits(s2n_limits(max_snd_buf))
		.unwrap();
	// what's the best practice here?
	let mut server = if bbr {
		builder
			.with_congestion_controller(s2n_quic::provider::congestion_controller::Bbr::default())
			.unwrap()
			.start()
			.unwrap()
	} else {
		builder.start().unwrap()
	};
	eprintln!("listening on {}", server.local_addr().unwrap());

	while let Some(mut conn) = server.accept().await {
		tokio::spawn(async move {
			let c_id = conn.id();
			eprintln!(
				"connection {} accepted from {:?}",
				c_id,
				conn.remote_addr().unwrap()
			);

			while let Ok(Some(s)) = conn.accept_bidirectional_stream().await {
				tokio::spawn(async move {
					eprintln!("stream {} opened from connection {}", s.id(), c_id);
					write(s).await;
				});
			}
		});
	}
}

async fn s2n_client(remote: SocketAddr, remote_name: &str, bind: SocketAddr, bbr: bool, max_snd_buf: u32) {
	let builder = s2n_quic::Client::builder()
		.with_tls(CERT_PEM)
		.unwrap()
		.with_io(bind)
		.unwrap()
		.with_limits(s2n_limits(max_snd_buf))
		.unwrap();
	let client = if bbr {
		builder
			.with_congestion_controller(s2n_quic::provider::congestion_controller::Bbr::default())
			.unwrap()
			.start()
			.unwrap()
	} else {
		builder.start().unwrap()
	};

	let connect = s2n_quic::client::Connect::new(remote).with_server_name(remote_name);
	let mut conn = client.connect(connect).await.unwrap();
	eprintln!("connected, id: {}", conn.id());

	let s = conn.open_bidirectional_stream().await.unwrap();
	eprintln!("stream opened, id: {}", s.id());
	read(s).await;
}

fn s2n_limits(max_snd_buf: u32) ->s2n_quic::provider::limits::Limits {
	s2n_quic::provider::limits::Limits::default()
		// .with_max_idle_timeout(Duration::from_secs(7)).unwrap()
		.with_data_window(15_000_000).unwrap() // for 300Mbps over 200ms RTT
		.with_bidirectional_local_data_window(15_000_000).unwrap()
		.with_bidirectional_remote_data_window(15_000_000).unwrap()
		.with_unidirectional_data_window(15_000_000).unwrap()
		// .with_max_open_local_bidirectional_streams(1024).unwrap()
		// .with_max_open_local_unidirectional_streams(1024).unwrap()
		// .with_max_open_remote_bidirectional_streams(1024).unwrap()
		// .with_max_open_remote_unidirectional_streams(1024).unwrap()
		.with_max_send_buffer_size(max_snd_buf).unwrap() // default is 512K
}

const BUF_SIZE: usize = 65536;
const TOTAL: isize = 7;

async fn write<W: AsyncWrite + Unpin>(mut w: W) {
	let buf = [0u8; BUF_SIZE];
	let written = Arc::new(Mutex::new(0usize));
	let done = Arc::new(Mutex::new(false));

	let w_c = written.clone();
	let d_c = done.clone();
	tokio::spawn(async move {
		let mut ctr = 0;
		let mut prev_w = 0;
		let mut intv = tokio::time::interval(Duration::from_secs(1));
		// the 1st one ticks immediately so we consume it here
		intv.tick().await;
		loop {
			intv.tick().await;
			let w = *w_c.lock().unwrap();
			eprintln!("{}bytes written", Pretty((w - prev_w) as f64));
			prev_w = w;
			ctr += 1;
			if ctr >= TOTAL {
				*d_c.lock().unwrap() = true;
				break;
			}
		}
	});

	loop {
		match w.write(&buf).await {
			Ok(s) => {
				*written.lock().unwrap() += s;
			}
			Err(e) => {
				eprintln!("error writing: {:?}", e);
				break;
			}
		}
		if *done.lock().unwrap() {
			break;
		}
	}
	eprintln!(
		"total {}bytes written",
		Pretty(*written.lock().unwrap() as f64)
	);
}

async fn read<R: AsyncRead + Unpin>(mut r: R) {
	let mut buf = [0u8; BUF_SIZE];
	let read = Arc::new(Mutex::new(0usize));
	let done = Arc::new(Mutex::new(false));

	let r_c = read.clone();
	let d_c = done.clone();
	tokio::spawn(async move {
		let mut prev_r = 0;
		let mut intv = tokio::time::interval(Duration::from_secs(1));
		intv.tick().await;
		loop {
			intv.tick().await;
			let r = *r_c.lock().unwrap();
			eprintln!("{}bytes read", Pretty((r - prev_r) as f64));
			prev_r = r;
			if *d_c.lock().unwrap() {
				break;
			}
		}
	});

	loop {
		match r.read(&mut buf).await {
			Ok(s) => {
				if s == 0 {
					break;
				}
				*read.lock().unwrap() += s;
			}
			Err(e) => {
				eprintln!("error reading: {:?}", e);
				break;
			}
		}
	}
	*done.lock().unwrap() = true;
	eprintln!("total {}bytes read", Pretty(*read.lock().unwrap() as f64));
}

const SI_PREFIXES: [&str; 5] = ["", "K", "M", "G", "T"];
struct Pretty<T>(T);

impl Display for Pretty<f64> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let mut v = self.0;
		let mut e = 0;
		while v >= 1000.0 {
			v /= 1000.0;
			e += 1;
		}
		// always 3 significants
		if v >= 100.0 {
			write!(f, "{:.0} {}", v, SI_PREFIXES[e])
		} else if v >= 10.0 {
			write!(f, "{:.1} {}", v, SI_PREFIXES[e])
		} else {
			write!(f, "{:.2} {}", v, SI_PREFIXES[e])
		}
	}
}
