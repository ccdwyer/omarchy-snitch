use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub struct GeoDb {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    centroids: HashMap<String, (f64, f64)>,
    mmdb_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GeoHit {
    pub country: String,
    pub lat: f64,
    pub lon: f64,
}

impl GeoDb {
    pub fn load(data_dir: &Path, mmdb_override: Option<&Path>) -> Self {
        let centroids = load_centroids(data_dir);
        let candidates: Vec<PathBuf> = mmdb_override
            .map(|p| vec![p.to_path_buf()])
            .unwrap_or_else(|| {
                vec![
                    data_dir.join("geoip/dbip-country-lite.mmdb"),
                    data_dir.join("dbip-country-lite.mmdb"),
                    PathBuf::from("data/geoip/dbip-country-lite.mmdb"),
                ]
            });
        let mut reader = None;
        let mut mmdb_path = None;
        for p in candidates {
            if p.is_file() {
                match maxminddb::Reader::open_readfile(&p) {
                    Ok(r) => {
                        mmdb_path = Some(p);
                        reader = Some(r);
                        break;
                    }
                    Err(e) => eprintln!("snitchd: mmdb open failed for {}: {e}", p.display()),
                }
            }
        }
        Self {
            reader,
            centroids,
            mmdb_path,
        }
    }

    pub fn has_mmdb(&self) -> bool {
        self.reader.is_some()
    }

    pub fn mmdb_path(&self) -> Option<&Path> {
        self.mmdb_path.as_deref()
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<GeoHit> {
        if ip.is_loopback() || ip.is_unspecified() || is_private(ip) {
            return None;
        }
        let reader = self.reader.as_ref()?;
        let country: maxminddb::geoip2::Country = match reader.lookup(ip) {
            Ok(Some(c)) => c,
            Ok(None) => return None,
            Err(_) => return None,
        };
        let iso = country
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .or_else(|| {
                country
                    .registered_country
                    .as_ref()
                    .and_then(|c| c.iso_code)
            })?;
        let cc = iso.to_uppercase();
        let (lat, lon) = self.centroids.get(&cc).copied().unwrap_or((0.0, 0.0));
        Some(GeoHit {
            country: cc,
            lat,
            lon,
        })
    }

    pub fn centroid(&self, cc: &str) -> Option<(f64, f64)> {
        self.centroids.get(&cc.to_uppercase()).copied()
    }
}

fn load_centroids(data_dir: &Path) -> HashMap<String, (f64, f64)> {
    let mut map = HashMap::new();
    let bundled = include_str!("../../data/country-centroids.json");
    ingest_centroids(&mut map, bundled);
    let on_disk = data_dir.join("country-centroids.json");
    if let Ok(text) = std::fs::read_to_string(on_disk) {
        ingest_centroids(&mut map, &text);
    }
    map
}

fn ingest_centroids(map: &mut HashMap<String, (f64, f64)>, text: &str) {
    let parsed: HashMap<String, Vec<f64>> = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return,
    };
    for (k, v) in parsed {
        if v.len() >= 2 {
            map.insert(k.to_uppercase(), (v[0], v[1]));
        }
    }
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local() || v.is_multicast() || v.is_broadcast(),
        IpAddr::V6(v) => {
            v.is_multicast()
                || v.is_unique_local()
                || v.is_unicast_link_local()
                || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn private_skipped() {
        let geo = GeoDb {
            reader: None,
            centroids: HashMap::new(),
            mmdb_path: None,
        };
        assert!(geo.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
        assert!(geo.lookup(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_none());
    }

    #[test]
    fn centroids_embedded() {
        let geo = GeoDb::load(Path::new("/nonexistent"), None);
        assert!(geo.centroid("US").is_some());
        assert!(geo.centroid("SE").is_some());
        let (lat, lon) = geo.centroid("JP").unwrap();
        assert!(lat > 30.0 && lat < 45.0);
        assert!(lon > 120.0 && lon < 150.0);
    }

    #[test]
    fn mmdb_google_dns() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../data");
        let geo = GeoDb::load(&root, None);
        if !geo.has_mmdb() {
            return;
        }
        let hit = geo
            .lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
            .expect("8.8.8.8 should resolve in DB-IP Country Lite");
        assert_eq!(hit.country.len(), 2);
        assert!(hit.lat != 0.0 || hit.lon != 0.0);
    }
}
