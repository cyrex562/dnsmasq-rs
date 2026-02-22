use std::net::Ipv4Addr;

/// A single ARP table entry.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip:          Ipv4Addr,
    pub mac:         [u8; 6],
    pub iface_index: u32,
}

/// Simple in-memory ARP cache.
pub struct ArpCache {
    entries: Vec<ArpEntry>,
}

impl ArpCache {
    pub fn new() -> Self {
        ArpCache { entries: Vec::new() }
    }

    /// Insert or update an ARP entry.
    pub fn update(&mut self, entry: ArpEntry) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.ip == entry.ip) {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Look up a MAC address by IP.
    pub fn find_mac(&self, ip: Ipv4Addr) -> Option<&[u8; 6]> {
        self.entries.iter().find(|e| e.ip == ip).map(|e| &e.mac)
    }

    /// Remove an entry by IP.
    pub fn remove(&mut self, ip: Ipv4Addr) {
        self.entries.retain(|e| e.ip != ip);
    }

    /// Return number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(ip: [u8; 4], mac: [u8; 6]) -> ArpEntry {
        ArpEntry {
            ip: Ipv4Addr::from(ip),
            mac,
            iface_index: 1,
        }
    }

    #[test]
    fn test_update_find_roundtrip() {
        let mut cache = ArpCache::new();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        cache.update(make_entry([192, 168, 1, 1], mac));
        assert_eq!(cache.find_mac(Ipv4Addr::new(192, 168, 1, 1)), Some(&mac));
    }

    #[test]
    fn test_update_overwrites_existing() {
        let mut cache = ArpCache::new();
        let ip = [10, 0, 0, 1];
        cache.update(make_entry(ip, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        let new_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        cache.update(make_entry(ip, new_mac));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.find_mac(Ipv4Addr::new(10, 0, 0, 1)), Some(&new_mac));
    }

    #[test]
    fn test_remove() {
        let mut cache = ArpCache::new();
        cache.update(make_entry([1, 2, 3, 4], [0; 6]));
        assert_eq!(cache.len(), 1);
        cache.remove(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_find_mac_missing() {
        let cache = ArpCache::new();
        assert_eq!(cache.find_mac(Ipv4Addr::new(1, 1, 1, 1)), None);
    }
}
