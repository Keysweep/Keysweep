pub struct IpSpoofer {
    ips: Vec<String>,
}

impl Default for IpSpoofer {
    fn default() -> Self {
        IpSpoofer::new()
    }
}

impl IpSpoofer {
    pub fn new() -> IpSpoofer {
        IpSpoofer { ips: Vec::new() }
    }
    pub fn generate_ip(&mut self, count: u32) {
        while self.ips.len() < count as usize {
            let (a, b, c, d) = (
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
            );

            if Self::is_reserved(a, b) {
                continue;
            }

            self.ips.push(format!("{a}.{b}.{c}.{d}"));
        }
    }

    fn is_reserved(a: u8, b: u8) -> bool {
        a == 0                                   // 0.0.0.0/8
            || a == 10                            // 10.0.0.0/8
            || a == 25                            // Amateur Radio
            || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 (CGNAT)
            || a == 127                           // Loopback
            || (a == 169 && b == 254)             // Link-local
            || (a == 172 && (16..=31).contains(&b)) // 172.16.0.0/12
            || (a == 192 && b == 168)             // 192.168.0.0/16
            || (a == 198 && (b == 18 || b == 19)) // Benchmark testing
            || a >= 224 // Multicast + Reserved
    }

    pub fn select_ip(&self) -> String {
        self.ips[rand::random_range(0..self.ips.len())].clone()
    }
}
